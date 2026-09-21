// Appends a Reach section into Splunk's own native value-click popup
// (.dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown.open),
// never a Reach-drawn tooltip of our own. That popup is destroyed and
// recreated on every open and carries no reliable field identity in its own
// markup, so identity is captured at click time (capture phase, before
// Splunk's own handler) off the .f-v element that was actually clicked, and
// correlated with the popup by timing when it appears.
//
// This script captures the click, loads the bundle and mounts the section.
// What the section says is app/lib/click-section.js's, the same walk the
// Sentinel grid and the field popdown take; the click's row is read by
// app/lib/click-context.js (context.js: the event's sourcetype, index and
// record type off the default-field links in the same row, never a bare
// name match); Splunk's own run control, the live search dispatched only
// from an explicit isTrusted click on "Run here →", is app/lib/click-splunk.js.
//
// Local-only: field meaning, decode lookups, and generating a pivot's SPL
// are pure key checks against the bundled data. The enrichment row
// (app/lib/enrich.js) is the same shape one hop further out: a bundled
// source reads only the extension's own packaged data; a fetch source asks
// the background worker, which alone holds the user's own key, only on an
// explicit click on its button.

(function () {
  if (!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]')) return;

  const POPUP_SELECTOR = ".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown.open";
  const CLICK_STALE_MS = 800;

  let bundleReady = null;
  function loadBundle() {
    if (!bundleReady) {
      bundleReady = Promise.all([
        import(chrome.runtime.getURL("app/lib/pack-fields.js")),
        import(chrome.runtime.getURL("app/lib/field-resolve.js")),
        import(chrome.runtime.getURL("app/lib/reachability.js")),
        import(chrome.runtime.getURL("app/lib/spl.js")),
        import(chrome.runtime.getURL("app/lib/fdr-queries.js")),
        import(chrome.runtime.getURL("app/components/h.js")),
        import(chrome.runtime.getURL("live-lookup.js")),
        import(chrome.runtime.getURL("app/lib/context.js")),
        import(chrome.runtime.getURL("app/lib/catalogue.js")),
        import(chrome.runtime.getURL("app/lib/popup-ui.js")),
        import(chrome.runtime.getURL("app/lib/packs.js")),
        import(chrome.runtime.getURL("app/lib/pivot.js")),
        import(chrome.runtime.getURL("app/lib/workflows.js")),
        import(chrome.runtime.getURL("app/lib/enrich.js")),
        import(chrome.runtime.getURL("app/lib/enrich/kev.js")),
        import(chrome.runtime.getURL("app/lib/enrich/virustotal.js")),
        import(chrome.runtime.getURL("app/lib/editor-bridge.js")),
        import(chrome.runtime.getURL("app/lib/notebook.js")),
        import(chrome.runtime.getURL("app/lib/menu-fit.js")),
        import(chrome.runtime.getURL("app/lib/benign.js")),
        import(chrome.runtime.getURL("app/lib/modules.js")),
        import(chrome.runtime.getURL("app/lib/runbooks.js")),
        import(chrome.runtime.getURL("app/lib/storage-keys.js")),
        import(chrome.runtime.getURL("app/lib/runtime.js")),
        import(chrome.runtime.getURL("app/lib/click-context.js")),
        import(chrome.runtime.getURL("app/lib/click-section.js")),
        import(chrome.runtime.getURL("app/lib/click-splunk.js")),
      ]).then(async ([fields, fieldResolve, reachability, spl, fdrQueries, hMod, liveLookup, context, catalogue, ui, packs, pivot, workflows, enrich, kevSource, vtSource, bridge, notebook, fit, benign, modules, runbooks, storageKeys, runtime, clickContext, clickSection, clickSplunk]) => {
        await catalogue.load({ fields: "lazy" }); // the packs and the user layer; a container's field catalogue is fetched on the first click in it
        await modules.hydrate(); // the enabled module set: each band is drawn only while its module is on
        enrich.register(kevSource.source);
        enrich.register(vtSource.source);
        const lib = { fields, resolve: fieldResolve.resolve, ...reachability, spl, fdrQueries, h: hMod.h, live: liveLookup, context, catalogue, ui, packs, pivot, workflows, enrich, bridge, notebook, fit, benign, modules, runbooks, keys: storageKeys.KEYS, runtime, clickContext: clickContext.clickContext, sectionFor: clickSection.sectionFor };
        lib.hooks = clickSplunk.hooks(lib);
        return lib;
      });
    }
    return bundleReady;
  }

  let lastClick = null; // { fieldName, value, el, at }

  // The side panel's pattern builder inserts through this page's search
  // bar: the request arrives as a runtime message and the bridge answers
  // with what it did. Only the extension's own pages can send it.
  if (chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (!msg || sender.id !== chrome.runtime.id) return false;
      if (msg.type === "reach:editor:apply") {
        loadBundle()
          .then((lib) => lib.bridge.onMessage(msg))
          .then(
            (res) => sendResponse(res || { ok: false, how: null, notice: "not handled" }),
            (err) => sendResponse({ ok: false, how: null, notice: err && err.message ? err.message : String(err) }),
          );
        return true;
      }
      // The advisor's Advise button, read from the side panel: what the
      // search bar holds right now, not what it held when the click rode
      // over.
      if (msg.type === "reach:editor:read") {
        loadBundle()
          .then((lib) => lib.bridge.onReadMessage(msg))
          .then(
            (res) => sendResponse(res || { ok: false, reason: "not handled", text: "", cursor: null }),
            (err) => sendResponse({ ok: false, reason: err && err.message ? err.message : String(err), text: "", cursor: null }),
          );
        return true;
      }
      return false;
    });
  }

  // The editor-focused offer: the search bar takes focus, the search names
  // a sourcetype with known-benign values, and one line under the bar
  // offers the exclusion per field (popup-ui.js exclusionStrip). Drawn
  // only; inserting is a click on the line. Its × hides it until the
  // search names another sourcetype.
  const STRIP_ID = "reach-benign-strip";
  let stripHiddenFor = "";
  async function offerExclusions() {
    const bar = document.querySelector(".search-bar-input");
    if (!bar) return;
    const lib = await loadBundle();
    const old = document.getElementById(STRIP_ID);
    if (old) old.remove();
    // The strip is the editor half of the benign module: its inject setting, off by default.
    if (!lib.modules.on("benign", "splunk") || lib.modules.setting("benign", lib.keys.benignInject) !== true) return;
    await lib.benign.load();
    const sourcetype = lib.context.searchStringTerm("sourcetype", document);
    if (!sourcetype || stripHiddenFor === sourcetype) return;
    const fields = Array.from(new Set(lib.benign.list({ container: sourcetype }).map((e) => e.field)));
    if (!fields.length) return;
    const strip = lib.ui.exclusionStrip({ container: sourcetype, fields, platform: "splunk", query: lib.context.searchString(document), onInsert: (req) => lib.bridge.apply(req), onClose: () => (stripHiddenFor = sourcetype) });
    if (!strip) return;
    strip.dataset.theme = lib.ui.hostTheme(bar);
    bar.insertAdjacentElement("afterend", lib.h("div", { id: STRIP_ID }, lib.h("style", null, lib.ui.POPUP_CSS), strip));
  }
  document.addEventListener(
    "focusin",
    (e) => {
      if (e.target && e.target.closest && e.target.closest(".search-bar-input")) offerExclusions().catch(() => {});
    },
    true,
  );

  document.addEventListener(
    "click",
    (e) => {
      const el = e.target.closest && e.target.closest(".f-v");
      if (!el) return;
      // The element is kept, not its row: which container counts as "the
      // event" is context.js's decision, made at render time with the bundle
      // loaded (it needs the pack's discriminator map).
      lastClick = {
        fieldName: el.dataset.fieldName || "",
        value: (el.textContent || el.title || "").trim(),
        el,
        at: Date.now(),
      };
    },
    true, // capture phase; must run before Splunk's own delegated handler
  );

  // Splunk's popup is never moved, resized or restyled. The section mounts
  // under Splunk's own items when its natural height (capped) fits there
  // within the viewport; otherwise it opens as Reach's own panel beside the
  // popup (menu-fit.js besideMenu, popup-ui.js anchoredPanel), closed when
  // the popup goes or on Escape.
  const SECTION_CAP = 0.7;
  const INLINE_CSS = "\n.reach-section--inline{overflow-y:auto;overscroll-behavior:contain}";
  function mountSection(lib, popup, section) {
    section.classList.add("reach-section--inline");
    const style = lib.h("style", null, lib.ui.POPUP_CSS + INLINE_CSS);
    popup.appendChild(style);
    popup.appendChild(section);
    const pr = popup.getBoundingClientRect();
    const sr = section.getBoundingClientRect();
    const fit = lib.fit.fitBelow({ top: pr.top, itemsHeight: sr.top - pr.top, wanted: sr.height, viewportHeight: window.innerHeight, cap: SECTION_CAP });
    if (fit.fits) {
      // The stylesheet's own cap (70vh) is the only height rule it needs.
      lib.fit.ownWheel(section, { isScroller: lib.fit.scrollsOnItsOwn });
      return;
    }
    section.remove();
    style.remove();
    section.classList.remove("reach-section--inline");
    const menu = popup.getBoundingClientRect();
    const place = lib.fit.besideMenu({ menu, viewportWidth: window.innerWidth, viewportHeight: window.innerHeight, height: sr.height, cap: SECTION_CAP });
    const panel = lib.ui.anchoredPanel({ section, place, closeWith: popup, theme: lib.ui.hostTheme(popup) });
    lib.fit.ownWheel(panel, { isScroller: lib.fit.scrollsOnItsOwn });
  }

  // The section for the click: the click's context off the row
  // (click-context.js), the bands in the shared order (click-section.js),
  // with Splunk's own run control and FDR edge as the hooks.
  async function render(popup, click) {
    const lib = await loadBundle();
    const on = (id) => lib.modules.on(id, "splunk");
    const ctx = lib.clickContext("splunk", click.el, { discriminators: lib.catalogue.discriminators(), runbooks: on("runbooks"), readEditor: () => lib.bridge.read() });
    const out = await lib.sectionFor({ platform: "splunk", click: { kind: "value", name: click.fieldName, value: click.value }, ctx, lib, hooks: lib.hooks });
    if (!out) return; // nothing to say: Splunk's popup stays as it is
    if (out.panel) {
      popup.appendChild(lib.h("style", null, lib.ui.POPUP_CSS));
      popup.appendChild(out.el);
      return;
    }
    mountSection(lib, popup, out.el);
  }

  // Splunk's search page mutates continuously (job polling, re-renders), so
  // the freshness test comes first: the document is only searched inside
  // the short window after a click, not on every batch. The search stays
  // document-wide because the popup may be inserted in one batch and
  // opened (.open) in a later one.
  const observer = new MutationObserver(() => {
    if (!lastClick || Date.now() - lastClick.at > CLICK_STALE_MS) return;
    const popup = document.querySelector(POPUP_SELECTOR + ":not([data-reach-rendered])");
    if (!popup) return;
    popup.dataset.reachRendered = "1";
    render(popup, lastClick).catch((err) => console.warn("[Reach]", err)); // a render failure must never break Splunk's own popup
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
