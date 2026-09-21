// The field's meaning, for a click on a field NAME. Two surfaces:
//
// Splunk's own field-info popdown (.popdown-dialog.shared-fieldinfo.open,
// opened by clicking a field name in the sidebar's field list): Reach
// appends its section as a flyout beside the popdown (right, left or
// below, wherever the viewport has room; the popdown itself never moves),
// rather than inline in its .field-info-reports-section slot, so a long Reach writeup
// doesn't push Splunk's own "Top values / Rare values / Events with this
// field" content further down the page. Field-level, not event-level: that
// popup summarizes a field across the whole result set, so there is no
// single "current event" to scope a definition to. The sourcetype comes
// from the page: the click context reads every sourcetype link in the
// results. One sourcetype on the page → the lookup is scoped to it;
// several → the popup says which of them the catalogue places this field
// on, and which it does not; none → matched by name only, and labelled so.
//
// A key name in the JSON event view (<span class="key-name">, tagged with
// data-field-name by json-tree-fields.js): Splunk wires nothing to it, so
// there is no host popup to append into, and Reach draws its own anchored
// panel (popup-ui.js) beside the click. This one IS event-level: the row
// the key sits in names the sourcetype, the index and the record type
// (app/lib/click-context.js, the same read value-popup.js makes), so the
// meaning is the field's on that sourcetype, not a page-wide guess. The
// section itself is app/lib/click-section.js's, the walk every surface takes.
//
// Local-only, same as value-popup.js: a pure key check against the bundled
// data, runs automatically, never touches the network.

(function () {
  if (!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]')) return;

  const POPUP_SELECTOR = ".popdown-dialog.shared-fieldinfo.open";
  const CLICK_STALE_MS = 800;
  const FLYOUT_WIDTH = 440;
  const FLYOUT_GAP = 12;
  const EDGE_MARGIN = 12;

  // Splunk positions the popdown (inline `left`/`top`, fixed width) once,
  // pointed at the field row it was opened from, and Reach never moves
  // it. The flyout (`.reach-section--flyout`) takes the popdown's right
  // when the viewport has room for it there, else its left, else the
  // space below it (menu-fit.js flyoutSide).
  const FLYOUT_CSS = '\n.reach-section--flyout[data-side="left"]{left:auto;right:100%;margin:0 12px 0 0}\n.reach-section--flyout[data-side="below"]{left:0;top:100%;margin:12px 0 0 0}';
  function placeFlyout(lib, popup, section) {
    section.dataset.side = lib.fit.flyoutSide({ menu: popup.getBoundingClientRect(), viewportWidth: document.documentElement.clientWidth, width: FLYOUT_WIDTH, gap: FLYOUT_GAP, margin: EDGE_MARGIN });
  }

  let bundleReady = null;
  function loadBundle() {
    if (!bundleReady) {
      bundleReady = Promise.all([
        import(chrome.runtime.getURL("app/lib/pack-fields.js")),
        import(chrome.runtime.getURL("app/lib/field-resolve.js")),
        import(chrome.runtime.getURL("app/lib/reachability.js")),
        import(chrome.runtime.getURL("app/components/h.js")),
        import(chrome.runtime.getURL("app/lib/context.js")),
        import(chrome.runtime.getURL("app/lib/catalogue.js")),
        import(chrome.runtime.getURL("app/lib/popup-ui.js")),
        import(chrome.runtime.getURL("app/lib/workflows.js")),
        import(chrome.runtime.getURL("app/lib/modules.js")),
        import(chrome.runtime.getURL("app/lib/menu-fit.js")),
        import(chrome.runtime.getURL("app/lib/runtime.js")),
        import(chrome.runtime.getURL("app/lib/runbooks.js")),
        import(chrome.runtime.getURL("app/lib/storage-keys.js")),
        import(chrome.runtime.getURL("app/lib/click-context.js")),
        import(chrome.runtime.getURL("app/lib/click-section.js")),
        import(chrome.runtime.getURL("app/lib/click-splunk.js")),
      ]).then(async ([fields, fieldResolve, reachability, hMod, context, catalogue, ui, workflows, modules, fit, runtime, runbooks, storageKeys, clickContext, clickSection, clickSplunk]) => {
        await catalogue.load({ fields: "lazy" }); // the packs and the user layer; a container's field catalogue is fetched on the first click in it
        await modules.hydrate(); // the enabled module set: each band is drawn only while its module is on
        const lib = { fields, resolve: fieldResolve.resolve, ROUTE_TEXT: reachability.ROUTE_TEXT, h: hMod.h, context, catalogue, ui, workflows, modules, fit, runtime, runbooks, keys: storageKeys.KEYS, clickContext: clickContext.clickContext, sectionFor: clickSection.sectionFor };
        lib.hooks = clickSplunk.hooks(lib);
        return lib;
      });
    }
    return bundleReady;
  }

  let lastClick = null; // { fieldName, at }

  document.addEventListener(
    "click",
    (e) => {
      if (!e.target.closest) return;
      const key = e.target.closest(".json-tree .key-name[data-reach-key]");
      if (key) {
        // Splunk has no handler here; the click is Reach's alone.
        openForKey({ fieldName: key.dataset.fieldName || "", el: key, x: e.clientX, y: e.clientY }).catch((err) => console.warn("[Reach]", err));
        return;
      }
      const el = e.target.closest("a[data-field-name]");
      if (!el || el.classList.contains("f-v")) return; // .f-v value clicks are value-popup.js's job
      lastClick = { fieldName: el.dataset.fieldName || "", at: Date.now() };
    },
    true, // capture phase; must run before Splunk's own delegated handler
  );

  // The section for a field: the same walk the value popup and the
  // Sentinel grid take (click-section.js), a field click drawing no value
  // line, no verdict and no action row. `click.el` set: a key in an
  // event, scoped to that event's row. Unset: the sidebar popdown, scoped
  // by the page (click-context.js reads the page's sourcetypes). Null when
  // there is nothing to say and the surface is the host's.
  async function sectionFor(click) {
    const lib = await loadBundle();
    const ctx = lib.clickContext("splunk", click.el || null, { discriminators: lib.catalogue.discriminators(), runbooks: lib.modules.on("runbooks", "splunk") });
    const out = await lib.sectionFor({ platform: "splunk", click: { kind: "field", name: click.fieldName, value: "" }, ctx, lib, hooks: lib.hooks });
    return out ? { lib, section: out.el, panel: out.panel } : null;
  }

  // Splunk's popdown: the section as a flyout beside it.
  async function render(popup, click) {
    const out = await sectionFor(click);
    if (!out) return;
    const { lib, section } = out;
    if (out.panel) {
      popup.appendChild(lib.h("style", null, lib.ui.POPUP_CSS));
      popup.appendChild(section);
      return;
    }
    section.classList.add("reach-section--flyout");
    popup.appendChild(lib.h("style", null, lib.ui.POPUP_CSS + FLYOUT_CSS));
    placeFlyout(lib, popup, section);
    popup.appendChild(section);
  }

  // A JSON key: Reach's own panel beside the click, in the event's theme.
  async function openForKey(click) {
    const out = await sectionFor(click);
    if (!out || out.panel) return; // the panel shows it; nothing to draw here
    const { lib, section } = out;
    lib.ui.anchoredPanel({ section, x: click.x, y: click.y, theme: lib.ui.hostTheme(click.el) });
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
