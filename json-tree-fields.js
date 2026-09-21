// Splunk's JSON pretty-printer (.json-tree) renders each leaf as a plain
// <span data-path="..."> with no click wiring, unlike the field=value links
// at the bottom of an event (<a class="f-v" data-field-name="...">). Splunk's
// "Add to search / Exclude from search" menu is bound to .f-v by delegation,
// not per-element, so tagging a leaf with the same class and data-field-name
// makes it fully clickable through Splunk's own menu. Verified against a
// live instance, including correct spath-based SPL for nested JSON fields.
//
// data-field-name is set to the RAW data-path verbatim, dotted segments and
// all. That's what Splunk's own SPL generator needs to build a correct
// spath() for a nested field. Resolving that path to a fields.json bundle
// key (for Reach's own meaning/decode/pivot lookups) is a separate concern,
// done by app/lib/field-resolve.js where a popup is actually rendered; never
// here, or Splunk's native "Add to search" would start generating SPL against
// the wrong (bundle) name instead of the real JSON path.
//
// The key name beside each leaf (<span class="key-name">, the coloured text
// before the colon) gets the same data-field-name, and nothing else: Splunk
// wires no menu to it, so it stays out of .f-v. field-info-popup.js takes
// the click and shows the field's meaning, scoped to this event.
//
// Gated on a Splunk Web asset signature (a <link>/<script> under its
// versioned /static/@<hash>/ path, how Splunk Web serves every one of its
// own static files), not a `window.*` global. MV3 content scripts run in an
// isolated JS world by default: `window.Splunk`, set by Splunk Web's own
// scripts, is never visible here even on a real Splunk page. That gate
// silently never fired. The DOM itself (unlike window-scoped globals) is
// shared across worlds, so a DOM signature is correct: this was never meant
// to be a security boundary (that's the per-origin permission grant), only
// a cheap "is there anything to do here" check.

(function () {
  if (!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]')) return;

  const LEAF_SELECTOR = '.json-tree [data-path]:not([data-reach-tagged])';

  function tagOne(el) {
    if (el.dataset.reachTagged) return;
    el.dataset.reachTagged = "1";
    if (!el.classList.contains("t")) return; // skip [+]/[-] expand toggles (class "jsexpands")
    el.classList.add("f-v");
    el.dataset.fieldName = el.dataset.path;
    el.setAttribute("role", "button");
    el.setAttribute("aria-haspopup", "true");
    el.style.cursor = "pointer";
    const key = el.parentElement && el.parentElement.classList.contains("key") ? el.parentElement.querySelector(":scope > .key-name") : null;
    if (key && !key.dataset.fieldName) {
      key.dataset.fieldName = el.dataset.path;
      key.dataset.reachKey = "1";
      key.setAttribute("role", "button");
      key.setAttribute("aria-haspopup", "dialog");
      key.style.cursor = "pointer";
    }
  }

  // Scoped to one node's own match plus its subtree. Never document.body.
  // A full-document querySelectorAll on every mutation callback is real jank
  // on a continuously-updating search-results page; this only looks at what
  // actually changed.
  function tagWithin(node) {
    if (!node || node.nodeType !== 1) return;
    if (node.matches && node.matches(LEAF_SELECTOR)) tagOne(node);
    if (node.querySelectorAll) {
      for (const el of node.querySelectorAll(LEAF_SELECTOR)) tagOne(el);
    }
  }

  // Mutations on a live results page can arrive in several separate batches
  // within one frame (scroll, re-render); coalesce them into one tagging
  // pass per frame instead of running inline in the observer callback.
  //
  // With a timeout: Splunk's search page is never idle (it polls the job and
  // re-renders continuously), and a bare requestIdleCallback was observed to
  // wait 45 s+, so the leaves Splunk inserts on a [+] expansion sat
  // untagged and unclickable. 200 ms is the ceiling before we run anyway.
  let pending = [];
  let scheduled = false;
  const runWhenIdle = window.requestIdleCallback
    ? (fn) => window.requestIdleCallback(fn, { timeout: 200 })
    : (fn) => window.requestAnimationFrame(fn);

  function flush() {
    scheduled = false;
    const nodes = pending;
    pending = [];
    for (const node of nodes) tagWithin(node);
  }

  function schedule(node) {
    pending.push(node);
    if (scheduled) return;
    scheduled = true;
    runWhenIdle(flush);
  }

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) schedule(node);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
  tagWithin(document.body); // one-time full scan for whatever's already on the page
})();
