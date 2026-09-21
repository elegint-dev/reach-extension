// Content script for the Logs blade frame (sandbox-N.reactblade.portal.azure.net,
// all_frames), the Sentinel counterpart of value-popup.js, field-info-popup.js
// and json-tree-fields.js in one, because the blade renders all three surfaces
// in one grid: a value cell, a column header, and the expanded row's
// key/value tree for a dynamic column.
//
// Right-click a value: the blade opens its own menu (Copy value / Filter for /
// Filter to exclude). Reach appends its section into that menu when it can
// find it (the same "append into the host's own menu, never draw our own"
// posture as on Splunk) and draws a small panel anchored to the cell when
// it cannot. Right-click a column header: the column's meaning on this
// table. Alt+click anywhere in the grid: Reach's panel directly.
//
// This script captures the click, loads the bundle and mounts the section.
// What the section says is app/lib/click-section.js's, the same walk the
// Splunk popups take; the grid is read by app/lib/click-context.js
// (sentinel-context.js: the row's Type column when it is projected, else
// the table named in the query editor, and the lookup is
// catalogue.fieldOn(table, column), never a bare name match); the blade's
// own pivot control (Copy KQL, Open as query tab through a deep link,
// docs/SENTINEL.md §5.6) and table picker are app/lib/click-sentinel.js.
//
// Local-only. Nothing here runs a query, and Reach never touches the
// network on its own. The one exception is the enrichment row
// (app/lib/enrich.js): a bundled source reads only the extension's own
// packaged data; a fetch source asks the background worker, which alone
// holds the user's own key, only on an explicit click on its button.

(function () {
  if (!/\.reactblade\.portal\.azure\.net$/.test(location.hostname)) return;

  const MENU_WAIT_MS = 1500;
  // Same selector as app/lib/sentinel-context.js HEADER_SEL; needed before
  // the bundle that holds it has loaded.
  const HEADER_SEL = '[role="columnheader"], th';

  let bundleReady = null;
  function loadBundle() {
    if (!bundleReady) {
      bundleReady = Promise.all([
        import(chrome.runtime.getURL("app/components/h.js")),
        import(chrome.runtime.getURL("app/lib/catalogue.js")),
        import(chrome.runtime.getURL("app/lib/popup-ui.js")),
        import(chrome.runtime.getURL("app/lib/packs.js")),
        import(chrome.runtime.getURL("app/lib/pivot.js")),
        import(chrome.runtime.getURL("app/lib/kql.js")),
        import(chrome.runtime.getURL("app/lib/sentinel-context.js")),
        import(chrome.runtime.getURL("app/lib/enrich.js")),
        import(chrome.runtime.getURL("app/lib/enrich/kev.js")),
        import(chrome.runtime.getURL("app/lib/enrich/virustotal.js")),
        import(chrome.runtime.getURL("app/lib/editor-bridge.js")),
        import(chrome.runtime.getURL("app/lib/menu-fit.js")),
        import(chrome.runtime.getURL("app/lib/benign.js")),
        import(chrome.runtime.getURL("app/lib/sentinel-settings.js")),
        import(chrome.runtime.getURL("app/lib/modules.js")),
        import(chrome.runtime.getURL("app/lib/runbooks.js")),
        import(chrome.runtime.getURL("app/lib/storage-keys.js")),
        import(chrome.runtime.getURL("app/lib/runtime.js")),
        import(chrome.runtime.getURL("app/lib/workflows.js")),
        import(chrome.runtime.getURL("app/lib/store.js")),
        import(chrome.runtime.getURL("app/lib/click-context.js")),
        import(chrome.runtime.getURL("app/lib/click-section.js")),
        import(chrome.runtime.getURL("app/lib/click-sentinel.js")),
      ]).then(async ([hMod, catalogue, ui, packs, pivot, kql, context, enrich, kevSource, vtSource, bridge, fit, benign, sentinelSettings, modules, runbooks, storageKeys, runtime, workflows, store, clickContext, clickSection, clickSentinel]) => {
        await catalogue.load();
        await modules.hydrate(); // the enabled module set: each band is drawn only while its module is on
        enrich.register(kevSource.source);
        enrich.register(vtSource.source);
        injectEditorBridge();
        bridge.ensureKqlInjected(); // the bridge watches the tag from now on: ready, or refused by the page
        return { h: hMod.h, catalogue, ui, packs, pivot, kql, context, enrich, bridge, fit, benign, sentinelSettings, modules, runbooks, keys: storageKeys.KEYS, runtime, workflows, store, clickContext: clickContext.clickContext, sectionFor: clickSection.sectionFor, hooks: clickSentinel.hooks };
      });
    }
    return bundleReady;
  }

  // The query editor is Monaco, reachable only from the page's own world:
  // sentinel-editor-inject.js is loaded once as a real <script src> and
  // app/lib/editor-bridge.js talks to it over DOM events. Loaded with the
  // bundle so the first click's Insert does not wait on it; the bridge
  // finds the tag by id (bridge.KQL_INJECT_ID) and waits for its ready mark.
  const EDITOR_INJECT_ID = "reach-editor-inject";
  function injectEditorBridge() {
    if (document.getElementById(EDITOR_INJECT_ID) || document.documentElement.dataset.reachEditorBridge === "1") return;
    const s = document.createElement("script");
    s.id = EDITOR_INJECT_ID;
    s.src = chrome.runtime.getURL("sentinel-editor-inject.js");
    (document.head || document.documentElement).appendChild(s);
  }

  // The workspace the Logs blade is on (sentinel-workspace.js keeps it): a
  // config fact the pivots link back to, never held.
  async function currentWorkspace(lib) {
    try {
      const out = await lib.store.getLiteral(lib.keys.sentinelWorkspace);
      return out[lib.keys.sentinelWorkspace] || null;
    } catch {
      return null;
    }
  }

  // --- the section ------------------------------------------------------------
  // The click's context off the grid (click-context.js: the row's Type, else
  // the query's tables, else the picker), then the bands in the shared
  // order (click-section.js), with the blade's own pivot control and table
  // picker as the hooks (click-sentinel.js).
  async function sectionFor(lib, click) {
    const { catalogue, ui } = lib;
    const workspace = await currentWorkspace(lib);
    const known = catalogue.sourcetypes().map((s) => s.name);
    const ctx = lib.clickContext("sentinel", click.target, {
      discriminators: catalogue.discriminators(),
      known,
      scope: workspace && workspace.name ? workspace.name : null,
      forcedTable: click.forcedTable || null,
      infer: (name, among) => catalogue.inferSourcetype(name, among),
      runbooks: click.kind === "value" && lib.modules.on("runbooks", "sentinel"),
    });
    if (!ctx.column) return null;
    const hooks = lib.hooks(lib, { workspace, rerender: (table) => { click.forcedTable = table; rerender(lib, click); } });
    const out = await lib.sectionFor({ platform: "sentinel", click: { kind: ctx.kind, name: ctx.column.path, value: ctx.value }, ctx, lib, hooks });
    if (!out) return null;
    return out.panel ? ui.panelLine() : out.el;
  }

  // --- theme: the portal's, not the OS's ----------------------------------------
  // The Azure portal's theme is a portal setting; prefers-color-scheme does
  // not know it. The blade paints its surfaces with it, so the host element
  // Reach draws into (the menu, or the body under a panel) says which one is
  // on: popup-ui.js's hostTheme reads it off the background.

  // --- surfaces ---------------------------------------------------------------
  // The blade's own menu when it can be found; otherwise Reach's anchored
  // panel (popup-ui.js), the same one Splunk's JSON keys get.

  function showPanel(lib, section, x, y) {
    const panel = lib.ui.anchoredPanel({ section, x, y, theme: lib.ui.hostTheme(document.body) });
    lib.fit.ownWheel(panel, { isScroller: lib.fit.scrollsOnItsOwn }); // the blade cancels the wheel on its way down
  }

  // Reach's own panel beside the blade's menu, which is never moved to
  // make room: at the menu's right edge (its left when the right has no
  // room), closed when the menu goes or on Escape.
  const SECTION_CAP = 0.6;
  function showBeside(lib, section, menu, height) {
    const wrap = menu.closest(".ag-popup-child") || menu;
    const place = lib.fit.besideMenu({ menu: wrap.getBoundingClientRect(), viewportWidth: window.innerWidth, viewportHeight: window.innerHeight, height, cap: SECTION_CAP });
    const panel = lib.ui.anchoredPanel({ section, place, closeWith: wrap, theme: lib.ui.hostTheme(document.body) });
    lib.fit.ownWheel(panel, { isScroller: lib.fit.scrollsOnItsOwn });
  }

  async function rerender(lib, click) {
    const section = await sectionFor(lib, click);
    if (!section) return;
    section.dataset.theme = lib.ui.hostTheme(click.host && document.body.contains(click.host) ? click.host : document.body);
    if (click.host && document.body.contains(click.host)) {
      const old = click.host.querySelector(".reach-section");
      if (old) old.remove();
      mountInMenu(lib, click.host, section);
    } else {
      showPanel(lib, section, click.x, click.y);
    }
  }

  // The blade's menu (ag-Grid's .ag-menu-list) is laid out as a table:
  // options are rows, their icon / label / shortcut parts are cells. An
  // appended block becomes an anonymous cell in the first column, and
  // anything wide there pushes the labels about. A table-caption at the
  // bottom is the one box that spans the whole table without joining
  // its columns; grid-column covers the CSS-grid variant of the menu.
  const MENU_CSS = '\n[role="menu"]>.reach-section{display:table-caption;caption-side:bottom;grid-column:1 / -1;justify-self:stretch;min-width:560px;max-width:none;width:auto;max-height:60vh;overflow:auto;overscroll-behavior:contain;box-sizing:border-box}';

  // ag-Grid positions its menu once, inside the grid's own overlay layer,
  // which clips at the grid's edge, and Reach never moves it. The section
  // is appended and measured; when its natural height (capped) fits
  // between the menu's items and the layer's bottom it stays, otherwise
  // it comes back out and opens beside the menu (menu-fit.js).
  function mountInMenu(lib, menu, section) {
    const style = menu.querySelector(":scope > style[data-reach-menu]") ? null : lib.h("style", { dataset: { reachMenu: "1" } }, lib.ui.POPUP_CSS + MENU_CSS);
    if (style) menu.appendChild(style);
    menu.appendChild(section);
    // A click inside the section must not be a menu-item click.
    section.addEventListener("click", (ev) => ev.stopPropagation());
    section.addEventListener("mousedown", (ev) => ev.stopPropagation());
    const wrap = menu.closest(".ag-popup-child") || menu;
    const layer = menu.closest(".ag-popup") || menu.closest(".ag-root-wrapper");
    const lr = layer ? layer.getBoundingClientRect() : null;
    const wr = wrap.getBoundingClientRect();
    const sh = section.getBoundingClientRect().height;
    const fit = lib.fit.fitBelow({ top: wr.top, itemsHeight: wr.height - sh, wanted: sh, viewportHeight: window.innerHeight, limit: lr ? lr.bottom : window.innerHeight, cap: SECTION_CAP });
    if (fit.fits) {
      lib.fit.ownWheel(section, { isScroller: lib.fit.scrollsOnItsOwn }); // the blade cancels the wheel on its way down
      return;
    }
    section.remove();
    if (style) style.remove();
    showBeside(lib, section, menu, sh);
  }

  // The blade's own menu, if one appears right after the right-click: the
  // element added to the DOM that contains "Copy value", or, when ag-Grid
  // reuses a popup element it already has, the one that becomes visible.
  function visibleMenu() {
    for (const m of document.querySelectorAll('.ag-menu-list, [role="menu"]')) {
      if (!/Copy value/.test(m.textContent || "") || m.querySelector(".reach-section")) continue;
      const r = m.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) return m;
    }
    return null;
  }
  function waitForMenu(ms) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (el) => { if (done) return; done = true; obs.disconnect(); clearInterval(timer); resolve(el); };
      const isMenu = (n) => n && n.nodeType === 1 && /Copy value/.test(n.textContent || "") && n.querySelector('[role="menuitem"], button, li');
      const obs = new MutationObserver((muts) => {
        for (const m of muts) for (const n of m.addedNodes) {
          if (isMenu(n)) return finish(n.querySelector('[role="menu"]') || n);
        }
      });
      obs.observe(document.body, { childList: true, subtree: true });
      const timer = setInterval(() => { const m = visibleMenu(); if (m) finish(m); }, 100);
      setTimeout(() => finish(visibleMenu()), ms);
    });
  }

  async function onContext(e, { direct = false } = {}) {
    const lib = await loadBundle();
    const { context, ui } = lib;
    const info = context.cellAt(e.target);
    if (!info.cell || (!info.grid && info.kind !== "header")) return;
    if (!context.columnOf(info, document)) return;
    const click = { target: e.target, kind: info.kind === "header" ? "field" : "value", x: e.clientX, y: e.clientY, at: Date.now() };

    const menu = direct || info.kind === "header" ? null : await waitForMenu(MENU_WAIT_MS);
    const section = await sectionFor(lib, click);
    if (!section) return;
    // The settings bar's "always open Reach beside the menu" toggle takes
    // the panel regardless of room, for anyone who prefers it outright;
    // otherwise the section mounts in the menu when it fits under the
    // blade's own items and opens beside the menu when it does not.
    const alwaysPanel = await lib.sentinelSettings.read();
    if (menu && document.body.contains(menu) && lib.fit.usePanel({ alwaysPanel })) {
      section.dataset.theme = ui.hostTheme(menu);
      showBeside(lib, section, menu, measure(lib, section));
      return;
    }
    if (menu && document.body.contains(menu)) {
      // The blade's menus are narrow; the section may widen them (a caption
      // widens the table, the option rows stretch, nothing else moves).
      click.host = menu;
      section.dataset.theme = ui.hostTheme(menu);
      mountInMenu(lib, menu, section);
    } else {
      showPanel(lib, section, click.x, click.y);
    }
  }

  // The section's natural height, measured off screen.
  function measure(lib, section) {
    const box = lib.h("div", { style: "position:fixed;left:-10000px;top:0;visibility:hidden" }, lib.h("style", null, lib.ui.POPUP_CSS), section);
    document.body.appendChild(box);
    const height = section.getBoundingClientRect().height;
    box.remove();
    return height;
  }

  function failed(e, err) {
    console.warn("[Reach]", err); // never break the blade's own menu
  }
  // Body cells: ag-Grid opens its own menu and suppresses the browser's.
  // A column header has no native menu, so the browser's would open next
  // to Reach's panel; take the event instead. That has to happen here,
  // during dispatch: onContext awaits the bundle before it knows what was
  // clicked, and a preventDefault after that await is too late.
  document.addEventListener(
    "contextmenu",
    (e) => {
      if (e.target && e.target.closest && e.target.closest(HEADER_SEL)) e.preventDefault();
      onContext(e).catch((err) => failed(e, err));
    },
    true,
  );
  document.addEventListener(
    "click",
    (e) => {
      if (!e.altKey) return;
      onContext(e, { direct: true }).catch((err) => failed(e, err));
    },
    true,
  );

  // The editor-focused offer: the Logs editor takes focus, the query names
  // a table with known-benign values, and one fixed line at the bottom of
  // the blade offers the exclusion per column (popup-ui.js exclusionStrip),
  // inserted through the editor bridge when the Logs editor answers,
  // copied otherwise. Drawn only; its × hides it until the query names
  // another table.
  const STRIP_ID = "reach-benign-strip";
  let stripHiddenFor = "";
  async function offerExclusions(editor) {
    const lib = await loadBundle();
    const old = document.getElementById(STRIP_ID);
    if (old) old.remove();
    // The strip is the editor half of the benign module: its inject setting, off by default.
    if (!lib.modules.on("benign", "sentinel") || lib.modules.setting("benign", lib.keys.benignInject) !== true) return;
    await lib.benign.load();
    const query = lib.context.queryText(document);
    const tables = lib.kql.tablesIn(query).filter((t) => lib.benign.list({ container: t }).length);
    const table = tables[0] || "";
    if (!table || stripHiddenFor === table) return;
    const fields = Array.from(new Set(lib.benign.list({ container: table }).map((e) => e.field)));
    const canInsert = await lib.bridge.kqlReady();
    const strip = lib.ui.exclusionStrip({ container: table, fields, platform: "sentinel", query, onInsert: canInsert ? (req) => lib.bridge.apply(req) : null, onClose: () => (stripHiddenFor = table) });
    if (!strip) return;
    strip.dataset.theme = lib.ui.hostTheme(editor);
    document.body.appendChild(lib.h("div", { id: STRIP_ID, style: "position:fixed;left:12px;bottom:12px;z-index:2147483000;max-width:calc(100vw - 24px);box-shadow:0 1.6px 3.6px rgba(0,0,0,.13),0 0.3px 0.9px rgba(0,0,0,.11);border-radius:4px" }, lib.h("style", null, lib.ui.POPUP_CSS), strip));
  }
  document.addEventListener(
    "focusin",
    (e) => {
      const editor = e.target && e.target.closest && e.target.closest(".monaco-editor");
      if (editor) offerExclusions(editor).catch(() => {});
    },
    true,
  );
})();
