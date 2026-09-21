// App shell: loads the bundle, mounts the omnibox and drawer once, installs
// the keyboard map, renders one view per route. Views fill the drawer via ctx.drawer.
// A view's render(ctx) returns an element, or { el, unmount }: afterMount
// runs once it is on the page, unmount before the next view replaces it.

import * as fields from "./lib/pack-fields.js";
import * as catalogue from "./lib/catalogue.js";
import { renderLoadError } from "./lib/data-ui.js";
import * as router from "./lib/router.js";
import * as keys from "./lib/keys.js";
import * as search from "./lib/search.js";
import * as facts from "./lib/facts.js";
import * as scope from "./lib/scope.js";
import * as selection from "./lib/selection.js";
import * as notebook from "./lib/notebook.js";
import * as searches from "./lib/searches.js";
import * as onboarding from "./lib/onboarding.js";
import * as sweep from "./lib/discovery-sweep.js";
import * as navstack from "./lib/navstack.js";
import * as modules from "./lib/modules.js";
import { TERMS, PLATFORM, isSentinel, rememberPlatform } from "./lib/platform.js";
import { onSurface, isStacked } from "./lib/surface.js";
import { copy } from "./lib/copy.js";
import { foldMove } from "./lib/paste-fold.js";

import { h, replace } from "./components/h.js";
import { omnibox } from "./components/omnibox.js";
import { drawer } from "./components/drawer.js";
import { keycap } from "./components/keycap.js";
import { settingsBar } from "./components/settingsBar.js";
import { holding } from "./components/holding.js";
import { midEllipsis } from "./components/titleBlock.js";
import { trail } from "./components/trail.js";

import * as startView from "./views/start.js";
import * as fieldView from "./views/field.js";
import * as eventView from "./views/event.js";
import * as workflowView from "./views/workflow.js";
import * as valueView from "./views/value.js";
import * as searchView from "./views/search.js";
import * as unknownView from "./views/unknown.js";
import * as sourcetypeView from "./views/sourcetype.js";
import * as catalogueView from "./views/catalogue.js";
import * as shareView from "./views/share.js";
import * as discoverView from "./views/discover.js";
import * as packsView from "./views/packs.js";
import * as coverageView from "./views/coverage.js";
import * as notebookView from "./views/notebook.js";
import * as runbookView from "./views/runbook.js";

const VIEWS = {
  start: startView,
  field: fieldView,
  event: eventView,
  workflow: workflowView,
  value: valueView,
  search: searchView,
  unknown: unknownView,
  sourcetype: sourcetypeView,
  catalogue: catalogueView,
  share: shareView,
  discover: discoverView,
  packs: packsView,
  coverage: coverageView,
  notebook: notebookView,
  runbook: runbookView,
};

// Start cards, keys 1–4.
export const CARDS = Object.freeze([
  { key: "1", id: "host", title: "A host", line: "A hostname or an aid, and you want to know what ran on it.", copy: "card.host", href: "#/w/host" },
  { key: "2", id: "pid", title: "An OS PID", line: "A PID from a ticket, a dump, ps or Task Manager.", copy: "card.pid", href: "#/w/pid" },
  { key: "3", id: "detection", title: "A detection", line: "A detection summary event: a different sourcetype, renamed handles.", copy: "card.detection", href: "#/w/detection" },
  { key: "4", id: "ioc", title: "An IOC", line: "A hash, an IP, a domain, a filename.", copy: "card.ioc", href: "#/w/ioc" },
]);

// The bar's nav links, in order; each is drawn only while its route is mounted.
const NAV = Object.freeze([
  { route: "catalogue", label: "Catalogue" },
  { route: "packs", label: "Packs" },
  { route: "discover", label: "Discover" },
  { route: "coverage", label: "Coverage" },
  { route: "notebook", label: "Notebook" },
  { route: "share", label: "Share" },
]);

const bar = document.getElementById("bar");
const main = document.getElementById("main");
const side = document.getElementById("side");

let omni = null;
let paste = null;
let pasteFold = null; // the drawer's fold above the ledger on stacked surfaces (buildChrome)
let foldArmed = false; // a click or key on the page since its render: the next drawer fill opens the fold
let currentView = null;
// A route can mount more than one drawer-owning component (a pack's pivot
// list beside the FDR ledger): every one that registers gets the typed
// param, and each guards its own fill behind its own selection.
let drawerParamHandlers = [];
let drawerCopyHandler = null;
let omniActive = -1;
let omniResults = [];
let keymapEl = null;
let settingsEl = null; // the bar's Settings fold (settingsBar.js)
let menuEl = null; // the frame's overlay on stacked surfaces: omnibox, nav, Settings, Keys
let menuBtn = null;
let frameTitle = null; // the compact title in the frame's first row
let trailEl = null;
let hold = null;

// The overlay behind the frame's menu button. Open it before anything in
// it takes focus, since it is display: none while closed.
function setMenu(open) {
  if (!menuEl) return;
  menuEl.hidden = !open;
  if (menuBtn) menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
}

function focusSearch() {
  if (menuEl && isStacked()) setMenu(true);
  if (omni) omni.focus();
}

// Open the Settings fold on a module's head: the link a module-off page,
// the start page's Tools line and an unconfigured enrichment row use.
function openSettings(moduleId) {
  if (!settingsEl) return;
  if (isStacked()) setMenu(true);
  settingsEl.open = true;
  const head = moduleId ? settingsEl.querySelector(`#${CSS.escape(modules.anchor(moduleId))}`) : null;
  if (head) {
    if (head.tagName === "DETAILS") head.open = true;
    head.scrollIntoView({ block: "start" });
  } else settingsEl.scrollIntoView({ block: "start" });
}

// The trail: navstack.js is the one source of truth for the header's
// Back and Forward and the trail row. Every move this router makes itself
// is flagged before it happens (navDirection for goBack and goForward,
// router.replace() marks its own hashchange, setUrl relabels directly), so
// a hashchange that arrives with no flag is a navigation the user made:
// an advance. history.length is never consulted. The state is mirrored to
// sessionStorage so a reload and the platform switch keep it.
//
// The trail records hops, not clicks. A SIEM click carries the row it was
// in (selection.js hopKey); a click from the row the current entry came
// from lands by router.replace(), so the chip and the history entry take
// the new value in place, and any other click advances with its hop
// (navHop, consumed by the hashchange it causes). A page the panel reaches
// itself (a link, a workflow, a chip) carries no hop, so the click after it
// is a new hop; the drawer's run link says so outright (navFresh), since
// the results it opens come back as clicks.
const TRAIL_KEY = "reach.trail";
let navBack = null;
let navForward = null;
let navDirection = null; // "back" | "forward" | null
let navHop = null; // the hop key the next advance carries
let navFresh = false; // the next click is a new hop whatever its row
let navState = navstack.restore(readTrail(), window.location.hash);
// A document that resumed its trail is a reload (or the platform switch):
// the route on screen is the user's, and the worker's replay of the last
// selection on hello must not move it. Only a fresh panel takes the replay.
const trailResumed = navstack.resumes(readTrail(), window.location.hash);

function readTrail() {
  try {
    return sessionStorage.getItem(TRAIL_KEY);
  } catch {
    return null;
  }
}

function saveTrail(extra) {
  try {
    sessionStorage.setItem(TRAIL_KEY, navstack.serialize(navState, extra));
  } catch {
    /* storage unavailable: the trail lasts the document */
  }
}

function goBack() {
  if (navBack && navBack.disabled) return;
  navDirection = "back";
  window.history.back();
}

function goForward() {
  if (navForward && navForward.disabled) return;
  navDirection = "forward";
  window.history.forward();
}

function updateNavState(meta) {
  const hash = window.location.hash;
  if (navDirection === "back") navState = navstack.moveBack(navState);
  else if (navDirection === "forward") navState = navstack.moveForward(navState);
  else if (meta && meta.replaced) navState = navstack.relabel(navState, hash);
  else navState = navstack.moveTo(navState, stampedPos(), hash) || navstack.advance(navState, hash, navHop);
  navDirection = null;
  navHop = null;
  navFresh = false;
  drawTrail();
}

function freshHop() {
  navFresh = true;
}

// The drawer's Copy and its run link write the search history (scenario
// 12): the text as handed on, the page's container, field and value, and
// the drawer's title as the name. The route says which surface wrote it.
const ROUTE_ORIGIN = { runbook: "runbook", workflow: "workflow", discover: "discovery" };
function noteSearch(text, source) {
  if (!text) return;
  const p = router.parse(window.location.hash).params || {};
  const title = paste && paste.querySelector ? paste.querySelector(".r-drawer__title") : null;
  searches
    .record({
      text,
      platform: PLATFORM,
      source,
      origin: ROUTE_ORIGIN[currentRoute] || "pivot",
      container: p.st || null,
      field: currentRoute === "value" || currentRoute === "field" ? p.name || null : null,
      value: p.value || null,
      name: title ? title.textContent : null,
    })
    .catch(() => {});
}

// Each history entry carries its trail position, so the browser's own
// back and forward (the wide tab's buttons, the keyboard) arrive as a
// traversal to a known entry rather than a new hop.
function stampedPos() {
  const s = window.history && window.history.state;
  return s && Number.isInteger(s.trailPos) ? s.trailPos : null;
}

function stampEntry() {
  if (!window.history || !window.history.replaceState) return;
  if (stampedPos() === navState.pos) return;
  try {
    window.history.replaceState({ trailPos: navState.pos }, "", window.location.hash);
  } catch {
    /* a document that refuses replaceState keeps the flags alone */
  }
}

function drawTrail() {
  if (navBack) navBack.disabled = !navstack.canGoBack(navState);
  if (navForward) navForward.disabled = !navstack.canGoForward(navState);
  if (trailEl) trailEl.update(navState);
  stampEntry();
  saveTrail();
}

// What a page reads as on the trail and in the frame's compact title: a
// hop that carried a value is named by the value, anything else by its name.
// entity: true marks a hop the trail's chip row keeps (trail.js filters on
// it); sourcetype, field, value and event pages earn it outright, a
// runbook only when it was reached from an alert row (its rule param),
// never a tool page (share, notebook, discover, coverage, packs, search,
// start, a runbook opened from the nav).
function chipFor(state) {
  const p = state.params || {};
  switch (state.route) {
    case "field": return { kind: "field", name: p.name, field: p.name, value: p.value || null, st: p.st || null, on: p.on || null, entity: true };
    case "value": return { kind: "value", name: p.value, field: p.name || null, value: p.value, st: p.st || null, on: null, entity: true };
    case "sourcetype": return { kind: "sourcetype", name: p.name, entity: true };
    case "event": return { kind: "event", name: p.name, entity: true };
    case "runbook": return { kind: "runbook", name: p.rule || p.key || "Runbook", entity: Boolean(p.rule) };
    case "workflow": return { kind: "workflow", name: p.id };
    case "search": return { kind: "search", name: p.q ? `Search: ${p.q}` : "Search" };
    case "unknown": return { kind: "page", name: p.name || "Unknown" };
    case "start": return { kind: "page", name: "Reach" };
    case "notebook": {
      const inv = p.id ? notebook.get(String(p.id)) : notebook.current();
      return { kind: "page", name: inv ? (inv.title || "Untitled") : "Notebook" };
    }
    case "notfound": return { kind: "page", name: "No such page" };
    default: return { kind: "page", name: state.route.charAt(0).toUpperCase() + state.route.slice(1) };
  }
}

// A full discovery keeps running across routes (its state lives in
// discovery-sweep.js); this one line in the bar says so anywhere but the
// Discover page, which shows the whole progress line itself.
const sweepLine = h("a", { class: "r-nav__sweep", href: "#/discover", hidden: true });
function showSweepLine(s = sweep.state()) {
  const show = s.running && currentRoute !== "discover";
  sweepLine.hidden = !show;
  if (show) sweepLine.textContent = `Full discovery ${s.done} of ${s.total}`;
}

// ---------------------------------------------------------------------------
// URL helpers

// Write state into the URL without re-rendering (`?sel=`, workflow params).
function setUrl(route, params) {
  const hash = router.build(route, params);
  if (window.history && window.history.replaceState) {
    window.history.replaceState(null, "", hash);
    navState = navstack.relabel(navState, hash);
    drawTrail();
  } else window.location.hash = hash;
  return hash;
}

function navigate(route, params) {
  router.navigate(route, params);
}

function href(route, params) {
  return router.build(route, params);
}

// ---------------------------------------------------------------------------
// The side panel: follow the click.
//
// This same page is Chrome's side panel for the extension (manifest
// side_panel). In a tab it is the catalogue, and nothing here runs; in the
// panel (chrome.tabs.getCurrent() has no tab to name) it connects to the
// background worker and shows whatever the user clicks in the window's
// pages: a content script sends the selection, background.js forwards it
// (and the page shows one line instead of its popup section). Each
// selection becomes the field's page on its sourcetype, with the record
// type the row was; a click on the other platform reloads this page told
// so, since the platform is decided once per document.

function followPanel() {
  const rt = globalThis.chrome && chrome.runtime;
  if (!rt || !rt.connect || !chrome.tabs || !chrome.tabs.getCurrent || !chrome.windows) return;
  chrome.tabs.getCurrent().then((tab) => {
    if (tab) return; // a tab page: the catalogue, not the panel
    return chrome.windows.getCurrent().then((win) => {
      if (!win || !Number.isInteger(win.id)) return;
      document.documentElement.dataset.surface = "panel";
      let retry = 1000;
      const connect = () => {
        let port;
        try {
          port = rt.connect({ name: "reach-panel" });
        } catch {
          return;
        }
        const connectedAt = Date.now();
        port.onMessage.addListener((msg) => {
          if (msg && msg.type === "reach:selection" && msg.selection) showSelection(msg.selection, { replay: msg.replay === true });
        });
        port.onDisconnect.addListener(() => {
          // The worker went to sleep, or was reloaded: come back. A port
          // that held for a while was a healthy one, and its loss is the
          // worker's ordinary idle sleep: reconnect soon, so the next
          // click still has a panel to land in. One that dropped at once
          // is a worker in trouble: back off, 1 s doubling to 30 s.
          if (Date.now() - connectedAt >= 5000) retry = 1000;
          setTimeout(connect, retry);
          retry = Math.min(retry * 2, 30000);
        });
        port.postMessage({ type: "reach:panel:hello", windowId: win.id });
      };
      connect();
    });
  }).catch(() => {});
}

function showSelection(sel, { replay = false } = {}) {
  // The worker replays the window's last click to every panel that says
  // hello. A reloaded panel already carries that click in its route and
  // the page the user went on to: it keeps its route.
  if (replay && trailResumed) return;
  // A click holds nothing (selection.js): the value rides in the field
  // route and in this tab's last event; only Hold, Attach and the Holding
  // add form write the held stores.
  const landed = selection.land(sel);
  if (!landed) return;
  const { platform, params, hop } = landed;
  if (platform !== PLATFORM) {
    rememberPlatform(platform);
    saveTrail({ switch: true, hop }); // the same tab under the other platform: the trail continues
    window.location.replace(`${window.location.pathname}?platform=${platform}${router.build("field", params)}`);
    return;
  }
  // The same row as the current hop: the chip takes the new value in
  // place. Another row, or a click after a page the panel reached itself
  // or after a pivot was run: a new hop.
  if (!navFresh && navstack.sameHop(navState, hop)) {
    router.replace("field", params);
    return;
  }
  // The same page from another row: the browser would not move on the
  // hash, and two entries on one URL would leave Back with no hashchange
  // to land, so the entry takes the row and stays one chip.
  if (router.build("field", params) === window.location.hash) {
    navState = navstack.label(navState, { hop });
    navFresh = false;
    drawTrail();
    return;
  }
  navHop = hop;
  navigate("field", params);
}

// ---------------------------------------------------------------------------
// Theme

function currentTheme() {
  const set = document.documentElement.getAttribute("data-theme");
  if (set) return set;
  // Light is the default on this build (the portal is light unless the user
  // chose otherwise); the OS's dark preference is honoured, as tokens.css does.
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("reach.theme", next);
  } catch {
    /* private mode / storage blocked: the theme still applies for this session */
  }
}

// ---------------------------------------------------------------------------
// Key map overlay, built from keys.KEYMAP

function toggleKeymap(force) {
  const show = force === undefined ? !keymapEl : force;
  if (!show) {
    if (keymapEl) keymapEl.remove();
    keymapEl = null;
    return;
  }
  if (keymapEl) return;
  keymapEl = h(
    "div",
    {
      class: "r-keymap",
      role: "dialog",
      "aria-modal": "false",
      "aria-label": "Keyboard map",
      onClick: (e) => {
        if (e.target === keymapEl) toggleKeymap(false);
      },
    },
    h(
      "div",
      { class: "r-keymap__panel" },
      h("h2", null, "Keys"),
      h(
        "ul",
        { class: "r-keymap__list" },
        keys.KEYMAP.map((k) => h("li", null, keycap({ key: k.key }), h("span", { class: "r-keymap__label" }, k.label))),
      ),
      h(
        "p",
        { class: "r-muted" },
        "Keys never fire while you are typing in a field, except ",
        h("kbd", null, "Esc"),
        ". Everything you see is in the URL, so browser back and forward work.",
      ),
      h("button", { type: "button", class: "r-keymap__close", onClick: () => toggleKeymap(false) }, "Close"),
    ),
  );
  document.body.appendChild(keymapEl);
  const btn = keymapEl.querySelector(".r-keymap__close");
  if (btn) btn.focus();
}

// ---------------------------------------------------------------------------
// Omnibox

function optionsFor(query) {
  const q = String(query || "").trim();
  if (!q) return { results: [], classified: null };
  const idx = catalogue.searchIndex();
  const c = search.classify(q, idx);
  const results = [];
  let classified = null;

  if (c.kind !== "name" && c.kind !== "empty") {
    classified = { kind: c.kind, label: c.candidates.map((x) => x.label).join("  or  ") };
    results.push({
      id: `v:${q}`,
      kind: "value",
      name: q,
      hint: c.ambiguous ? `ambiguous: ${c.candidates.map((x) => x.label).join(" or ")}` : c.candidates[0] && c.candidates[0].label,
    });
  }

  // Sourcetypes from every catalogue layer, before field/event names: a
  // sourcetype is the coarser thing and there are few of them.
  const ql = q.toLowerCase();
  for (const st of catalogue.sourcetypes()) {
    if (!st.name.toLowerCase().includes(ql)) continue;
    results.push({ id: `st:${st.name}`, kind: "sourcetype", name: st.name, hint: `sourcetype · ${st.sources.join(", ")}${st.name.toLowerCase() === ql ? "" : " · substring match"}` });
    if (results.length >= 4) break;
  }

  // Columns from every catalogue layer, on the tables that carry them: the
  // whole name space on Sentinel, where there is no bundle index.
  if (!fields.loaded()) {
    let n = 0;
    for (const st of catalogue.sourcetypes()) {
      for (const f of catalogue.fieldsOn(st.name)) {
        if (!f.toLowerCase().includes(ql)) continue;
        results.push({ id: `c:${st.name}|${f}`, kind: TERMS.field, name: f, hint: `${TERMS.field} on ${st.name}${f.toLowerCase() === ql ? "" : " · substring match"}` });
        if (++n >= 12) break;
      }
      if (n >= 12) break;
    }
    if (!results.length) results.push({ id: `u:${q}`, kind: "not found", name: q, hint: "not a catalogue name" });
    return { results, classified };
  }

  const names = c.kind === "name" ? c.candidates : search.matchNames(q, idx);
  for (const m of names.slice(0, 12)) {
    const hint = m.kind === "field" ? searchView.aboutField(m.name, { fields, catalogue }) : `event · ${searchView.aboutEvent(m.name, { fields })}`;
    results.push({ id: `${m.kind === "field" ? "f" : "e"}:${m.name}`, kind: m.kind, name: m.name, hint: `${hint}${m.match === "exact" ? "" : ` · ${m.match} match`}` });
  }

  if (names.length > 12) results.push({ id: `s:${q}`, kind: "search", name: `see all ${names.length} matches`, hint: "results list" });
  if (!names.some((m) => m.match === "exact")) results.push({ id: `u:${q}`, kind: "not found", name: q, hint: "not an exact catalogue name; see what is near it" });

  return { results, classified };
}

function goToResult(result) {
  if (!result) return;
  const id = String(result.id || "");
  const sep = id.indexOf(":");
  const kind = id.slice(0, sep);
  const name = id.slice(sep + 1);
  if (kind === "f") navigate("field", { name });
  else if (kind === "c") {
    const bar = name.indexOf("|");
    navigate("field", { name: name.slice(bar + 1), st: name.slice(0, bar) });
  } else if (kind === "st") navigate("sourcetype", { name });
  else if (kind === "e") navigate("event", { name });
  else if (kind === "v") navigate("value", { value: name });
  else if (kind === "s") navigate("search", { q: name });
  else navigate("unknown", { name });
}

function omniSubmit() {
  const q = omni.input.value.trim();
  if (!q) return;
  setMenu(false);
  if (omniResults.length && omniResults[omniActive >= 0 ? omniActive : 0]) {
    const r = omniResults[omniActive >= 0 ? omniActive : 0];
    if (r.kind !== "not found") {
      omni.setResults([]);
      omniResults = [];
      goToResult(r);
      return;
    }
  }
  const idx = catalogue.searchIndex();
  const c = search.classify(q, idx);
  if (c.kind === "name" && c.candidates.length && c.candidates[0].match === "exact") {
    goToResult({ id: `${c.candidates[0].kind === "field" ? "f" : "e"}:${c.candidates[0].name}` });
    return;
  }
  if (c.kind !== "name" && c.kind !== "empty") {
    navigate("value", { value: q });
    return;
  }
  navigate("unknown", { name: q });
}

function buildChrome() {
  omni = omnibox({
    placeholder: copy("omnibox.placeholder"),
    onInput: (value) => {
      const { results, classified } = optionsFor(value);
      omniResults = results;
      omniActive = results.length ? 0 : -1;
      omni.setResults(results, omniActive);
      omni.setClassified(classified);
    },
    onSelect: (result) => {
      omni.setResults([]);
      omniResults = [];
      setMenu(false);
      goToResult(result);
    },
    onClear: () => {
      omniResults = [];
      omniActive = -1;
    },
  });
  omni.input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.defaultPrevented) {
      e.preventDefault();
      omniSubmit();
    }
  });

  paste = drawer({
    state: "empty",
    emptyText: copy("drawer.empty"),
    // A typed parameter is the open page's, never a held fact: the page's
    // handler keeps it, and its URL where the page writes one.
    onParam: (name, value) => {
      for (const fn of drawerParamHandlers) fn(name, value);
    },
    onCopy: (text, form) => {
      noteSearch(text, "copy");
      if (drawerCopyHandler) drawerCopyHandler(text, form);
    },
    // A pivot run: its results come back as clicks, and the first is a new hop.
    onRun: () => {
      noteSearch(paste.text(), isSentinel() ? "open" : "run");
      freshHop();
    },
  });

  sweep.subscribe(showSweepLine);
  settingsEl = settingsBar();
  const settings = settingsEl;
  // Back/forward: they fit the panel width (measured with the panel-width
  // harness), so they show at every width, not only where there is no
  // browser chrome to fall back on.
  navBack = h("button", { type: "button", class: "r-btn r-btn--small r-navctl__btn", "aria-label": "Back", title: "Back ([)", onClick: goBack }, "‹");
  navForward = h("button", { type: "button", class: "r-btn r-btn--small r-navctl__btn", "aria-label": "Forward", title: "Forward (])", onClick: goForward }, "›");
  const navctl = h("div", { class: "r-navctl" }, navBack, navForward);
  // The nav row lists the tool routes the registry mounts right now; a
  // module switched off in Settings loses its link at once.
  const nav = h("nav", { class: "r-nav" });
  const drawNav = () => {
    const mounted = new Set(modules.routes(PLATFORM));
    replace(nav, NAV.filter((n) => mounted.has(n.route)).map((n) => h("a", { href: href(n.route, {}) }, n.label)), sweepLine);
  };
  modules.subscribe(drawNav);
  drawNav();
  const keysHint = h(
    "div",
    { class: "r-keys" },
    keycap({ key: "/", hint: "search" }),
    keycap({ key: "↑↓", hint: "rows" }),
    keycap({ key: "Enter", hint: "select" }),
    keycap({ key: "c", hint: "copy" }),
    keycap({ key: "?", hint: "keys" }),
  );

  // The frame on stacked surfaces: row 1 is back, forward, the compact
  // title, the platform badge, search (from 360 px) and the menu; the
  // menu's overlay holds the omnibox, the nav links, Settings and Keys;
  // row 2 is the trail; row 3 is the Holding line while something is
  // held or pinned. The wide tab keeps its bar and gains the trail row.
  frameTitle = h("span", { class: "r-frame__title" });
  const badge = h("span", { class: "r-frame__badge", title: TERMS.platform }, TERMS.lang);
  const searchBtn = h("button", { type: "button", class: "r-btn r-btn--small r-frame__search", "aria-label": "Search", title: "Search (/)", onClick: () => focusSearch() }, "⌕");
  menuBtn = h("button", { type: "button", class: "r-btn r-btn--small r-frame__menubtn", "aria-label": "Menu", "aria-expanded": "false", onClick: () => setMenu(menuEl.hidden) }, "☰");
  const row1 = h("div", { class: "r-frame__row" }, navctl, frameTitle, badge, searchBtn, menuBtn);
  const keysBtn = h("button", { type: "button", class: "r-btn r-frame__keys", onClick: () => { setMenu(false); toggleKeymap(true); } }, "Keys");
  menuEl = h("div", { class: "r-frame__menu", hidden: true });
  menuEl.addEventListener("click", (e) => {
    if (e.target.closest && e.target.closest("a[href]")) setMenu(false);
  });
  trailEl = trail();
  trailEl.update(navState);
  hold = holding();
  facts.subscribe(layout);
  notebook.subscribe(layout);

  // The paste's fold: on stacked surfaces the drawer sits inside main
  // under the title block, folded behind one line (its title once a row
  // is selected) that opens, and scrolls into view, when a row fills it.
  // Parameter edits refill the same title and do not move the page.
  const pasteTitle = h("span", { class: "r-paste__title" }, copy("paste.summary.empty"));
  pasteFold = h(
    "details",
    { class: "r-paste", hidden: true },
    h("summary", { class: "r-paste__summary" }, h("span", { class: "r-paste__label" }, "Query"), pasteTitle),
  );
  const setTitle = paste.setTitle;
  let lastTitle = "";
  // Whether the analyst acted on the page since it rendered: the views
  // fill the drawer from render and from a row alike, so the fold learns
  // which from the page, not the caller.
  const armFold = () => {
    foldArmed = true;
  };
  main.addEventListener("click", armFold, true);
  main.addEventListener("keydown", armFold, true);
  paste.setTitle = (t, sub) => {
    setTitle(t, sub);
    pasteTitle.textContent = t || copy("paste.summary.empty");
    const move = foldMove({ title: t, lastTitle, acted: foldArmed, inFold: pasteFold.contains(paste) });
    if (move) pasteFold.open = move.open;
    if (move && move.scroll) {
      const top = pasteFold.getBoundingClientRect().top + window.scrollY - bar.offsetHeight - 8;
      window.scrollTo(0, Math.max(0, top));
    }
    lastTitle = t;
  };
  onSurface((s) => {
    // The chrome is built once for the session, so its copy.js lines are
    // re-asked here when the panel is dragged across a breakpoint; a view
    // re-asks its own on the next render.
    omni.input.placeholder = copy("omnibox.placeholder");
    paste.setEmptyText(copy("drawer.empty"));
    pasteTitle.textContent = lastTitle || copy("paste.summary.empty");
    hold.refreshCopy();
    settings.refreshCopy();
    setMenu(false);
    bar.classList.toggle("r-bar--frame", s !== "wide");
    if (s === "wide") {
      replace(bar, navctl, omni, nav, settings, keysHint, trailEl);
      replace(side, hold, paste);
      pasteFold.hidden = true;
    } else {
      // navctl moved out of row1 into the wide bar the last time this ran
      // wide (or never left, the first time): row1's own children list is
      // stale until it is put back, first, ahead of the title.
      if (row1.firstChild !== navctl) row1.insertBefore(navctl, row1.firstChild);
      replace(menuEl, omni, nav, settings, keysBtn);
      replace(bar, row1, menuEl, trailEl, hold);
      pasteFold.append(paste);
      placeFold();
      pasteFold.hidden = paste.hidden;
    }
  });

  // In the panel a data table stacks into one labelled block per row
  // (components.css, surfaces): each cell carries its column heading, put
  // here as data-label so the stylesheet can print it. Views draw tables
  // whenever they like (discovery after a fetch, coverage a row at a time),
  // so the labels follow the DOM rather than the render.
  const labelTables = () => {
    for (const t of main.querySelectorAll("table")) {
      const heads = Array.from(t.querySelectorAll(":scope > thead th")).map((th) => th.textContent.trim());
      if (!heads.length) continue;
      for (const td of t.querySelectorAll(":scope > tbody > tr > td:not([data-label])")) {
        const i = Array.prototype.indexOf.call(td.parentElement.children, td);
        td.dataset.label = heads[i] || "";
      }
    }
  };
  new MutationObserver(labelTables).observe(main, { childList: true, subtree: true });
}

// The paste's fold goes under the title block on stacked surfaces, before
// the sections; a view without a title block yet gets it first.
function placeFold() {
  if (!pasteFold || !pasteFold.contains(paste)) return;
  const first = main.firstElementChild;
  const title = first && first.querySelector ? first.querySelector(":scope > .r-title") : null;
  if (title) title.after(pasteFold);
  else main.prepend(pasteFold);
}

// ---------------------------------------------------------------------------
// Row focus movement (↑ ↓)

function focusableRows() {
  // A row behind a closed fold (a collapsed ledger band) is not on screen; skip it.
  return Array.from(main.querySelectorAll('[data-row-id][tabindex="0"], .r-rowlink')).filter((r) => !r.closest("details:not([open])"));
}

function moveRows(delta) {
  if (document.activeElement === omni.input && omniResults.length) {
    omniActive = Math.max(0, Math.min(omniResults.length - 1, omniActive + delta));
    omni.setActive(omniActive);
    return;
  }
  const rows = focusableRows();
  if (!rows.length) return;
  const at = rows.indexOf(document.activeElement);
  const next = at < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, at + delta));
  rows[next].focus();
}

// ---------------------------------------------------------------------------
// Routing

function resetDrawer() {
  drawerParamHandlers = [];
  drawerCopyHandler = null;
  paste.setTitle("", "");
  paste.setParams([]);
  paste.setHazards([]);
  paste.setMacros({});
  paste.setSpl({ inline: "", macro: "" });
  paste.setState("empty");
}

function ctxFor(state) {
  return {
    fields,
    catalogue,
    search,
    route: state.route,
    params: state.params,
    drawer: paste,
    cards: CARDS,
    navigate,
    back: () => goBack(),
    href,
    setUrl,
    goBack,
    focusSearch,
    openSettings,
    modules,
    setDrawerParamHandler: (fn) => {
      drawerParamHandlers.push(fn);
    },
    setDrawerCopyHandler: (fn) => {
      drawerCopyHandler = fn;
    },
  };
}

// Routes with nothing to paste. The drawer is hidden on them; the side rail
// stays for the Holding panel while there is something held or pinned, and
// folds away to give the catalogue the width when there is not.
const WIDE_ROUTES = new Set(["catalogue", "sourcetype", "share", "discover", "start", "packs", "coverage", "notebook"]);
let currentRoute = "";

function layout() {
  const wide = WIDE_ROUTES.has(currentRoute);
  const any = hold ? hold.count() > 0 : false;
  document.getElementById("page").classList.toggle("r-page--wide", wide && !any);
  if (paste) paste.hidden = wide;
  if (pasteFold && pasteFold.contains(paste)) pasteFold.hidden = wide;
}

// A view returns an element, or { el, unmount }; the unmount hook lands on
// the element renderRoute holds and is called before the next view replaces it.
function asElement(out) {
  if (!out || out.nodeType || !out.el) return out;
  if (typeof out.unmount === "function") out.el.unmount = out.unmount;
  return out.el;
}

function renderRoute(state) {
  const ctx = ctxFor(state);
  if (currentView && typeof currentView.unmount === "function") currentView.unmount();
  currentView = null;
  foldArmed = false;
  resetDrawer();
  scope.clearPending(); // an index question belongs to the route that asked it
  currentRoute = state.route;
  layout();
  showSweepLine();
  let node;
  try {
    const view = VIEWS[state.route];
    // A route is mounted while its module is on for this platform
    // (modules.js): the workflow and event pages are Splunk knowledge and
    // never mount on Sentinel. The bare value page is FDR's carriers
    // ledger, except when the URL names the column and table: then it is
    // the value's meaning and pattern, which both platforms have.
    const status = modules.routeStatus(state.route, PLATFORM);
    const bareValue = isSentinel() && state.route === "value" && !(state.params.st && state.params.name);
    if (status === "absent" || bareValue) node = notHere(state);
    else if (status === "off") node = moduleOff(state);
    else node = view ? asElement(view.render(ctx)) : notFound(state);
  } catch (err) {
    console.error(err);
    node = unknownPage({
      name: "That page did not render",
      chip: "did not render",
      why: String((err && err.message) || err),
      actions: [backAction(), h("a", { class: "r-btn", href: "#/" }, "Start"), h("a", { class: "r-btn", href: "#/catalogue" }, "Catalogue")],
    });
  }
  currentView = node;
  replace(main, node);
  placeFold();
  const meta = chipFor(state);
  navState = navstack.label(navState, meta);
  drawTrail();
  if (frameTitle) {
    frameTitle.textContent = midEllipsis(meta.name, 24);
    frameTitle.title = meta.field && meta.value ? `${meta.field}=${meta.value}` : meta.name;
    frameTitle.dataset.kind = meta.kind;
  }
  document.title = titleFor(state);
  main.scrollTop = 0;
  window.scrollTo(0, 0);
  if (node && typeof node.afterMount === "function") node.afterMount();
  settleFocus(state);
}

// After a route change, focus the selected ledger row when the URL names one,
// else the main region; never leave it in the omnibox or on the body, where
// the ledger keys are inert.
function settleFocus(state) {
  const active = document.activeElement;
  if (active && active !== main && active !== document.body && !(omni && active === omni.input) && main.contains(active)) return;
  const sel = state.params && state.params.sel;
  const row = sel ? main.querySelector(`[data-row-id="${CSS.escape(String(sel))}"]`) : null;
  if (row) row.focus();
  else main.focus({ preventScroll: true });
}

function titleFor(state) {
  const p = state.params || {};
  switch (state.route) {
    case "field": return `${p.name} - Reach`;
    case "event": return `${p.name} - event - Reach`;
    case "workflow": return `${p.id} - workflow - Reach`;
    case "value": return `${p.value} - value - Reach`;
    case "search": return `${p.q || ""} - search - Reach`;
    case "unknown": return `${p.name} - not in the catalogue - Reach`;
    case "sourcetype": return `${p.name} - sourcetype - Reach`;
    case "catalogue": return "Catalogue - Reach";
    case "share": return "Share - Reach";
    case "discover": return "Discover - Reach";
    case "packs": return "Packs - Reach";
    case "coverage": return "Coverage - Reach";
    case "notebook": return "Notebook - Reach";
    case "runbook": return `${p.rule || p.key} - runbook - Reach`;
    default: return "Reach";
  }
}

// The unknown template (views/unknown.js): a name, a chip saying what kind
// of absence this is, one line of why, the way back and the alternative.
// notHere, moduleOff, notFound and a render failure all draw it.
function backAction() {
  return unknownView.backAction(goBack);
}

function unknownPage({ name, chip, why, actions }) {
  return unknownView.absentPage({ name, chip, why, actions });
}

function notHere(state) {
  const p = state.params || {};
  const alt = p.st ? h("a", { class: "r-btn", href: href("sourcetype", { name: p.st }) }, TERMS.Sourcetype) : h("a", { class: "r-btn", href: "#/catalogue" }, TERMS.Sourcetypes);
  let why;
  if (state.route === "value") why = `a bare value has no ${TERMS.field}: click the value in the grid so the ${TERMS.field} is known`;
  else if (state.route === "workflow") why = `no guided workflow on ${TERMS.platform}: the pivots on a value or ${TERMS.field} page carry the value into ${TERMS.lang}`;
  else if (state.route === "event") why = `event pages are the Falcon pack's field catalogue, Splunk knowledge; the ${TERMS.sourcetype} page lists the record types here`;
  else why = `the ${state.route} page is Splunk knowledge; this build of Reach is for ${TERMS.platform}`;
  const name = state.route === "workflow" ? p.id : state.route === "value" ? p.value : p.name;
  return unknownPage({ name: name || state.route, chip: `not on ${TERMS.platform}`, why, actions: [backAction(), alt] });
}

// A route whose module is switched off: the page is not mounted, and the
// way back is Settings, on that module's head.
function moduleOff(state) {
  const m = modules.routeOwner(state.route);
  const label = m ? m.label : state.route;
  return unknownPage({
    name: `${label} is off`,
    chip: "module off",
    why: `The ${state.route} page belongs to the ${label} module, which is switched off. Turn it on in Settings to mount it again.`,
    actions: [backAction(), h("a", { href: "#/", class: "r-btn r-settings__open", onClick: (e) => { e.preventDefault(); openSettings(m ? m.id : null); } }, "Settings"), h("a", { class: "r-btn", href: "#/catalogue" }, "Catalogue")],
  });
}

function notFound(state) {
  const path = String((state.params && state.params.path) || "that address");
  return unknownPage({
    name: path,
    chip: "no such page",
    why: `No page at ${path}. Press / and type what you are holding.`,
    actions: [backAction(), h("a", { class: "r-btn", href: "#/catalogue" }, "Catalogue"), h("a", { class: "r-btn", href: "#/" }, "Start")],
  });
}

// ---------------------------------------------------------------------------
// Boot

async function main_() {
  try {
    await Promise.all([
      catalogue.load(), // loads the packs, the fields sidecars this platform knows, and the user layer
      modules.hydrate().catch(() => {}), // the enabled module set, so the router and the nav read it synchronously
      scope.hydrate().catch(() => {}), // the index shared with the options page and the popups, so the first SPL built already has it; never a reason not to boot
      onboarding.hydrate().catch(() => {}), // enabled-origin count for the start page's onboarding card, read before its first render
      notebook.load().catch(() => {}), // the investigation notebook, so its readers answer from the first render
    ]);
    // Which indexes carry a sourcetype: what discovery inventoried, read
    // through the catalogue's discovered layer. catalogue.sourcetypes()
    // rebuilds the merged list on every call and a pivot asks on every
    // keystroke, so the answer is kept until the catalogue changes.
    let byName = null;
    facts.installAliases();
    catalogue.subscribe(() => {
      byName = null;
      facts.installAliases();
    });
    scope.use({
      indexesFor: (st) => {
        if (!byName) byName = new Map(catalogue.sourcetypes().map((s) => [s.name, s.indexes || []]));
        return byName.get(st) || [];
      },
    });
  } catch (err) {
    renderLoadError(err);
    document.getElementById("page").hidden = true;
    return;
  }

  buildChrome();

  keys.install({
    handlers: {
      focusSearch,
      escape: () => {
        if (keymapEl) {
          toggleKeymap(false);
          return;
        }
        if (menuEl && !menuEl.hidden && document.activeElement !== omni.input) {
          setMenu(false);
          return;
        }
        if (document.activeElement === omni.input) return false; // the omnibox clears itself
        focusSearch();
      },
      up: () => moveRows(-1),
      down: () => moveRows(1),
      select: () => {
        const el = document.activeElement;
        if (el && el.closest && el.closest("[data-row-id]")) return false; // the ledger row handles it
        if (el && el.tagName === "A") return false;
        return false;
      },
      copy: () => paste.copy(),
      cycleEvent: () => {
        if (currentView && typeof currentView.cycleEvent === "function") currentView.cycleEvent();
        else return false;
      },
      card1: () => (fields.loaded() && modules.on("workflows") ? navigate("workflow", { id: CARDS[0].id }) : false),
      card2: () => (fields.loaded() && modules.on("workflows") ? navigate("workflow", { id: CARDS[1].id }) : false),
      card3: () => (fields.loaded() && modules.on("workflows") ? navigate("workflow", { id: CARDS[2].id }) : false),
      card4: () => (fields.loaded() && modules.on("workflows") ? navigate("workflow", { id: CARDS[3].id }) : false),
      back: () => goBack(),
      forward: () => goForward(),
      help: () => toggleKeymap(),
      theme: () => toggleTheme(),
    },
  });

  router.start((state, meta) => {
    updateNavState(meta);
    renderRoute(state);
  });
  followPanel();
  // A module switched on or off re-renders the page: a route may have
  // mounted or gone, and a band may have appeared or left.
  modules.subscribe(() => {
    const active = document.activeElement;
    if (active && keys.isEditable(active)) return;
    renderRoute(router.current());
  });
  // A note saved from a Splunk popup lands in the same store; re-render the
  // current page so it shows without a reload. Never while the user is typing.
  function rerender() {
    const active = document.activeElement;
    if (active && keys.isEditable(active)) return;
    const state = router.current();
    // Discover writes the store mid-operation and redraws its own results;
    // replacing the whole view here would orphan its status line and the
    // buttons still running. Coverage confirms bindings one after another
    // and redraws its own rows the same way.
    if (state.route === "discover" || state.route === "coverage") return;
    renderRoute(state);
  }
  // A full discovery writes the discovered layer several times per
  // sourcetype; on any other route that would be a re-render per write.
  // While one runs, the re-render waits for a two-second lull instead, so
  // the page settles once the sweep is done (or between sourcetypes).
  let settle = null;
  catalogue.subscribe(() => {
    if (!sweep.state().running) {
      rerender();
      return;
    }
    clearTimeout(settle);
    settle = setTimeout(() => {
      settle = null;
      rerender();
    }, 2000);
  });
}

main_();
