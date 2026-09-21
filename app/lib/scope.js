// scope: where a search runs. The Splunk index (the Sentinel workspace is
// the analogue) is configuration, not a fact the analyst is holding: it
// never shows in the Holding rail and is never bound from the facts stores
// (app/lib/held.js refuses it). A pivot resolves it at compile time, per
// sourcetype, in this order:
//
//   override    the Settings value (settingsBar.js, the options page): set,
//               it is the index of every search
//   remembered  the index chosen for this sourcetype in the settings bar's
//               chooser, or learned from the event that was clicked
//   derived     discovery inventoried the sourcetype in exactly one index
//               (catalogue.sourcetype(st).indexes)
//   ambiguous   several indexes carry it and nothing chose: the settings
//               bar asks, once, and remembers the answer
//   unknown     nothing known: the search keeps its own default (the FDR
//               pack's cs_index macro, a pack pivot's $index$)
//
//   scope.index() / setIndex(v)          the Settings value ("" removes)
//   scope.resolve({ indexes, override, remembered })   → { index, state, choices }   (pure)
//   scope.indexFor(st)                   → the same, from the stores
//   scope.bind(params, st)               params with index filled in when unbound
//   scope.notes(st)                      drawer notes: the ambiguous prompt
//   scope.remember(st, index) / forget(st) / remembered(st) / choices()
//   scope.learn(st, index)               a clicked event's index, kept for its sourcetype
//   scope.pending() / clearPending()     the sourcetypes waiting on a choice
//   scope.use({ indexesFor })            who answers "which indexes carry st" (app.js: the catalogue)
//   scope.hydrate()                      resolves once the shared index is in
//   scope.subscribe(fn) / follow(el, fn) fn() on any change
//
// The Settings value has two homes. Here it is localStorage (reach.scope);
// inside the extension it is also chrome.storage.local csIndex (storage-keys.js), which the
// options page and the Splunk-page popups read and this page's
// localStorage cannot reach. The two are mirrored: hydrate() takes the
// shared value at boot and follows later changes, setIndex() writes
// through.

import { isSentinel } from "./platform.js";
import * as store from "./store.js";
import { KEYS } from "./storage-keys.js";
import { hasChrome } from "./runtime.js";

const KEY = "reach.scope";
const SHARED_INDEX_KEY = KEYS.csIndex; // chrome.storage.local, shared with the module list and the popups

// Keys the held stores never take: scope, whichever platform's word.
export const SCOPE_KEYS = Object.freeze(["index", "workspace"]);
export function isScopeKey(name) {
  return SCOPE_KEYS.includes(String(name ?? "").trim().toLowerCase());
}

const listeners = new Set();

function clean(v) {
  return String(v ?? "").trim();
}

function read() {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") return { index: clean(parsed.index), bySourcetype: { ...(parsed.bySourcetype || {}) } };
    }
    return { index: "", bySourcetype: {} };
  } catch {
    return { index: "", bySourcetype: {} };
  }
}

function write(state) {
  try {
    if (state.index || Object.keys(state.bySourcetype).length) localStorage.setItem(KEY, JSON.stringify(state));
    else localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: scope still holds for the rest of this render */
  }
}

let state = read();
let waiting = new Map(); // sourcetype → choices, while a chooser is due

function notify() {
  for (const fn of listeners) fn();
}

// A question raised while a view is compiling (indexFor, from bind) is
// announced after that render, not inside it: the views follow this store
// and would otherwise re-enter their own fill.
let queued = false;
function notifyLater() {
  if (queued) return;
  queued = true;
  queueMicrotask(() => {
    queued = false;
    notify();
  });
}

// ---------------------------------------------------------------------------
// The Settings value

export function index() {
  return state.index;
}

// The shared copy, written whenever the value changes. The onChanged echo
// of our own write carries the value already in the state and is ignored.
function shareIndex(v) {
  if (!hasChrome()) return;
  store.setLiteral({ [SHARED_INDEX_KEY]: v }).catch(() => {});
}

export function setIndex(value) {
  const v = clean(value);
  if (v === state.index) return;
  state = { ...state, index: v };
  write(state);
  shareIndex(v);
  if (v && waiting.size) waiting = new Map(); // an override answers every open question
  notify();
}

// Takes the index from chrome.storage.local, where the options page and the
// popups keep it, and follows it from then on. The shared value wins at
// boot when both are set: it is the one every surface can see. A value
// with no shared copy yet is copied up, so a user coming from an earlier
// build keeps their index.
let hydrated = null;
export function hydrate() {
  if (hydrated) return hydrated;
  if (!hasChrome()) return (hydrated = Promise.resolve());
  hydrated = (async () => {
    const got = await store.getLiteral(SHARED_INDEX_KEY).catch(() => ({}));
    const shared = clean(got[SHARED_INDEX_KEY]);
    if (shared && shared !== state.index) {
      state = { ...state, index: shared };
      write(state);
      notify();
    } else if (!shared && state.index) {
      shareIndex(state.index);
    }
    store.subscribeLiteral((key, value) => {
      if (key !== SHARED_INDEX_KEY) return;
      const next = clean(value);
      if (next === state.index) return;
      state = { ...state, index: next };
      write(state);
      notify();
    });
  })();
  return hydrated;
}

// ---------------------------------------------------------------------------
// Per sourcetype

export function remembered(sourcetype) {
  return state.bySourcetype[clean(sourcetype)] || "";
}

export function choices() {
  return { ...state.bySourcetype };
}

export function remember(sourcetype, value) {
  const st = clean(sourcetype);
  const v = clean(value);
  if (!st) return;
  if ((state.bySourcetype[st] || "") === v) {
    if (waiting.delete(st)) notify();
    return;
  }
  const bySourcetype = { ...state.bySourcetype };
  if (v) bySourcetype[st] = v;
  else delete bySourcetype[st];
  state = { ...state, bySourcetype };
  write(state);
  waiting.delete(st);
  notify();
}

export function forget(sourcetype) {
  remember(sourcetype, "");
}

// The index the clicked event sits in is evidence of where its sourcetype
// lives, not a fact to hold: kept for the sourcetype. A wildcard is the
// search string's scope (index=*), not an index.
export function learn(sourcetype, value) {
  const v = clean(value);
  if (!v || /[*]/.test(v) || !clean(sourcetype)) return;
  remember(sourcetype, v);
}

// ---------------------------------------------------------------------------
// Resolution

function known(list) {
  const out = [];
  for (const i of list || []) {
    const v = clean(i);
    if (v && v !== "*" && !out.includes(v)) out.push(v);
  }
  return out;
}

// Pure. `indexes` is what discovery recorded for the sourcetype.
export function resolve({ indexes = [], override = "", remembered: chosen = "" } = {}) {
  const list = known(indexes);
  const o = clean(override);
  if (o) return { index: o, state: "override", choices: list };
  const c = clean(chosen);
  if (c) return { index: c, state: "remembered", choices: list };
  if (list.length === 1) return { index: list[0], state: "derived", choices: list };
  if (list.length > 1) return { index: "", state: "ambiguous", choices: list };
  return { index: "", state: "unknown", choices: [] };
}

// Who knows which indexes carry a sourcetype: app.js hands in the
// catalogue's discovered layer. Nothing registered means nothing known.
let provider = { indexesFor: () => [] };
export function use(p) {
  provider = { ...provider, ...(p || {}) };
}

function indexesFor(sourcetype) {
  try {
    return provider.indexesFor(sourcetype) || [];
  } catch {
    return [];
  }
}

const NONE = Object.freeze({ index: "", state: "unknown", choices: [] });

// From the stores. An ambiguous answer is remembered as waiting, so the
// settings bar can ask; asking again for the same sourcetype is silent.
export function indexFor(sourcetype) {
  if (isSentinel()) return NONE;
  const st = clean(sourcetype);
  const res = resolve({ indexes: st ? indexesFor(st) : [], override: state.index, remembered: st ? remembered(st) : "" });
  if (res.state === "ambiguous") {
    const cur = waiting.get(st);
    if (!cur || cur.join("\n") !== res.choices.join("\n")) {
      waiting.set(st, res.choices);
      notifyLater();
    }
  }
  return res;
}

function isBound(v) {
  return v !== undefined && v !== null && clean(v) !== "";
}

// A pivot's params with the index filled in, unless the caller bound one
// (typed in the drawer, carried on a URL): what every view calls before
// generating.
export function bind(params, sourcetype) {
  const p = params || {};
  if (isBound(p.index)) return p;
  const res = indexFor(sourcetype);
  return res.index ? { ...p, index: res.index } : p;
}

// The prompt, as a drawer note beside the SPL, while the chooser is due.
export function notes(sourcetype) {
  if (isSentinel()) return [];
  const st = clean(sourcetype);
  const res = resolve({ indexes: st ? indexesFor(st) : [], override: state.index, remembered: st ? remembered(st) : "" });
  if (res.state !== "ambiguous") return [];
  return [{ level: "note", text: `${st} is in ${res.choices.length} indexes (${res.choices.join(", ")}): choose one under Settings, or type it here.` }];
}

export function pending() {
  return Array.from(waiting, ([sourcetype, list]) => ({ sourcetype, choices: list.slice() }));
}

export function clearPending() {
  if (!waiting.size) return;
  waiting = new Map();
  notify();
}

// ---------------------------------------------------------------------------

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// subscribe() for a view: let go once the element has left the page
// (views have no unmount hook).
export function follow(el, fn) {
  const off = subscribe(() => {
    if (!el.isConnected) {
      off();
      return;
    }
    fn();
  });
  return off;
}

export default { SCOPE_KEYS, isScopeKey, index, setIndex, hydrate, remembered, choices, remember, forget, learn, resolve, use, indexFor, bind, notes, pending, clearPending, subscribe, follow };
