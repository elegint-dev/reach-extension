// held: a key:value store of facts the analyst is holding. Two instances
// of it feed app/lib/facts.js, differing only in where they keep the map:
//
//   app/lib/investigation.js   this tab (sessionStorage): the case
//   app/lib/pinned.js          this browser (localStorage): the environment
//
//   const s = heldStore({ storage: () => sessionStorage, key: "reach.investigation" });
//   s.get("aid")
//   s.set("aid", "abc123")     // "" removes the key
//   s.all()                    // { aid: "abc123", ... }
//   s.remove("aid"), s.clear()
//   s.subscribe(fn)            // fn() on any change; returns unsubscribe
//
// Keys are case-insensitive and stored lowercased, so "AID" and "aid" are
// the same fact. The storage thunk is evaluated inside try/catch on every
// access: private mode / storage-blocked means facts last the render, not
// that the app breaks.
//
// Concept aliases: a workflow input named pid and a clicked RawProcessId
// are one fact, as are two columns bound to the same concept. The app
// installs the map once the packs are loaded (setAliases, built by
// aliasPairs from the pack bindings and the workflow inputs); from then on
// set() and get() resolve a name to its canonical key, all() returns
// canonical keys only, and a document written before the map was installed
// folds on read (first value kept). aliasesOf() is the reverse: facts.js
// expands a bound fact under every name a view may ask for.
//
//   setAliases(pairs)             pairs: [[alias, canonical], …]; replaces the map
//   canonicalKey(name)            the key a name is held under
//   aliasesOf(key)                every other name that means the same fact
//   aliasPairs({ bindings, params }) → pairs
//     bindings: [{ concept, column }]  the columns bound on this platform, by concept key
//     params:   [{ name, column }] a workflow input that is a column by another name
//               [{ name, concept }] a pack input bound from a concept
//     A column bound to two concepts is left alone (no alias through it);
//     the canonical of a concept is its first bound column.
//
// Scope keys (app/lib/scope.js: the index, the workspace) are never held.
// The guard lives here and nowhere else: set() of a scope key writes
// nothing and notifies nobody, and read() drops one already sitting in
// storage from an earlier build, without writing back, so it cannot come
// back through a stale document. Every reader of all() can therefore trust
// the map as it is.
//
// The stored shape is the flat map { key: value }. A held value maps onto
// the notebook's pin entry (app/lib/notebook.js) as field: key, value:
// value; provenance is the notebook's to add.
//
// termsFor(facts, platform, quote) → [{ key, value, text }]: the held facts
// as search terms, key=value in SPL and key == value in KQL, each value
// through the platform's own quote (spl.quote or kql.quote, handed in so
// this module stays free of both). The insert shortcut offers these when
// the query box is focused; it never inserts on its own.

import { isScopeKey } from "./scope.js";

export function normalizeKey(name) {
  return String(name ?? "").trim().toLowerCase();
}

let aliasMap = new Map(); // alias → canonical, both normalised
let reverseMap = new Map(); // canonical → [alias, …]

export function setAliases(pairs) {
  const next = new Map();
  for (const [alias, canonical] of pairs || []) {
    const a = normalizeKey(alias);
    const c = normalizeKey(canonical);
    if (!a || !c || a === c || isScopeKey(a) || isScopeKey(c)) continue;
    next.set(a, c);
  }
  // No chains: an alias whose canonical is itself an alias points at the end of it.
  for (const [a, c] of next) {
    let end = c;
    for (let i = 0; i < 8 && next.has(end) && next.get(end) !== a; i++) end = next.get(end);
    next.set(a, end);
  }
  aliasMap = next;
  reverseMap = new Map();
  for (const [a, c] of aliasMap) {
    if (!reverseMap.has(c)) reverseMap.set(c, []);
    reverseMap.get(c).push(a);
  }
}

export function canonicalKey(name) {
  const k = normalizeKey(name);
  return aliasMap.get(k) || k;
}

export function aliasesOf(key) {
  return [...(reverseMap.get(normalizeKey(key)) || [])];
}

export function aliasPairs({ bindings = [], params = [] } = {}) {
  const conceptsOfColumn = new Map();
  for (const b of bindings) {
    const col = normalizeKey(b && b.column);
    if (!col || !b.concept) continue;
    if (!conceptsOfColumn.has(col)) conceptsOfColumn.set(col, new Set());
    conceptsOfColumn.get(col).add(b.concept);
  }
  const columnsOf = new Map(); // concept → [column, …], first is canonical
  for (const b of bindings) {
    const col = normalizeKey(b && b.column);
    if (!col || !b.concept || conceptsOfColumn.get(col).size !== 1) continue;
    if (!columnsOf.has(b.concept)) columnsOf.set(b.concept, []);
    const list = columnsOf.get(b.concept);
    if (!list.includes(col)) list.push(col);
  }
  const pairs = [];
  const columnCanonical = new Map();
  for (const [, cols] of columnsOf) {
    for (const c of cols.slice(1)) {
      pairs.push([c, cols[0]]);
      columnCanonical.set(c, cols[0]);
    }
  }
  for (const p of params) {
    const name = normalizeKey(p && p.name);
    if (!name) continue;
    let target = null;
    if (p.column) target = normalizeKey(p.column);
    else if (p.concept && columnsOf.has(p.concept)) target = columnsOf.get(p.concept)[0];
    if (!target) continue;
    target = columnCanonical.get(target) || target;
    if (target !== name) pairs.push([name, target]);
  }
  return pairs;
}

// The map as held: every key canonical, the first value for a key kept.
function fold(facts) {
  const out = {};
  for (const [k, v] of Object.entries(facts)) {
    const ck = canonicalKey(k);
    if (!(ck in out)) out[ck] = v;
  }
  return out;
}

export function termsFor(facts, platform, quote = (v) => JSON.stringify(String(v))) {
  const kql = platform === "sentinel" || platform === "kql";
  const out = [];
  for (const [k, v] of Object.entries(facts || {})) {
    const key = normalizeKey(k);
    const value = String(v ?? "").trim();
    if (!key || !value || isScopeKey(key)) continue;
    out.push({ key, value, text: kql ? `${key} == ${quote(value)}` : `${key}=${quote(value)}` });
  }
  return out;
}

export function heldStore({ storage, key }) {
  const listeners = new Set();

  function read() {
    try {
      const raw = storage().getItem(key);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
      const out = {};
      for (const [k, v] of Object.entries(parsed)) if (!isScopeKey(k)) out[k] = v;
      return out;
    } catch {
      return {};
    }
  }

  function write(facts) {
    try {
      if (Object.keys(facts).length) storage().setItem(key, JSON.stringify(facts));
      else storage().removeItem(key);
    } catch {
      /* storage unavailable: the cache still serves the rest of this render */
    }
  }

  let cache = read();

  function notify() {
    for (const fn of listeners) fn();
  }

  function all() {
    return fold(cache);
  }

  function get(name) {
    return fold(cache)[canonicalKey(name)] ?? "";
  }

  function set(name, value) {
    const k = canonicalKey(name);
    if (!k || isScopeKey(k)) return;
    const v = String(value ?? "").trim();
    const next = fold(cache);
    if (v) next[k] = v;
    else delete next[k];
    cache = next;
    write(cache);
    notify();
  }

  function remove(name) {
    set(name, "");
  }

  function clear() {
    cache = {};
    write(cache);
    notify();
  }

  function subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  return { normalizeKey, all, get, set, remove, clear, subscribe };
}
