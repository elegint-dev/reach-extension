// document: one versioned JSON document under a store.js key, the shape
// benign.js, notebook.js and runbooks-store.js share. The instance keeps
// the live copy, adopts whatever is stored into the current shape, writes
// through one serialised chain (every write rereads first, so two contexts
// on one chrome.storage.local document never overwrite each other), prunes
// past a byte budget in the document's own order, and tells subscribers
// what changed.
//
//   const D = versionedDocument({ key, version, empty, adopt, prune, budget })
//
//   key        the store.js key (reach.<key> in chrome.storage.local)
//   version    the document's v; empty() defaults to { v: version }
//   empty()    → a fresh document
//   adopt(raw) → the stored value as the current shape; a foreign or
//                damaged value becomes empty()
//   prune(d, { at, bytes, budget }) → { pruned, warning }, called on a
//                write only when bytes(d) is past the budget; it removes in
//                place and says what went
//   budget     bytes; 0 means unbounded
//
//   await D.load({ force? })     → the document; the readers are synchronous
//                                  and answer empty() until it resolves
//   D.get()                      → the live document, empty() before load
//   await D.update(fn, { at? })  → fn(d) mutates the reread document and
//                                  returns the call's result; returning
//                                  D.unchanged(result) leaves the store alone
//   await D.prune()              → { pruned, warning } from an empty write
//   D.subscribe(fn)              → fn({ type: "change" }) on any write from
//                                  any context, fn({ type: "pruned", ... })
//                                  after a write that pruned; returns unsubscribe
//   D.emit(ev)                   → an event of the document's own
//   D.bytes(d = live)            → the size as stored
//   D.exportJSON(body)           → JSON text of { v, exported_at, ...body }
//   D.lastPrune()                → what the last write pruned
//   D._reset()                   → drop the live copy (tests)
//
// "change" comes from the store's own notification, once per write on
// every backend; update() never emits it itself. Plain ES module. No DOM.

import * as store from "./store.js";

class Unchanged {
  constructor(result) {
    this.result = result;
  }
}

export function newId(prefix) {
  const rnd = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID().slice(0, 8) : Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now().toString(36)}_${rnd}`;
}

const NO_PRUNE = Object.freeze({ pruned: [], warning: "" });

export function versionedDocument({ key, version = 1, empty = null, adopt = null, prune = null, budget = 0 } = {}) {
  if (!key) throw new Error("versionedDocument needs a key.");
  const fresh = empty || (() => ({ v: version }));
  const take = adopt || ((raw) => (raw && typeof raw === "object" && raw.v === version ? raw : fresh()));

  const listeners = new Set();
  let doc = null;
  let loading = null;
  let chain = Promise.resolve();
  let last = NO_PRUNE;
  let hooked = false;

  function emit(ev) {
    for (const fn of listeners) {
      try {
        fn(ev);
      } catch {
        /* one listener's error does not stop the rest */
      }
    }
  }

  function hook() {
    if (hooked) return;
    hooked = true;
    store.subscribe((k, value) => {
      if (k !== key) return;
      doc = take(value);
      emit({ type: "change" });
    });
  }

  function load({ force = false } = {}) {
    hook();
    if (doc && !force) return Promise.resolve(doc);
    if (loading && !force) return loading;
    loading = store
      .get(key)
      .then((raw) => {
        doc = take(raw);
        return doc;
      })
      .finally(() => {
        loading = null;
      });
    return loading;
  }

  function get() {
    return doc || fresh();
  }

  function bytes(d = doc) {
    const s = JSON.stringify(d || fresh());
    return typeof TextEncoder !== "undefined" ? new TextEncoder().encode(s).length : s.length;
  }

  function update(fn, { at = Date.now() } = {}) {
    const step = chain.then(async () => {
      await load({ force: true });
      const out = fn(doc);
      if (out instanceof Unchanged) return out.result;
      last = budget && prune && bytes(doc) > budget ? { ...NO_PRUNE, ...(prune(doc, { at, bytes, budget }) || {}) } : NO_PRUNE;
      await store.set(key, doc);
      if (last.pruned.length || last.warning) emit({ type: "pruned", ...last });
      return out;
    });
    chain = step.catch(() => {});
    return step;
  }

  function unchanged(result) {
    return new Unchanged(result);
  }

  function pruneNow(opts) {
    return update((d) => d, opts).then(() => ({ ...last }));
  }

  function subscribe(fn) {
    hook();
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  function exportJSON(body = {}) {
    return JSON.stringify({ v: version, exported_at: new Date().toISOString(), ...body }, null, 2);
  }

  function lastPrune() {
    return { ...last };
  }

  function _reset() {
    doc = null;
    loading = null;
    chain = Promise.resolve();
    last = NO_PRUNE;
  }

  return { key, version, budget, load, get, update, unchanged, prune: pruneNow, subscribe, emit, bytes, exportJSON, lastPrune, _reset };
}

export default { versionedDocument, newId };
