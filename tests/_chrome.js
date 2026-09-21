// One fake chrome for the node tests: chrome.storage.local with onChanged,
// runtime messaging, permissions, scripting registrations and tabs. Every
// list behind it is handed back so a test reads state directly.
//
//   import { fakeChrome } from "./_chrome.js";
//   const c = fakeChrome({ id, answer, permitted, registered, tabs, getURL, deferChanges, clone, storage });
//   const restore = c.install();          // globalThis.chrome = c.chrome; restore() puts back what was there
//   c.local                               // Map behind chrome.storage.local, values as stored
//   c.messages                            // every runtime.sendMessage payload, in order
//   c.bgListeners, c.connectListeners, c.startupListeners   // what the worker registered
//   c.permitted                           // Set of granted origin patterns
//   c.registered                          // content script registrations, as given to registerContentScripts
//   c.created                             // tabs.create arguments
//   c.fire(changes)                       // deliver a storage.onChanged by hand
//
// runtime.sendMessage(msg, cb): with `answer(msg)` given, its return is the
// reply (spread under { ok: true } unless it says ok: false; a throw is
// { ok: false, error, status }); without one the message goes to the
// onMessage listeners the worker registered, the first sendResponse wins.
// Both forms answer on a later microtask, as the real one does.
// storage.local.set fires onChanged once per call with every key, on the
// same tick; deferChanges: true fires it on a later task, the way Chrome
// delivers a context's own write back to it. Values are structured-cloned
// on the way in and out (clone overrides that).
// permissions.contains({ origins }) is true when every origin is in
// `permitted`; request adds, remove deletes.
// tabs.query answers `tabs` (an array, or a function of the query).

const DEFAULT_ID = "test-extension";

function keysOf(k) {
  if (k === null || k === undefined) return null;
  if (Array.isArray(k)) return k;
  if (typeof k === "object") return Object.keys(k);
  return [k];
}

export function fakeChrome(opts = {}) {
  const { id = DEFAULT_ID, answer = null, permitted = [], registered = [], tabs = [], getURL = (p) => `chrome-extension://${id}/${p}`, deferChanges = false, clone = structuredClone, storage = true } = opts;
  const local = new Map();
  const changeListeners = [];
  const bgListeners = [];
  const connectListeners = [];
  const startupListeners = [];
  const installedListeners = [];
  const permissionListeners = [];
  const messages = [];
  const created = [];
  const permittedSet = new Set(permitted);
  const registeredList = registered.slice();

  function fire(changes) {
    for (const fn of changeListeners.slice()) fn(changes, "local");
  }
  function changed(changes) {
    if (deferChanges) setTimeout(() => fire(changes), 0);
    else fire(changes);
  }

  // A message to the worker's listeners: the first sendResponse resolves,
  // a listener returning true keeps the channel open for its async answer.
  function deliver(listeners, msg, sender) {
    return new Promise((resolve) => {
      let handled = false;
      for (const fn of listeners) {
        const keep = fn(msg, sender, (res) => {
          handled = true;
          resolve(res);
        });
        if (keep === true || handled) return;
      }
      resolve(undefined);
    });
  }

  function shape(res) {
    return res && res.ok === false ? res : { ok: true, ...(res || {}) };
  }
  function reply(msg, sender) {
    if (answer) {
      try {
        return Promise.resolve(answer(msg)).then(shape);
      } catch (err) {
        return Promise.resolve({ ok: false, error: err.message, status: err.status });
      }
    }
    return deliver(bgListeners, msg, sender);
  }

  const chrome = {
    runtime: {
      id,
      lastError: null,
      getURL,
      sendMessage(...args) {
        const cb = typeof args[args.length - 1] === "function" ? args.pop() : null;
        const msg = args.length === 2 ? args[1] : args[0];
        messages.push(msg);
        const p = reply(msg, { id });
        if (!cb) return p;
        p.then((res) => cb(res));
        return undefined;
      },
      onMessage: { addListener: (fn) => bgListeners.push(fn), removeListener: (fn) => bgListeners.splice(bgListeners.indexOf(fn) >>> 0, 1) },
      onConnect: { addListener: (fn) => connectListeners.push(fn) },
      onStartup: { addListener: (fn) => startupListeners.push(fn) },
      onInstalled: { addListener: (fn) => installedListeners.push(fn) },
    },
    tabs: {
      query: async (q) => (typeof tabs === "function" ? tabs(q) : tabs.slice()),
      create: async (o) => {
        created.push(o);
        return { id: created.length, ...o };
      },
      sendMessage: async () => undefined,
    },
    storage: {
      local: {
        get: async (k) => {
          const keys = keysOf(k);
          const out = {};
          if (keys === null) {
            for (const [key, v] of local) out[key] = clone(v);
            return out;
          }
          if (k && typeof k === "object" && !Array.isArray(k)) for (const [key, v] of Object.entries(k)) out[key] = clone(v);
          for (const key of keys) if (local.has(key)) out[key] = clone(local.get(key));
          return out;
        },
        set: async (obj) => {
          const changes = {};
          for (const [k, v] of Object.entries(obj)) {
            const oldValue = local.has(k) ? clone(local.get(k)) : undefined;
            local.set(k, clone(v));
            changes[k] = { oldValue, newValue: clone(v) };
          }
          changed(changes);
        },
        remove: async (k) => {
          const changes = {};
          for (const key of keysOf(k) || []) {
            if (!local.has(key)) continue;
            changes[key] = { oldValue: clone(local.get(key)), newValue: undefined };
            local.delete(key);
          }
          if (Object.keys(changes).length) changed(changes);
        },
        clear: async () => {
          const changes = {};
          for (const [key, v] of local) changes[key] = { oldValue: clone(v), newValue: undefined };
          local.clear();
          if (Object.keys(changes).length) changed(changes);
        },
      },
      sync: { get: async () => ({}), set: async () => {}, remove: async () => {} },
      onChanged: {
        addListener: (fn) => changeListeners.push(fn),
        removeListener: (fn) => {
          const at = changeListeners.indexOf(fn);
          if (at >= 0) changeListeners.splice(at, 1);
        },
      },
    },
    scripting: {
      getRegisteredContentScripts: async () => registeredList.slice(),
      registerContentScripts: async (entries) => {
        registeredList.push(...entries);
      },
      updateContentScripts: async () => {},
      unregisterContentScripts: async ({ ids } = {}) => {
        for (const rid of ids || []) {
          const at = registeredList.findIndex((r) => r.id === rid);
          if (at >= 0) registeredList.splice(at, 1);
        }
      },
      executeScript: async () => [],
    },
    permissions: {
      contains: async ({ origins = [] } = {}) => origins.every((o) => permittedSet.has(o)),
      request: async ({ origins = [] } = {}) => {
        origins.forEach((o) => permittedSet.add(o));
        for (const fn of permissionListeners) fn({ origins });
        return true;
      },
      remove: async ({ origins = [] } = {}) => {
        origins.forEach((o) => permittedSet.delete(o));
        return true;
      },
      getAll: async () => ({ permissions: ["scripting", "storage"], origins: Array.from(permittedSet) }),
      onAdded: { addListener: (fn) => permissionListeners.push(fn) },
      onRemoved: { addListener: () => {} },
    },
  };

  // storage: false leaves chrome.storage out, so store.js keeps its memory
  // backend: the shape of a page with the runtime but no storage grant.
  if (!storage) delete chrome.storage;

  function install() {
    const had = Object.prototype.hasOwnProperty.call(globalThis, "chrome") ? globalThis.chrome : undefined;
    globalThis.chrome = chrome;
    return () => {
      if (had === undefined) delete globalThis.chrome;
      else globalThis.chrome = had;
    };
  }

  return { chrome, local, fire, deliver, messages, bgListeners, connectListeners, startupListeners, installedListeners, permissionListeners, permitted: permittedSet, registered: registeredList, created, install };
}

export default fakeChrome;
