// Persistent key/value storage for the catalogue's user and discovered
// layers. chrome.storage.local inside the extension (content scripts and the
// app page alike, same store, so an annotation saved from a Splunk popup is
// on the app page instantly); localStorage when the app is served as a plain
// page. Never chrome.storage.sync: it is capped at 100 KB total and 8 KB per
// item, and a catalogue is neither.
//
//   await get(key)            → value | undefined
//   await getMany(keys)       → { [key]: value } for the keys that exist
//   await keys(prefix)        → [key] every stored key under the prefix
//   await set(key, value)     → resolves once written
//   await remove(key)
//   subscribe(fn)             → fn(key, value) on any change from any context; returns unsubscribe
//   backend()                 → "chrome" | "local" | "memory"
//
// The literal keys (storage-keys.js): the worker and the in-page popups
// read these by their stored name, so they carry no reach. prefix. Same
// backends, localStorage under the same name when served as a plain page.
//
//   await getLiteral(keys)       → { [key]: value } for the keys that exist
//   await setLiteral({ [key]: value })
//   await removeLiteral(keys)
//   subscribeLiteral(fn)         → fn(key, value) on any change to any key, as stored
//
// Plain ES module. No DOM.

import { hasChrome } from "./runtime.js";

const PREFIX = "reach.";
const listeners = new Set();
const literalListeners = new Set();
const memory = new Map();

function hasLocalStorage() {
  try {
    return typeof localStorage !== "undefined" && localStorage !== null;
  } catch {
    return false;
  }
}

export function backend() {
  if (hasChrome()) return "chrome";
  if (hasLocalStorage()) return "local";
  return "memory";
}

export async function get(key) {
  const k = PREFIX + key;
  if (hasChrome()) {
    const out = await chrome.storage.local.get(k);
    return out[k];
  }
  if (hasLocalStorage()) {
    try {
      const raw = localStorage.getItem(k);
      return raw === null ? undefined : JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
  return memory.get(k);
}

export async function getMany(names) {
  const out = {};
  const values = await Promise.all(names.map((k) => get(k)));
  names.forEach((k, i) => {
    if (values[i] !== undefined) out[k] = values[i];
  });
  return out;
}

// Every key under `prefix`, without the store prefix. One scan; a caller
// runs it once per load, not per read.
export async function keys(prefix) {
  const p = PREFIX + prefix;
  let all = [];
  if (hasChrome()) {
    if (typeof chrome.storage.local.getKeys === "function") all = await chrome.storage.local.getKeys();
    else all = Object.keys((await chrome.storage.local.get(null)) || {});
  } else if (hasLocalStorage()) {
    try {
      for (let i = 0; i < localStorage.length; i++) all.push(localStorage.key(i));
    } catch {
      all = [];
    }
    for (const k of memory.keys()) if (!all.includes(k)) all.push(k);
  } else {
    all = Array.from(memory.keys());
  }
  return all.filter((k) => typeof k === "string" && k.startsWith(p)).map((k) => k.slice(PREFIX.length));
}

export async function set(key, value) {
  const k = PREFIX + key;
  if (hasChrome()) {
    await chrome.storage.local.set({ [k]: value });
    return; // onChanged fires for every context, including this one
  }
  if (hasLocalStorage()) {
    try {
      localStorage.setItem(k, JSON.stringify(value));
    } catch {
      memory.set(k, value); // quota / private mode: keep it for this session
    }
  } else {
    memory.set(k, value);
  }
  notify(key, value);
}

export async function remove(key) {
  const k = PREFIX + key;
  if (hasChrome()) {
    await chrome.storage.local.remove(k);
    return;
  }
  if (hasLocalStorage()) {
    try {
      localStorage.removeItem(k);
    } catch {
      /* nothing to do */
    }
  }
  memory.delete(k);
  notify(key, undefined);
}

function notify(key, value) {
  for (const fn of listeners) fn(key, value);
}

function notifyLiteral(key, value) {
  for (const fn of literalListeners) fn(key, value);
}

// One onChanged listener for both listener sets, attached once per chrome
// object (a page that gains or swaps it is hooked again, never twice).
const hooked = new WeakSet();
function hookChrome() {
  if (!hasChrome() || !chrome.storage.onChanged || hooked.has(chrome.storage.onChanged)) return;
  hooked.add(chrome.storage.onChanged);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    for (const [k, ch] of Object.entries(changes)) {
      if (k.startsWith(PREFIX)) notify(k.slice(PREFIX.length), ch.newValue);
      notifyLiteral(k, ch.newValue);
    }
  });
}

export function subscribe(fn) {
  listeners.add(fn);
  hookChrome();
  return () => listeners.delete(fn);
}

// ---------------------------------------------------------------------------
// Literal keys

function names(keys) {
  return Array.isArray(keys) ? keys : [keys];
}

export async function getLiteral(keys) {
  const list = names(keys);
  if (hasChrome()) return chrome.storage.local.get(list);
  const out = {};
  for (const k of list) {
    if (hasLocalStorage()) {
      try {
        const raw = localStorage.getItem(k);
        if (raw !== null) {
          out[k] = JSON.parse(raw);
          continue;
        }
      } catch {
        /* unreadable: absent */
      }
    }
    if (memory.has(k)) out[k] = memory.get(k);
  }
  return out;
}

export async function setLiteral(obj) {
  if (hasChrome()) {
    await chrome.storage.local.set(obj);
    return;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (hasLocalStorage()) {
      try {
        localStorage.setItem(k, JSON.stringify(v));
      } catch {
        memory.set(k, v);
      }
    } else {
      memory.set(k, v);
    }
    notifyLiteral(k, v);
  }
}

export async function removeLiteral(keys) {
  const list = names(keys);
  if (!list.length) return;
  if (hasChrome()) {
    await chrome.storage.local.remove(list).catch(() => {});
    return;
  }
  for (const k of list) {
    if (hasLocalStorage()) {
      try {
        localStorage.removeItem(k);
      } catch {
        /* nothing to do */
      }
    }
    memory.delete(k);
    notifyLiteral(k, undefined);
  }
}

export function subscribeLiteral(fn) {
  literalListeners.add(fn);
  hookChrome();
  return () => literalListeners.delete(fn);
}

export default { get, getMany, keys, set, remove, subscribe, backend, getLiteral, setLiteral, removeLiteral, subscribeLiteral };
