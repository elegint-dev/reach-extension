// sentinel-settings: the one Sentinel-only settings-bar toggle that is not
// scope (app/lib/scope.js) and not a pin (app/lib/pinned.js): "always open
// Reach beside the menu" on the portal (app/lib/menu-fit.js usePanel),
// instead of the section Reach normally appends into the blade's own
// ag-Grid menu.
//
// chrome.storage.local only, no localStorage mirror: unlike scope's
// override, both sides that touch this value are already inside the
// extension's storage, the settings bar (an extension page) and
// sentinel-grid.js (the blade's content script, a different origin).
//
//   sentinelSettings.alwaysPanel()        → cached boolean, false until hydrate() resolves
//   sentinelSettings.setAlwaysPanel(v)
//   sentinelSettings.hydrate()            → reads the stored value once, follows later changes
//   sentinelSettings.subscribe(fn)        → fn() on any change; returns unsubscribe
//   sentinelSettings.read()               → one-shot chrome.storage.local read, no cache

import * as store from "./store.js";
import { KEYS } from "./storage-keys.js";
import { hasChrome } from "./runtime.js";

const KEY = KEYS.sentinelAlwaysPanel;
const listeners = new Set();
let cached = false;

function notify() {
  for (const fn of listeners) fn();
}

export function alwaysPanel() {
  return cached;
}

export function setAlwaysPanel(v) {
  cached = Boolean(v);
  if (hasChrome()) store.setLiteral({ [KEY]: cached }).catch(() => {});
  notify();
}

let hydrated = null;
export function hydrate() {
  if (hydrated) return hydrated;
  if (!hasChrome()) return (hydrated = Promise.resolve());
  hydrated = (async () => {
    const got = await store.getLiteral(KEY).catch(() => ({}));
    cached = Boolean(got[KEY]);
    store.subscribeLiteral((key, value) => {
      if (key !== KEY) return;
      cached = Boolean(value);
      notify();
    });
    notify();
  })();
  return hydrated;
}

// For a caller that wants the current value fresh, not the cache: the
// blade's content script, on every right-click, without hydrate()'s
// change listener (each read already sees the latest write).
export async function read() {
  if (!hasChrome()) return false;
  try {
    const got = await store.getLiteral(KEY);
    return Boolean(got[KEY]);
  } catch {
    return false;
  }
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export default { alwaysPanel, setAlwaysPanel, hydrate, subscribe, read };
