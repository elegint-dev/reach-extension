// settings, the one thing worth remembering across browser sessions that is
// not a fact: where Splunk is. localStorage, guarded; private mode /
// storage-blocked just means re-entering it. The index a search runs in is
// scope (app/lib/scope.js); cross-session facts (a tenant, and the like)
// are pinned values (app/lib/pinned.js).
//
//   settings.splunkBase()            → "https://splunk.example:8000" | ""
//   settings.setSplunkBase(v)        → stored only if it parses as http(s)
//   settings.subscribe(fn)           → fn() on any change; returns unsubscribe

const KEYS = { splunkBase: "reach.splunkBase" };
const listeners = new Set();

// Exported for tests. The base URL is spliced straight into an <a href>, so
// only an actual http(s) origin is accepted, never javascript: or bare text.
export function isHttpUrl(v) {
  const s = String(v ?? "").trim();
  if (!s) return false;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function read(key) {
  try {
    return localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function write(key, v) {
  try {
    if (v) localStorage.setItem(key, v);
    else localStorage.removeItem(key);
  } catch {
    /* storage unavailable */
  }
}

function notify() {
  for (const fn of listeners) fn();
}

export function splunkBase() {
  return read(KEYS.splunkBase);
}

// Returns true if the value was accepted and stored.
export function setSplunkBase(v) {
  const s = String(v ?? "").trim().replace(/\/+$/, "");
  if (s && !isHttpUrl(s)) return false;
  write(KEYS.splunkBase, s);
  notify();
  return true;
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
