// wipe: "Clear all Reach data" (Settings) and a row's own Clear button.
// Every key this extension writes belongs to one module in the registry
// (app/lib/modules.js keys), in every store it writes to; clearModule(id)
// removes that module's, run() removes every module's, then unregisters
// every content script and, if asked, revokes the optional host
// permissions that let them run. Switching a module off (modules.js
// setEnabled) does not go through here: it removes only that module's
// secret-marked keys (modules.removeSecrets), not this file's full clear.
//
//   await wipe.clearModule(id)
//     → [key, ...]                the keys removed, prefixed as stored
//   await wipe.run({ revokeHosts: false })
//     → { storage: [key, ...],   // store.js documents + literal chrome.storage.local keys
//         local: [key, ...],     // this page's own localStorage
//         session: [key, ...],   // this page's own sessionStorage
//         scriptsUnregistered: n,
//         hostsRevoked: [pattern, ...] }
//
// Two things this cannot reach, both worth saying out loud rather than
// silently missing:
//
//   - sessionStorage is per tab. A wipe run from one tab clears that tab's
//     reach.investigation; another open tab keeps its own until it closes.
//   - a content script writes some of these same keys (reach.scope,
//     reach.pinned, reach.investigation) into the Splunk or Sentinel
//     page's own localStorage/sessionStorage, not the extension's. That is
//     ordinary site data on that origin once written, outside anything an
//     extension page can clear; see SECURITY.md.
//
// tests/modules-registry.test.js holds every store's exported KEY to a
// registry entry, and tests/wipe.test.js scans app/lib for an exported
// KEY/KEYS/PREFIX the registry has not been told about.

import * as modules from "./modules.js";
import * as catalogue from "./catalogue.js";
import * as layer from "./layer.js";

// The literal chrome.storage.local keys the enrichment modules keep
// (an API key, an origin, a toggle), read from the registry.
export const ENRICH_SETTING_KEYS = Object.freeze(
  modules.MODULES.filter((m) => m.sources.length).flatMap((m) => modules.keysOf(m.id).chrome),
);

// A field inside another module's document, cleared in place rather than
// as a key: coverage's bindings live in catalogue.user, the verdicts
// module's fleet baseline in every discovered environment.
const FIELD_CLEARERS = {
  "catalogue.user.bindings": async () => {
    try {
      await catalogue.clearBindings();
    } catch {
      /* the catalogue is not loaded here (a content script, a bare test): nothing to clear */
    }
  },
  "catalogue.discovered.org_corpus": async () => {
    const all = await layer.readAll();
    for (const [envKey, env] of Object.entries(all)) {
      if (!env || !env.org_corpus) continue;
      await layer.update(envKey, (e) => {
        delete e.org_corpus;
      });
    }
  },
};

export async function clearModule(id) {
  const removed = await modules.removeKeys(id);
  for (const field of modules.keysOf(id).field) {
    const fn = FIELD_CLEARERS[field];
    if (fn) {
      await fn();
      removed.push(field);
    }
  }
  return removed;
}

async function unregisterScripts() {
  if (typeof chrome === "undefined" || !chrome.scripting || typeof chrome.scripting.getRegisteredContentScripts !== "function") return 0;
  const existing = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const ids = existing.filter((s) => s && typeof s.id === "string" && s.id.startsWith("reach-")).map((s) => s.id);
  if (!ids.length) return 0;
  if (typeof chrome.scripting.unregisterContentScripts !== "function") return 0;
  await chrome.scripting.unregisterContentScripts({ ids }).catch(() => {});
  return ids.length;
}

// Every optional permission currently granted. The extension's required
// permissions (storage, activeTab, scripting, sidePanel) are not optional
// and chrome.permissions.remove refuses them; only origins are ever
// requested optionally (manifest.json optional_host_permissions), so this
// only ever removes host access, never a base permission.
async function revokeOptionalHosts() {
  if (typeof chrome === "undefined" || !chrome.permissions || typeof chrome.permissions.getAll !== "function") return [];
  const got = await chrome.permissions.getAll().catch(() => ({ origins: [] }));
  const origins = Array.isArray(got.origins) ? got.origins : [];
  if (!origins.length) return [];
  if (typeof chrome.permissions.remove !== "function") return [];
  const ok = await chrome.permissions.remove({ origins }).catch(() => false);
  return ok ? origins : [];
}

export async function run({ revokeHosts = false } = {}) {
  const storageKeys = [];
  const localKeys = [];
  const sessionKeys = [];

  for (const m of modules.MODULES) {
    const k = modules.keysOf(m.id);
    const local = new Set(k.local);
    const session = new Set(k.session);
    for (const key of await clearModule(m.id)) {
      if (local.has(key)) localKeys.push(key);
      else if (session.has(key)) sessionKeys.push(key);
      else if (!k.field.includes(key)) storageKeys.push(key);
    }
  }

  const scriptsUnregistered = await unregisterScripts();
  const hostsRevoked = revokeHosts ? await revokeOptionalHosts() : [];

  return { storage: storageKeys, local: localKeys, session: sessionKeys, scriptsUnregistered, hostsRevoked };
}

export default { run, clearModule, ENRICH_SETTING_KEYS };
