// The module registry: what Reach is cut into, and which pieces are on.
// Off means gone from the page: the route is not mounted and its nav link
// not drawn, the popup band is not rendered, the enrichment source never
// offers, and the module's host permissions are revoked. Off does not
// empty the module's storage: only the keys its registry entry marks
// `secret` (a credential or a grant) go with it. Everything else a module
// has kept stays until Clear on its row or Clear all Reach data removes
// it (removeKeys, wipe.js).
//
//   MODULES                        one frozen list, the order the settings surface draws
//   HEAD, SECTIONS                 title-block ids and titled-section ids, each drawn where BANDS says
//   BANDS                          the draw order shared by the popups and the value page; every id of
//                                  HEAD and SECTIONS once, not their concatenation
//   await hydrate()                read the enabled set once; readers below are sync after it
//   on(id, platform)               tier core, or enabled, and platform in the module's platforms
//   enabled(platform)              every module id that is on
//   routes(platform)               route ids mounted right now
//   routeStatus(route, platform)   "on" | "off" | "absent" | "unknown"
//   bands(platform)                BANDS filtered to modules that are on
//   sources(platform)              enrichment source ids that may offer
//   sourceOwner(id) / routeOwner(id) / bandOwner(id)   the module entry, or null
//   keysOf(id)                     { chrome, store, storePrefix, local, session, field, secret }
//   await hostsOf(id)              host patterns the module needs right now (static, or from its settings)
//   await setEnabled(id, on)       on: request hosts (needs a click), then write; off: write, revoke hosts,
//                                  remove the keys keysOf(id).secret names (a credential or a grant)
//   await removeSecrets(id)        the keys Off itself removes; a subset of removeKeys
//   await removeKeys(id)           every key family the module owns, regardless of secret; Clear's and wipe.js's
//   setting(id, key)               a module setting's value as of the last hydrate or write, sync
//   await readSettings(id) / writeSetting(id, key, value)   a module setting, chrome.storage.local (localStorage when served)
//   subscribe(fn)                  fn() after the enabled set or a setting changes, from any context
//   anchor(id)                     the settings surface anchor for a module, "module-<id>"
//
// The enabled set is one store document, "modules" (chrome.storage.local
// key reach.modules): { enabled: { [id]: true | false } }. An id absent
// from it takes its tier's default (core and on are on, off is off), so a
// module added later starts at its tier. A core module has no entry and
// is always on. A route or source entry is an id, or { id, platforms }
// when one item of a both-platform module is narrower.
//
// Plain ES module. No DOM. chrome.* is used when present and guarded.

import * as store from "./store.js";
import { PLATFORM } from "./platform.js";
import { PROVIDERS, PROVIDER_LABEL, patternFor, WRITES_HINT } from "./enrich/selfhosted.js";

export const KEY = "modules";

const BOTH = Object.freeze(["splunk", "sentinel"]);
const SPLUNK = Object.freeze(["splunk"]);

// HEAD: the frame's title block on the page (h1, chips, scope, callout,
// actions) and the untitled rows on the popup (badge, chips, scope,
// actions). SECTIONS: the titled sections, each under its registry
// heading, on both surfaces.
export const HEAD = Object.freeze(["scope", "runbook", "hold", "benign", "exclusion"]);
export const SECTIONS = Object.freeze(["value", "meaning", "everywhere", "verdict", "enrich", "pivots", "workflows", "pattern"]);
// BANDS is the draw order every walk reads: runbook first when present,
// then verdict, Meaning (value folded in), Hold, Known benign, then the
// rest as HEAD and SECTIONS otherwise have them. Not [...HEAD,
// ...SECTIONS]: verdict is pulled ahead of Hold and Known benign so a
// popup reads verdict, then what the value means, then what to do with it.
export const BANDS = Object.freeze(["scope", "runbook", "verdict", "value", "meaning", "hold", "benign", "exclusion", "everywhere", "enrich", "pivots", "workflows", "pattern"]);

const entry = (m) => Object.freeze({ routes: [], bands: [], sources: [], settings: [], keys: {}, hosts: [], sends: "nothing", ...m });

export const MODULES = Object.freeze([
  entry({
    id: "shell",
    label: "Reach",
    about: "The panel and popup frames: router, bar, omnibox, start and unknown pages, the host hooks.",
    tier: "core",
    platforms: BOTH,
    routes: ["start", "unknown"],
    bands: ["scope"],
    keys: { chrome: ["trustedOrigins", "reach.sentinel.alwaysPanel", "reach.onboarding.dismissed"], store: ["modules"], local: ["reach.platform", "reach.theme"], session: ["reach.trail"] },
    sends: "nothing; content scripts run on the SIEM origins you enabled",
  }),
  entry({
    id: "catalogue",
    label: "Catalogue",
    about: "What a sourcetype, record type, field or value means and who says so: pack, yours, discovered.",
    tier: "core",
    platforms: BOTH,
    routes: ["catalogue", "sourcetype", "field", "value", { id: "event", platforms: SPLUNK }, "packs", "search"],
    bands: ["value", "meaning", "everywhere"],
    keys: { store: ["catalogue.user", "catalogue.falcon"] },
  }),
  entry({
    id: "pivots",
    label: "Pivots",
    about: "Every edge a pack or the FDR bundle declares from a field, its SPL or KQL, the drawer, Run in Splunk or Open as query tab.",
    tier: "core",
    platforms: BOTH,
    bands: ["pivots"],
    sends: "Splunk: the pivot's search to your own Splunk on Run; Sentinel: nothing",
  }),
  entry({
    id: "hold",
    label: "Hold and notebook",
    about: "Hold a value with the event, search and time it came from; the Holding rail; the notebook, its export and the paste-back import.",
    tier: "core",
    platforms: BOTH,
    routes: ["notebook"],
    bands: ["hold"],
    keys: { store: ["notebook", "searches"], local: ["reach.pinned"], session: ["reach.investigation", "reach.lastEvent"] },
  }),
  entry({
    id: "settings",
    label: "Settings",
    about: "Where the SIEM is and what scope a search runs in; the module list; Clear all Reach data.",
    tier: "core",
    platforms: BOTH,
    keys: { chrome: ["csIndex", "spAppNamespace"], local: ["reach.scope", "reach.splunkBase"] },
  }),
  entry({
    id: "verdicts",
    label: "Known-good verdicts",
    about: "A hash, signing id or image path on a mac or linux Falcon event checked against the bundled corpus, and against the fleet baseline run from the Falcon sourcetype page.",
    tier: "on",
    platforms: BOTH,
    bands: ["verdict"],
    keys: { field: ["catalogue.discovered.org_corpus"] },
  }),
  entry({
    id: "enrich-bundled",
    label: "Bundled enrichment",
    about: "Offline lookups shipped in the extension: CISA KEV, MITRE ATT&CK, Sigma, Splunk ESCU, Sentinel analytic rules, LOLDrivers, LOLRMM, and the deep-link rows LOLBAS, GTFOBins, HijackLibs.",
    tier: "on",
    platforms: BOTH,
    bands: ["enrich"],
    sources: ["kev", "attack", "sigma", { id: "escu", platforms: SPLUNK }, { id: "sentinel-rules", platforms: ["sentinel"] }, "loldrivers", "lolrmm", "lolbas", "gtfobins", "hijacklibs"],
    sends: "nothing; a deep-link row opens a public page in a new tab on click",
  }),
  entry({
    id: "discovery",
    label: "Discover",
    about: "Measure your own tables: fields, fill, record types, health and deltas.",
    tier: "on",
    platforms: BOTH,
    routes: ["discover"],
    keys: { store: ["catalogue.discovered.envs", "catalogue.discovery.sweep", "sentinel.workspaces"], storePrefix: ["catalogue.discovered."], local: ["reach.devExt"] },
    sends: "Splunk: fixed reporting searches to your own Splunk through the open tab; Sentinel: nothing",
  }),
  entry({
    id: "coverage",
    label: "Coverage",
    about: "Which concepts each feed carries on your tables, what the proposer thinks unbound columns mean, confirm into a binding.",
    tier: "on",
    platforms: BOTH,
    routes: ["coverage"],
    keys: { field: ["catalogue.user.bindings"] },
  }),
  entry({
    id: "workflows",
    label: "Guided workflows",
    about: "The FDR five (Splunk) and any pack workflow: situation, inputs, expect, disambiguate, troubleshoot, the search. A pack hunt runs once from here and is saved in the SIEM to run on a schedule.",
    tier: "on",
    platforms: BOTH,
    routes: ["workflow"],
    // The popups' Workflows band is the FDR five's and stays Splunk's; a
    // pack workflow on Sentinel is reached from the start page.
    bands: [{ id: "workflows", platforms: SPLUNK }],
    sends: "the workflow's search to your own Splunk on Run; nothing on Sentinel, where Copy KQL is the hand-off",
  }),
  entry({
    id: "runbooks",
    label: "Runbooks",
    about: "An alert row recognised by its rule, and a runbook seeded from what the rule's author published: the trigger, the false-positive conditions, pivots bound from the row, then Hold or Mark benign. Yours to edit, export and import, or hand to Sentinel as incident tasks.",
    tier: "on",
    platforms: BOTH,
    routes: ["runbook"],
    bands: ["runbook"],
    keys: { store: ["runbooks"] },
    sends: "nothing; the bundled rule indexes are read on the first alert row",
  }),
  entry({
    id: "benign",
    label: "Known benign",
    about: "Mark a value benign for this field and sourcetype with a reason; the set is kept locally.",
    tier: "on",
    platforms: BOTH,
    bands: ["benign", "exclusion"],
    settings: [{ key: "reach.benign.inject", kind: "toggle", default: false, label: "Offer the exclusion in the editor", hint: "On, the exclusion strip and every insert offer write into the search editor; off, they copy." }],
    keys: { store: ["benign"], chrome: ["reach.benign.inject"] },
  }),
  entry({
    id: "virustotal",
    label: "VirusTotal",
    about: "Look up an ip, domain or hash with your own key, one click per lookup.",
    tier: "off",
    platforms: BOTH,
    sources: ["virustotal"],
    settings: [{ key: "vtApiKey", kind: "secret", label: "API key", hint: "64 hex characters from virustotal.com/gui/my-apikey. Stored only in this browser." }],
    keys: { chrome: ["vtApiKey"], secret: ["vtApiKey"] },
    hosts: ["https://www.virustotal.com/*"],
    sends: "ip, domain or hash to virustotal.com with your key, on click",
  }),
  entry({
    id: "circl",
    label: "CIRCL hashlookup",
    about: "Known-file check on a hash, no key.",
    tier: "off",
    platforms: BOTH,
    sources: ["circl"],
    keys: { chrome: ["reach.enrich.circl.enabled"] },
    hosts: ["https://hashlookup.circl.lu/*"],
    sends: "the hash to hashlookup.circl.lu, on click",
  }),
  entry({
    id: "epss",
    label: "EPSS",
    about: "Exploit probability for a CVE, no key.",
    tier: "off",
    platforms: BOTH,
    sources: ["epss"],
    keys: { chrome: ["reach.enrich.epss.enabled"] },
    hosts: ["https://api.first.org/*"],
    sends: "the CVE id to api.first.org, on click",
  }),
  entry({
    id: "selfhosted",
    label: "Self-hosted relay",
    about: "One MISP or IntelOwl instance you run, at a typed origin with a token; hash, ip, domain, url and cve.",
    tier: "off",
    platforms: BOTH,
    sources: ["selfhosted"],
    settings: [
      { key: "reach.enrich.selfhosted.provider", kind: "select", label: "Provider", default: "misp", options: PROVIDERS.map((id) => ({ value: id, label: PROVIDER_LABEL[id] })) },
      { key: "reach.enrich.selfhosted.origin", kind: "url", label: "Origin", placeholder: "https://misp.example.org" },
      { key: "reach.enrich.selfhosted.token", kind: "secret", label: "Token / API key" },
      { key: "reach.enrich.selfhosted.writes", kind: "toggle", default: false, label: "Allow writes to MISP (record a sighting, propose an attribute)", hint: WRITES_HINT },
    ],
    keys: { chrome: ["reach.enrich.selfhosted.provider", "reach.enrich.selfhosted.origin", "reach.enrich.selfhosted.token", "reach.enrich.selfhosted.writes"], secret: ["reach.enrich.selfhosted.origin", "reach.enrich.selfhosted.token"] },
    hosts: (s) => [patternFor(s["reach.enrich.selfhosted.origin"] || "")].filter(Boolean),
    sends: "the value to the origin you typed, with the token, on click; with writes on, a sighting or a proposed attribute to your MISP, on click",
  }),
  entry({
    id: "pattern",
    label: "Pattern builder",
    about: "The value cut by shape, a state per piece, the cheapest SPL or KQL that says it, previewed over the profile's top values.",
    tier: "off",
    platforms: BOTH,
    bands: ["pattern"],
    sends: "Splunk: the test search to your own Splunk on click; Sentinel: nothing",
  }),
  entry({
    id: "advisor",
    label: "Query advisor",
    about: "Efficiency class per field, lint over SPL or KQL on a click, and on Splunk the job's own counts.",
    tier: "off",
    platforms: BOTH,
    sends: "Splunk: a GET on search/jobs/<sid> to your own Splunk on Measure; Sentinel: nothing",
  }),
  entry({
    id: "share",
    label: "Share and import",
    about: "Export your notes and bindings as a file, import another's; the notebook's own import is not gated here.",
    tier: "off",
    platforms: BOTH,
    routes: ["share"],
    sends: "nothing; a file download, a file pick, the clipboard",
  }),
]);

const byId = new Map(MODULES.map((m) => [m.id, m]));

export function get(id) {
  return byId.get(id) || null;
}

export function anchor(id) {
  return `module-${id}`;
}

// ---------------------------------------------------------------------------
// The enabled set

let chosen = {};
let hydrated = null;
const listeners = new Set();

function notify() {
  for (const fn of listeners) fn();
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function readDoc(doc) {
  const enabled = doc && typeof doc === "object" && doc.enabled && typeof doc.enabled === "object" ? doc.enabled : {};
  const next = {};
  for (const [id, v] of Object.entries(enabled)) if (byId.has(id) && typeof v === "boolean") next[id] = v;
  chosen = next;
}

// Every module setting's value, read once with the enabled set so a
// render can ask synchronously (setting()); kept fresh by the storage
// change listener and by writeSetting().
let settingValues = {};
let listening = false;

function allSettingKeys() {
  return MODULES.flatMap((m) => m.settings.map((s) => s.key));
}

async function readAllSettings() {
  const got = await store.getLiteral(allSettingKeys());
  const next = {};
  for (const m of MODULES) for (const s of m.settings) next[s.key] = got[s.key] === undefined ? (s.default === undefined ? "" : s.default) : got[s.key];
  settingValues = next;
}

function listen() {
  if (listening) return;
  listening = true;
  store.subscribe((key, value) => {
    if (key !== KEY) return;
    readDoc(value);
    notify();
  });
  const keys = new Set(allSettingKeys());
  store.subscribeLiteral((k, value) => {
    if (!keys.has(k)) return;
    const def = MODULES.flatMap((m) => m.settings).find((s) => s.key === k);
    settingValues = { ...settingValues, [k]: value === undefined ? (def && def.default !== undefined ? def.default : "") : value };
    notify();
  });
}

export function hydrate() {
  if (!hydrated) {
    hydrated = Promise.all([store.get(KEY).then(readDoc), readAllSettings()])
      .catch(() => {
        chosen = {};
      })
      .then(listen);
  }
  return hydrated;
}

// Tests only: forget the store read so the next hydrate() reads again.
export function reset() {
  chosen = {};
  settingValues = {};
  hydrated = null;
}

export function setting(id, key) {
  const def = settingsOf(id).find((s) => s.key === key);
  if (!def) return undefined;
  return key in settingValues ? settingValues[key] : def.default === undefined ? "" : def.default;
}

function inPlatforms(list, platform) {
  return !platform || !Array.isArray(list) || list.includes(platform);
}

export function on(id, platform = PLATFORM) {
  const m = byId.get(id);
  if (!m || !inPlatforms(m.platforms, platform)) return false;
  if (m.tier === "core") return true;
  return typeof chosen[id] === "boolean" ? chosen[id] : m.tier === "on";
}

export function enabled(platform = PLATFORM) {
  return MODULES.filter((m) => on(m.id, platform)).map((m) => m.id);
}

function itemId(item) {
  return typeof item === "string" ? item : item.id;
}

function itemOn(item, platform) {
  return typeof item === "string" || inPlatforms(item.platforms, platform);
}

export function routes(platform = PLATFORM) {
  const out = [];
  for (const m of MODULES) {
    if (!on(m.id, platform)) continue;
    for (const r of m.routes) if (itemOn(r, platform)) out.push(itemId(r));
  }
  return out;
}

function ownerOf(list, id) {
  for (const m of MODULES) for (const item of m[list]) if (itemId(item) === id) return m;
  return null;
}

export function routeOwner(route) {
  return ownerOf("routes", route);
}

export function sourceOwner(source) {
  return ownerOf("sources", source);
}

export function bandOwner(band) {
  return ownerOf("bands", band);
}

// Why a route is not mounted: "absent" when the module or the route is not
// on this platform, "off" when the module is switched off, "unknown" when
// no module owns it.
export function routeStatus(route, platform = PLATFORM) {
  const m = routeOwner(route);
  if (!m) return "unknown";
  const item = m.routes.find((r) => itemId(r) === route);
  if (!inPlatforms(m.platforms, platform) || !itemOn(item, platform)) return "absent";
  return on(m.id, platform) ? "on" : "off";
}

export function bands(platform = PLATFORM) {
  return BANDS.filter((b) => {
    const m = bandOwner(b);
    return m && on(m.id, platform) && itemOn(m.bands.find((item) => itemId(item) === b), platform);
  });
}

export function sources(platform = PLATFORM) {
  const out = [];
  for (const m of MODULES) {
    if (!on(m.id, platform)) continue;
    for (const s of m.sources) if (itemOn(s, platform)) out.push(itemId(s));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Keys, hosts, settings

export function keysOf(id) {
  const k = (byId.get(id) || {}).keys || {};
  return { chrome: k.chrome || [], store: k.store || [], storePrefix: k.storePrefix || [], local: k.local || [], session: k.session || [], field: k.field || [], secret: k.secret || [] };
}

// A live count of the module's registry-declared keys actually present in
// storage right now, not the registry's own name total (keysOf(id) lists
// what a module may hold, not what it holds). A storePrefix key already
// counted through an explicit store key is not counted twice. Field keys
// live in another module's document (wipe.js's FIELD_CLEARERS); this stays
// with the stores modules.js already reads.
export async function keysStoredOf(id) {
  const k = keysOf(id);
  let n = 0;
  if (k.store.length) n += Object.keys(await store.getMany(k.store)).length;
  for (const prefix of k.storePrefix) {
    const found = await store.keys(prefix);
    n += found.filter((key) => !k.store.includes(key)).length;
  }
  if (k.chrome.length) n += Object.keys(await store.getLiteral(k.chrome)).length;
  for (const key of k.local) {
    try {
      if (localStorage.getItem(key) !== null) n++;
    } catch {
      /* storage unavailable */
    }
  }
  for (const key of k.session) {
    try {
      if (sessionStorage.getItem(key) !== null) n++;
    } catch {
      /* storage unavailable */
    }
  }
  return n;
}

export function settingsOf(id) {
  return (byId.get(id) || {}).settings || [];
}

export async function readSettings(id) {
  const defs = settingsOf(id);
  if (!defs.length) return {};
  const got = await store.getLiteral(defs.map((s) => s.key));
  const out = {};
  for (const s of defs) out[s.key] = got[s.key] === undefined ? (s.default === undefined ? "" : s.default) : got[s.key];
  return out;
}

export async function readSetting(id, key) {
  return (await readSettings(id))[key];
}

export async function writeSetting(id, key, value) {
  if (!settingsOf(id).some((s) => s.key === key)) throw new Error(`modules.writeSetting: ${id} has no setting ${key}`);
  await store.setLiteral({ [key]: value });
  settingValues = { ...settingValues, [key]: value };
  notify();
}

export async function hostsOf(id) {
  const m = byId.get(id);
  if (!m) return [];
  if (typeof m.hosts === "function") return m.hosts(await readSettings(id));
  return m.hosts.slice();
}

function hasPermissions() {
  return typeof chrome !== "undefined" && Boolean(chrome.permissions);
}

// Whether every host the module needs is granted; true with no hosts.
export async function permitted(id) {
  const hosts = await hostsOf(id);
  if (!hosts.length) return true;
  if (!hasPermissions() || typeof chrome.permissions.contains !== "function") return false;
  return chrome.permissions.contains({ origins: hosts }).catch(() => false);
}

// Request the module's hosts from a click. Resolves true when nothing is
// needed or the grant came through.
export async function requestHosts(id, hosts = null) {
  const list = hosts || (await hostsOf(id));
  if (!list.length) return true;
  if (!hasPermissions() || typeof chrome.permissions.request !== "function") return false;
  return chrome.permissions.request({ origins: list }).catch(() => false);
}

export async function revokeHosts(id, hosts = null) {
  const list = hosts || (await hostsOf(id));
  if (!list.length) return [];
  if (!hasPermissions() || typeof chrome.permissions.remove !== "function") return [];
  const ok = await chrome.permissions.remove({ origins: list }).catch(() => false);
  return ok ? list : [];
}

// Remove every key the module owns, regardless of secret. Clear on a row
// and Clear all Reach data (wipe.js) call this; Off does not. The
// field-level clear (coverage's bindings inside catalogue.user) is
// wipe.js's own clearModule, which calls this first and then its own
// field clearers.
export async function removeKeys(id) {
  const k = keysOf(id);
  const removed = [];
  for (const key of k.store) {
    await store.remove(key);
    removed.push(`reach.${key}`);
  }
  for (const prefix of k.storePrefix) {
    for (const key of await store.keys(prefix)) {
      await store.remove(key);
      removed.push(`reach.${key}`);
    }
  }
  await store.removeLiteral(k.chrome);
  removed.push(...k.chrome);
  for (const s of settingsOf(id)) settingValues = { ...settingValues, [s.key]: s.default === undefined ? "" : s.default };
  for (const key of k.local) {
    try {
      localStorage.removeItem(key);
      removed.push(key);
    } catch {
      /* storage unavailable */
    }
  }
  for (const key of k.session) {
    try {
      sessionStorage.removeItem(key);
      removed.push(key);
    } catch {
      /* storage unavailable */
    }
  }
  return removed;
}

// Off's own removal: only the keys the module's registry entry marks
// `secret` (a credential or a grant), never the rest of what it keeps.
export async function removeSecrets(id) {
  const k = keysOf(id);
  if (!k.secret.length) return [];
  const secret = new Set(k.secret);
  const removed = [];
  for (const key of k.store) {
    if (!secret.has(key)) continue;
    await store.remove(key);
    removed.push(`reach.${key}`);
  }
  const chromeSecrets = k.chrome.filter((key) => secret.has(key));
  if (chromeSecrets.length) {
    await store.removeLiteral(chromeSecrets);
    removed.push(...chromeSecrets);
  }
  for (const s of settingsOf(id)) if (secret.has(s.key)) settingValues = { ...settingValues, [s.key]: s.default === undefined ? "" : s.default };
  for (const key of k.local) {
    if (!secret.has(key)) continue;
    try {
      localStorage.removeItem(key);
      removed.push(key);
    } catch {
      /* storage unavailable */
    }
  }
  for (const key of k.session) {
    if (!secret.has(key)) continue;
    try {
      sessionStorage.removeItem(key);
      removed.push(key);
    } catch {
      /* storage unavailable */
    }
  }
  return removed;
}

async function writeChosen() {
  await store.set(KEY, { enabled: { ...chosen } });
  notify();
}

// A per-source flag background.js reads beside the module set (circl and
// epss): kept in step with the toggle so the worker's own check agrees.
const FLAG_KEYS = { circl: "reach.enrich.circl.enabled", epss: "reach.enrich.epss.enabled" };

export async function setEnabled(id, want) {
  const m = byId.get(id);
  if (!m) throw new Error(`modules.setEnabled: no module ${id}`);
  if (m.tier === "core") throw new Error(`modules.setEnabled: ${id} is core and cannot be switched`);
  await hydrate();
  if (want) {
    const hosts = await hostsOf(id);
    if (hosts.length && !hasPermissions()) return { ok: false, why: `Not available here: a page served outside the extension cannot ask for ${hosts.join(", ")}. Turn ${m.label} on from the extension's Settings.` };
    const ok = await requestHosts(id, hosts);
    if (!ok) return { ok: false, why: `Permission for ${hosts.join(", ")} was not granted; ${m.label} stays off.` };
    if (FLAG_KEYS[id]) await store.setLiteral({ [FLAG_KEYS[id]]: true });
    chosen = { ...chosen, [id]: true };
    await writeChosen();
    return { ok: true, hosts };
  }
  const hosts = await hostsOf(id);
  chosen = { ...chosen, [id]: false };
  await writeChosen();
  const revoked = await revokeHosts(id, hosts);
  const removed = await removeSecrets(id);
  return { ok: true, hostsRevoked: revoked, removed };
}

export default { MODULES, HEAD, SECTIONS, BANDS, KEY, get, anchor, hydrate, reset, on, enabled, routes, routeStatus, routeOwner, sourceOwner, bandOwner, bands, sources, keysOf, keysStoredOf, settingsOf, setting, readSettings, readSetting, writeSetting, hostsOf, permitted, requestHosts, revokeHosts, removeKeys, removeSecrets, setEnabled, subscribe };
