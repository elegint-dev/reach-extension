// Which SIEM this page is about. The catalogue model is the same on both;
// what differs is the host UI Reach hooks, the query language it emits and
// the words it uses for the key. Everything platform-specific asks here
// rather than sniffing for chrome.* or a Splunk asset signature.
//
//   PLATFORM                 "sentinel" | "splunk", decided once, when this module loads
//   rememberPlatform(p)      write the platform the next app page should open on
//   isSentinel()
//   isPortalOrigin(origin)   an enabled origin that is the Azure portal (a Sentinel environment, never a Splunk one)
//   TERMS                    the user-facing words for the catalogue key
//                            (Splunk: sourcetype / field / index / SPL;
//                             Sentinel: table / column / workspace / KQL)
//
// One extension serves both. A content script is on one platform's page,
// so the page's hostname decides: the Azure portal and its blade frames
// are Sentinel, anything else is Splunk (the Splunk scripts only ever run
// on origins the user enabled as Splunk). The catalogue app (index.html,
// or the copy served for development; it sets window.REACH_APP) is told by
// whoever opened it:
// `?platform=sentinel|splunk` on its URL, which it remembers in
// localStorage for next time; with neither, Splunk. Tests pin a platform
// through globalThis.REACH_PLATFORM before importing anything.
//
// The internal key names stay `sourcetype` and `field` everywhere in the
// code and in stored data: a Sentinel table is stored under the same key a
// Splunk sourcetype would be, so exports, packs and the store format do not
// fork between platforms. Only the words shown to the user change.
//
// Plain ES module. No DOM writes; reads location and localStorage.

import { KEYS } from "./storage-keys.js";

const PORTAL_HOST_RE = /(^|\.)portal\.azure\.com$|\.reactblade\.portal\.azure\.net$|(^|\.)security\.microsoft\.com$/;
const STORAGE_KEY = KEYS.platform;

function fromOverride() {
  const v = globalThis.REACH_PLATFORM;
  return v === "sentinel" || v === "splunk" ? v : null;
}

// The catalogue app marks itself (index.html sets window.REACH_APP before
// loading app.js); a content script's isolated world never sees that, so
// there the page's hostname is the answer.
function fromHost() {
  try {
    if (globalThis.REACH_APP) return null;
    const host = globalThis.location ? globalThis.location.hostname : "";
    if (!host) return null;
    if (PORTAL_HOST_RE.test(host)) return "sentinel";
    const proto = globalThis.location.protocol;
    return proto === "http:" || proto === "https:" ? "splunk" : null; // chrome-extension:// pages: the popup, options
  } catch {
    return null;
  }
}

function fromQuery() {
  try {
    const q = new URLSearchParams(globalThis.location ? globalThis.location.search : "").get("platform");
    return q === "sentinel" || q === "splunk" ? q : null;
  } catch {
    return null;
  }
}

function fromStorage() {
  try {
    const v = globalThis.localStorage ? localStorage.getItem(STORAGE_KEY) : null;
    return v === "sentinel" || v === "splunk" ? v : null;
  } catch {
    return null;
  }
}

function decide() {
  const override = fromOverride();
  if (override) return override;
  const host = fromHost();
  if (host) return host;
  const query = fromQuery();
  if (query) {
    rememberPlatform(query);
    return query;
  }
  return fromStorage() || "splunk";
}

// The platform the next app page opens on: the popup writes it before
// opening the panel, the app before switching itself over on a click from
// the other platform.
export function rememberPlatform(platform) {
  try {
    localStorage.setItem(STORAGE_KEY, platform === "sentinel" ? "sentinel" : "splunk");
  } catch {
    /* private mode or no storage: remembered for this page only */
  }
}

export const PLATFORM = decide();

export function isSentinel() {
  return PLATFORM === "sentinel";
}

export function isPortalOrigin(origin) {
  try {
    return PORTAL_HOST_RE.test(new URL(String(origin || "")).hostname);
  } catch {
    return false;
  }
}

// The app URL for a platform, for whoever opens the catalogue from a page:
// the popup, and the in-page sections' "Open in Reach" links.
export function appQuery(platform = PLATFORM) {
  return `?platform=${platform === "sentinel" ? "sentinel" : "splunk"}`;
}

// The words a platform uses for the catalogue's nouns. TERMS is this
// page's set; termsFor answers for either platform (the heading registry's
// test resolves every heading under both).
const TERMS_BY_PLATFORM = Object.freeze({
  sentinel: Object.freeze({
    platform: "Microsoft Sentinel",
    host: "the Azure portal",
    sourcetype: "table",
    sourcetypes: "tables",
    Sourcetype: "Table",
    Sourcetypes: "Tables",
    field: "column",
    fields: "columns",
    Field: "Column",
    Fields: "Columns",
    index: "workspace",
    indexes: "workspaces",
    lang: "KQL",
    env: "workspace",
    envs: "workspaces",
    Env: "Workspace",
  }),
  splunk: Object.freeze({
    platform: "Splunk",
    host: "Splunk Web",
    sourcetype: "sourcetype",
    sourcetypes: "sourcetypes",
    Sourcetype: "Sourcetype",
    Sourcetypes: "Sourcetypes",
    field: "field",
    fields: "fields",
    Field: "Field",
    Fields: "Fields",
    index: "index",
    indexes: "indexes",
    lang: "SPL",
    env: "Splunk instance",
    envs: "Splunk instances",
    Env: "Splunk instance",
  }),
});

export function termsFor(platform) {
  return platform === "sentinel" ? TERMS_BY_PLATFORM.sentinel : TERMS_BY_PLATFORM.splunk;
}

export const TERMS = termsFor(PLATFORM);

export default { PLATFORM, rememberPlatform, isSentinel, isPortalOrigin, appQuery, TERMS, termsFor };
