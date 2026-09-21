// The extension's service worker, a module (manifest.json background.type).
// Re-registers Reach's content scripts on every already-approved Splunk
// origin at startup, and keeps the registered file list in sync with
// CONTENT_SCRIPTS (content-config.js; e.g. after adding value-popup.js
// there, a reload updates every already-approved origin without the user
// re-clicking enable). The permission grant itself happens in popup.js,
// from a user gesture, per origin; never here, and never broadly.
//
// The enrichment relay: each fetch-mode source (app/lib/enrich/<source>.js)
// exports one descriptor, `relay`, and lookup() below is the one function
// that reads its keys from chrome.storage.local, checks the host
// permission, re-checks the kind and id, fetches and shapes the answer.
// A descriptor names: id, messages { status, lookup } and bySource when
// the pair is shared, keys, config(got), hosts(cfg), configured(cfg),
// status(cfg, permitted), accepts(kind, id), method, url(kind, id, cfg),
// headers(cfg), answer({ ok, status, body }, cfg), failure(cfg, why),
// errors { unconfigured, unpermitted, refused }, and optionally
// cacheTtlMs with cacheable(res). A descriptor that also writes names
// messages.write, writable(cfg), errors { writesOff, writeRefused } and
// writes { <op>: { method, accepts(msg, cfg), url(msg, cfg), body(msg, cfg),
// answer } }, run by write() below behind every check a lookup passes.

import "./content-config.js";
import * as modules from "./app/lib/modules.js";
import { KEYS } from "./app/lib/storage-keys.js";
import { relay as virustotalRelay } from "./app/lib/enrich/virustotal.js";
import { relay as circlRelay } from "./app/lib/enrich/circl.js";
import { relay as epssRelay } from "./app/lib/enrich/epss.js";
import { relay as selfhostedRelay } from "./app/lib/enrich/selfhosted.js";

const { CONTENT_SCRIPT_ID_PREFIX, CONTENT_SCRIPTS, SENTINEL } = globalThis.REACH_CONTENT_CONFIG;

const RELAYS = [virustotalRelay, circlRelay, epssRelay, selfhostedRelay];

async function restoreTrustedOrigins() {
  await migrateOffCortex();
  const { [KEYS.trustedOrigins]: trustedOrigins = [] } = await chrome.storage.local.get(KEYS.trustedOrigins);
  if (!trustedOrigins.length) return;

  // Only re-register what the runtime permission system still actually grants.
  // The user may have revoked a site's permission from chrome://extensions
  // directly since it was approved, and storage.local wouldn't know.
  const stillGranted = [];
  for (const origin of trustedOrigins) {
    const patterns = origin === SENTINEL.origin ? SENTINEL.patterns : [`${origin}/*`];
    const has = await chrome.permissions.contains({ origins: patterns }).catch(() => false);
    if (has) stillGranted.push(origin);
  }
  if (stillGranted.length !== trustedOrigins.length) {
    await chrome.storage.local.set({ [KEYS.trustedOrigins]: stillGranted });
  }

  const existing = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const existingIds = new Set(existing.map((s) => s.id));

  for (const origin of stillGranted) {
    if (origin === SENTINEL.origin) {
      for (const entry of SENTINEL.entries) {
        const call = existingIds.has(entry.id) ? chrome.scripting.updateContentScripts([entry]) : chrome.scripting.registerContentScripts([entry]);
        await call.catch(() => {});
      }
      continue;
    }
    const id = CONTENT_SCRIPT_ID_PREFIX + origin;
    const entry = { id, matches: [`${origin}/*`], js: CONTENT_SCRIPTS, runAt: "document_idle" };
    const call = existingIds.has(id)
      ? chrome.scripting.updateContentScripts([entry])
      : chrome.scripting.registerContentScripts([entry]);
    await call.catch(() => {}); // origin no longer valid as a match pattern; skip it, don't crash startup
  }
}

chrome.runtime.onStartup.addListener(restoreTrustedOrigins);
chrome.runtime.onInstalled.addListener(restoreTrustedOrigins);

// The popup asks for the permission, but Chrome's native prompt closes the
// popup, and its script can die before it registers the content scripts:
// the permission lands, the registration does not, and the popup then
// reads "Enabled" off the permission alone. So registration follows the
// grant here, in the worker, whatever happened to the popup. Only origins
// Reach draws into are registered: the portal pair, or a Splunk origin
// pattern; the VirusTotal host permission is a fetch target, not a page.
async function registerForGrant(origins) {
  const trusted = new Set((await chrome.storage.local.get(KEYS.trustedOrigins))[KEYS.trustedOrigins] || []);
  let changed = false;
  const existing = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const existingIds = new Set(existing.map((s) => s.id));
  const upsert = (entry) => (existingIds.has(entry.id) ? chrome.scripting.updateContentScripts([entry]) : chrome.scripting.registerContentScripts([entry])).catch(() => {});
  // Every fetch-target host permission (VirusTotal, CIRCL, EPSS, and the
  // self-hosted enrichment origin the user typed in Settings) is a
  // recipient for a fetch, not a page: registering CONTENT_SCRIPTS there
  // and listing it in trustedOrigins would put it in Splunk discovery.
  // Read from each relay descriptor's hosts, so a source added later never
  // needs a matching line here.
  const fetchTargetPatterns = await fetchTargetHosts();
  if (origins.some((o) => SENTINEL.patterns.includes(o))) {
    const has = await chrome.permissions.contains({ origins: SENTINEL.patterns }).catch(() => false);
    if (has) {
      for (const entry of SENTINEL.entries) await upsert(entry);
      if (!trusted.has(SENTINEL.origin)) { trusted.add(SENTINEL.origin); changed = true; }
    }
  }
  for (const pattern of origins) {
    if (SENTINEL.patterns.includes(pattern) || !/^https?:\/\/[^*/]+\/\*$/.test(pattern)) continue; // a wildcard host or a non-page grant
    if (fetchTargetPatterns.has(pattern)) continue;
    const origin = pattern.slice(0, -2);
    await upsert({ id: CONTENT_SCRIPT_ID_PREFIX + origin, matches: [pattern], js: CONTENT_SCRIPTS, runAt: "document_idle" });
    if (!trusted.has(origin)) { trusted.add(origin); changed = true; }
  }
  if (changed) await chrome.storage.local.set({ [KEYS.trustedOrigins]: Array.from(trusted) });
}

chrome.permissions.onAdded.addListener((perm) => {
  if (perm && perm.origins && perm.origins.length) registerForGrant(perm.origins);
});

// Relay for the app page: "run this reporting search on a Splunk tab for
// <origin>". The tab does the work (discovery-agent.js); this only finds it.
// Host permission for the origin is what makes the url filter work, and it
// is only ever granted per origin from popup.js.
async function tabsFor(origin) {
  const tabs = await chrome.tabs.query({ url: `${origin}/*` }).catch(() => []);
  return tabs.filter((t) => t.id != null);
}

// Enabled Splunk origins: the stored list, plus whatever content scripts
// are actually registered (they persist across reloads; the list is the
// weaker record of the two). What reach:discover:tabs lists and what a
// run may name are this one set.
async function enabledOrigins() {
  const { [KEYS.trustedOrigins]: trustedOrigins = [] } = await chrome.storage.local.get(KEYS.trustedOrigins);
  const registered = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const origins = new Set(trustedOrigins);
  for (const s of registered) if (s.id.startsWith(CONTENT_SCRIPT_ID_PREFIX)) origins.add(s.id.slice(CONTENT_SCRIPT_ID_PREFIX.length));
  return { origins, registered: registered.length };
}

// Discovery runs only from Reach's own page as a top-level document: the
// side panel (no sender.tab) or the catalogue tab (frameId 0). index.html
// is web-accessible, so any site can frame it; a framed copy arrives with
// the host page's tab and a frameId above 0, and is refused here whatever
// the page itself does.
function fromTopLevelExtensionPage(sender) {
  return !sender.tab || sender.frameId === 0;
}
const NOT_OWN_PAGE = "Discovery only runs from Reach's own page.";

// --- the side panel ----------------------------------------------------------
// One panel per window (index.html, the manifest's side_panel). The panel
// page connects a port named "reach-panel" and says which window it is in.
// A click in a page sends reach:selection (from a content script, so it
// arrives with its tab); the selection goes to that window's panel when
// there is one, and the reply says whether one took it. That reply is the
// whole mode switch: panel open, the page shows one line and the panel
// shows the field; panel closed, the page's own popup, as ever. The last
// selection per window is kept so a panel opened after the click shows it.
const PANEL_PORT = "reach-panel";
const panels = new Map(); // windowId → Port
const lastSelection = new Map(); // windowId → selection

// Only these fields, only as short strings: the panel navigates on them,
// and reads the row's sibling fields for the verdict.
function cleanSelection(sel) {
  const str = (v, n = 512) => (typeof v === "string" ? v.slice(0, n) : "");
  if (!sel || typeof sel !== "object") return null;
  const out = {
    platform: sel.platform === "sentinel" ? "sentinel" : "splunk",
    kind: sel.kind === "value" ? "value" : "field",
    name: str(sel.name),
    value: str(sel.value, 4096),
    sourcetype: str(sel.sourcetype),
    index: str(sel.index),
    discriminator: null,
  };
  if (sel.discriminator && typeof sel.discriminator === "object") {
    const d = { field: str(sel.discriminator.field), value: str(sel.discriminator.value) };
    if (d.field && d.value) out.discriminator = d;
  }
  // The clicked row's sibling fields (popup-ui.js verdictFields): a few
  // named columns as short strings, for the panel's known-good verdict.
  out.event = {};
  if (sel.event && typeof sel.event === "object" && !Array.isArray(sel.event)) {
    for (const [k, v] of Object.entries(sel.event).slice(0, 32)) {
      if (/^[A-Za-z][A-Za-z0-9_.]{0,63}$/.test(k) && typeof v === "string" && v) out.event[k] = v.slice(0, 512);
    }
  }
  // Where the click was, for the notebook's pin (popup-ui.js pinFrom): the
  // event's id, time and one-line summary, the search text and job id,
  // the scope (index or workspace). Strings only, key by key.
  const p = sel.provenance;
  if (p && typeof p === "object" && !Array.isArray(p)) {
    const ev = p.event && typeof p.event === "object" ? { id: str(p.event.id), time: str(p.event.time, 64), summary: str(p.event.summary, 2000) } : {};
    const search = p.search && typeof p.search === "object" ? { text: str(p.search.text, 4000), sid: str(p.search.sid, 200) } : {};
    out.provenance = { event: ev, search, scope: str(p.scope) };
  }
  return out.name ? out : null;
}

function panelConnected(port) {
  if (!port || port.name !== PANEL_PORT || !port.sender || port.sender.id !== chrome.runtime.id) return;
  let windowId = null;
  port.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "reach:panel:hello" || !Number.isInteger(msg.windowId)) return;
    windowId = msg.windowId;
    panels.set(windowId, port);
    // A fresh panel lands on the window's last click; a reloaded one keeps
    // its route (app.js showSelection reads the replay flag).
    const last = lastSelection.get(windowId);
    if (last) port.postMessage({ type: "reach:selection", selection: last, replay: true });
  });
  port.onDisconnect.addListener(() => {
    if (windowId !== null && panels.get(windowId) === port) panels.delete(windowId);
  });
}

function relay(msg, sender, sendResponse) {
  if (!msg || sender.id !== chrome.runtime.id) return false;
  const guard = (fn) => fn().catch((err) => sendResponse({ ok: false, error: `Background relay failed: ${err && err.message ? err.message : String(err)}` }));
  if (msg.type === "reach:selection") {
    const tab = sender.tab;
    const selection = cleanSelection(msg.selection);
    if (!tab || !Number.isInteger(tab.windowId) || !selection) {
      sendResponse({ ok: false, panel: false });
      return false;
    }
    const full = { ...selection, tabId: tab.id, windowId: tab.windowId, at: Date.now() };
    lastSelection.set(tab.windowId, full);
    const port = panels.get(tab.windowId);
    if (port) {
      try {
        port.postMessage({ type: "reach:selection", selection: full });
      } catch {
        panels.delete(tab.windowId); // gone without a disconnect event
      }
    }
    sendResponse({ ok: true, panel: panels.has(tab.windowId) });
    return false;
  }
  if (msg.type === "reach:discover:tabs") {
    if (!fromTopLevelExtensionPage(sender)) {
      sendResponse({ ok: false, error: NOT_OWN_PAGE });
      return false;
    }
    guard(async () => {
      try {
        const { origins, registered } = await enabledOrigins();
        const out = [];
        for (const origin of origins) {
          const tabs = await tabsFor(origin);
          out.push({ origin, tabs: tabs.length, title: tabs[0] ? tabs[0].title : null });
        }
        sendResponse({ ok: true, origins: out, registered });
      } catch (err) {
        sendResponse({ ok: false, error: `Could not list enabled instances: ${err && err.message ? err.message : String(err)}` });
      }
    });
    return true;
  }
  if (msg.type === "reach:discover:run" || msg.type === "reach:discover:rest") {
    if (!fromTopLevelExtensionPage(sender)) {
      sendResponse({ ok: false, error: NOT_OWN_PAGE });
      return false;
    }
    guard(async () => {
      const { origins } = await enabledOrigins();
      if (typeof msg.origin !== "string" || !origins.has(msg.origin)) {
        sendResponse({ ok: false, error: `${msg.origin} is not an enabled Splunk instance.` });
        return;
      }
      const tabs = await tabsFor(msg.origin);
      if (!tabs.length) {
        sendResponse({ ok: false, error: `No open Splunk tab on ${msg.origin}. Open one (and keep it open) so the request can run with your session.` });
        return;
      }
      const forward =
        msg.type === "reach:discover:run"
          ? { type: "reach:run", spl: msg.spl, earliest: msg.earliest, latest: msg.latest, app: msg.app, timeoutMs: msg.timeoutMs }
          : { type: "reach:rest", path: msg.path, search: msg.search, count: msg.count };
      // A tab still loading has no agent yet; try each until one answers,
      // and say what each one said if none does.
      const failures = [];
      for (const tab of tabs) {
        try {
          const res = await chrome.tabs.sendMessage(tab.id, forward);
          if (res) {
            sendResponse(res);
            return;
          }
          failures.push(`tab ${tab.id}: no response`);
        } catch (err) {
          failures.push(`tab ${tab.id}: ${err && err.message ? err.message : String(err)}`);
        }
      }
      sendResponse({ ok: false, error: `No Reach agent answered on ${msg.origin} (${failures.join("; ")}). Reload that Splunk tab once, then try again.` });
    });
    return true;
  }
  if (isRelayMessage(msg)) {
    const desc = relayFor(msg);
    if (!desc) {
      sendResponse({ ok: false, status: 0, error: "Reach does not know this enrichment source." });
      return false;
    }
    guard(async () => sendResponse(await (msg.type === desc.messages.write ? write(desc, msg) : lookup(desc, msg))));
    return true;
  }
  return false;
}

// --- the enrichment relay ---------------------------------------------------
// Every module, key, permission and shape check happens here, fresh per
// message, never trusted from the caller: a content script sends
// { kind, id } and gets the report back, never a key or token. What is
// sent is exactly the clicked value, already screened by the source's
// classify(), and only after the user clicked the value and then the
// source's button. The module set (app/lib/modules.js, reach.modules) is
// read once and followed through storage changes, so a module switched
// off in Settings is refused here on the next message.

function isRelayMessage(msg) {
  return RELAYS.some((d) => Object.values(d.messages).includes(msg.type));
}

function relayFor(msg) {
  return RELAYS.find((d) => Object.values(d.messages).includes(msg.type) && (!d.bySource || msg.source === d.id)) || null;
}

async function readConfig(desc) {
  return desc.config(await chrome.storage.local.get(desc.keys));
}

// Every host a relay fetches from right now: the fixed ones and the
// self-hosted origin as typed.
async function fetchTargetHosts() {
  const out = new Set();
  for (const desc of RELAYS) for (const host of desc.hosts(await readConfig(desc))) out.add(host);
  return out;
}

const caches = new Map(); // relay id → Map("kind:id" → { at, res }); dies with the worker

async function lookup(desc, msg) {
  const cfg = await readConfig(desc);
  const hosts = desc.hosts(cfg);
  const permitted = hosts.length ? await chrome.permissions.contains({ origins: hosts }).catch(() => false) : false;
  if (msg.type === desc.messages.status) return desc.status(cfg, permitted);
  await modules.hydrate();
  const owner = modules.sourceOwner(desc.id);
  if (!owner || !modules.on(owner.id, null)) return { ok: false, status: 0, reason: "module off", error: `${owner ? owner.label : desc.id} is off: turn it on in Reach's settings.` };
  if (!desc.configured(cfg)) return { ok: false, status: 0, error: desc.errors.unconfigured };
  if (!permitted) return { ok: false, status: 0, error: desc.errors.unpermitted };
  const id = typeof msg.id === "string" ? msg.id : "";
  if (!desc.accepts(msg.kind, id)) return { ok: false, status: 0, error: desc.errors.refused };

  const cacheKey = `${msg.kind}:${id}`;
  let cache = null;
  if (desc.cacheTtlMs) {
    if (!caches.has(desc.id)) caches.set(desc.id, new Map());
    cache = caches.get(desc.id);
    const hit = cache.get(cacheKey);
    if (hit && Date.now() - hit.at < desc.cacheTtlMs) return { ...hit.res, cached: true };
  }

  let res;
  try {
    const r = await fetch(desc.url(msg.kind, id, cfg), { method: desc.method, headers: desc.headers(cfg), credentials: "omit", cache: "no-store" });
    let body = null;
    try {
      body = await r.json();
    } catch {
      body = null;
    }
    res = desc.answer({ ok: r.ok, status: r.status, body }, cfg);
  } catch (err) {
    res = desc.failure(cfg, err && err.message ? err.message : String(err));
  }
  if (cache && desc.cacheable(res)) cache.set(cacheKey, { at: Date.now(), res });
  return res;
}

// A write to the source (a MISP sighting or proposed attribute): the same
// gate order as a lookup, then the descriptor's own writes toggle, then the
// named operation's shape check; never cached, one request per message.
async function write(desc, msg) {
  const cfg = await readConfig(desc);
  const hosts = desc.hosts(cfg);
  const permitted = hosts.length ? await chrome.permissions.contains({ origins: hosts }).catch(() => false) : false;
  await modules.hydrate();
  const owner = modules.sourceOwner(desc.id);
  if (!owner || !modules.on(owner.id, null)) return { ok: false, status: 0, reason: "module off", error: `${owner ? owner.label : desc.id} is off: turn it on in Reach's settings.` };
  if (!desc.configured(cfg)) return { ok: false, status: 0, error: desc.errors.unconfigured };
  if (!permitted) return { ok: false, status: 0, error: desc.errors.unpermitted };
  if (!desc.writes || typeof desc.writable !== "function" || !desc.writable(cfg)) return { ok: false, status: 0, reason: "writes off", error: desc.errors.writesOff };
  const op = typeof msg.op === "string" && Object.prototype.hasOwnProperty.call(desc.writes, msg.op) ? desc.writes[msg.op] : null;
  if (!op || !op.accepts(msg, cfg)) return { ok: false, status: 0, error: desc.errors.writeRefused };
  try {
    const body = op.body(msg, cfg);
    const headers = body === null || body === undefined ? desc.headers(cfg) : { ...desc.headers(cfg), "content-type": "application/json" };
    const init = { method: op.method, headers, credentials: "omit", cache: "no-store" };
    if (body !== null && body !== undefined) init.body = JSON.stringify(body);
    const r = await fetch(op.url(msg, cfg), init);
    let json = null;
    try {
      json = await r.json();
    } catch {
      json = null;
    }
    return op.answer({ ok: r.ok, status: r.status, body: json }, cfg, msg);
  } catch (err) {
    return desc.failure(cfg, err && err.message ? err.message : String(err));
  }
}

// Cortex left the provider list (app/lib/enrich/selfhosted.js's PROVIDERS):
// a stored provider of "cortex" would otherwise fall back to "misp" and
// start sending a Cortex token to ${origin}/attributes/restSearch. Runs
// from restoreTrustedOrigins() at startup.
async function migrateOffCortex() {
  const got = await chrome.storage.local.get(selfhostedRelay.keys);
  if (got[KEYS.selfhostedProvider] !== "cortex") return;
  const hosts = selfhostedRelay.hosts(selfhostedRelay.config(got));
  if (hosts.length) await chrome.permissions.remove({ origins: hosts }).catch(() => {});
  await chrome.storage.local.remove(selfhostedRelay.keys);
}

chrome.runtime.onMessage.addListener(relay);
chrome.runtime.onConnect.addListener(panelConnected);
// No onMessageExternal listener: relay()'s only authz check is
// sender.id !== chrome.runtime.id, and Chrome lets any other installed
// extension message this one by default (unlike web-page senders, that is
// NOT gated by an absent externally_connectable.matches). A listener here
// that forged the sender to pass that check let any extension run arbitrary
// SPL against this user's Splunk. The dev workflow this served (driving
// discovery from the served app on :8765) is gone with it; see README.
