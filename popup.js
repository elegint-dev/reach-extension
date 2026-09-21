// Per-origin enable/disable for json-tree-fields.js. This is the only place
// that ever requests a host permission, and it only ever does so from this
// button's click, a genuine user gesture, never from a content script.
//
// CONTENT_SCRIPT_ID_PREFIX, CONTENT_SCRIPTS and SENTINEL come from
// content-config.js, loaded by popup.html just before this file. Enabling
// on the portal grants both Sentinel patterns and registers the blade
// script in every frame: same per-click, per-origin gesture.

function isSentinelOrigin(origin) {
  return /^https:\/\/(portal\.azure\.com|[a-z0-9-]+\.reactblade\.portal\.azure\.net)$/.test(origin);
}

// A store reviewer (or anyone else) with no Splunk and no Azure portal open
// used to see "Enable on this Splunk instance" leading the popup on any
// http(s) page; clicking it granted a permission that then did nothing.
// classify() decides, from what the caller already knows about the tab,
// whether this is a page Reach can actually act on. "splunk" is decided by
// looksLikeSplunk() below (the same asset-signature marker the content
// scripts gate on: value-popup.js, field-info-popup.js, json-tree-fields.js,
// search-history.js, discovery-agent.js), run via a one-shot
// chrome.scripting.executeScript under the popup's own activeTab grant, so
// no new host permission is requested just to look.
function classify({ sentinel, splunk }) {
  if (sentinel) return "sentinel";
  if (splunk) return "splunk";
  return "unknown";
}

async function looksLikeSplunk(tabId) {
  if (!Number.isInteger(tabId) || !chrome.scripting || !chrome.scripting.executeScript) return false;
  try {
    const [{ result } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => !!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]'),
    });
    return !!result;
  } catch {
    // No access to the page (a chrome:// page, another extension's page, a
    // page that refused injection): treat it as not Splunk, same as a plain
    // page that really isn't.
    return false;
  }
}

const toggle = document.getElementById("toggle");
const status = document.getElementById("status");
const originLabel = document.getElementById("origin");
const appLink = document.getElementById("appLink");
const enableBlock = document.getElementById("enableBlock");
const enableHint = document.getElementById("enableHint");

// The grant this button asks for, spelled out for a reviewer or a first
// user with no other context: a recognized page, not yet enabled. Once
// enabled the "Reload the page" status line covers it instead.
const ENABLE_HINT = "Reach adds a section to the value menu on this site; nothing runs until you click a value.";

// recognized: a page Reach can actually enable on (real Splunk, or the Azure
// portal). There it leads as before. Anywhere else, "Open the catalogue"
// leads instead (it works with the bundled packs, no SIEM needed) and the
// enable button becomes a small secondary line.
function updateLayout(recognized) {
  appLink.classList.toggle("r-primary-action", !recognized);
  appLink.textContent = recognized ? "Open the catalogue in a tab →" : "Open the catalogue →";
  enableBlock.classList.toggle("r-secondary", !recognized);
}

function originPatternFor(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

async function getTrustedOrigins() {
  const { KEYS } = await import(chrome.runtime.getURL("app/lib/storage-keys.js"));
  const { [KEYS.trustedOrigins]: trustedOrigins = [] } = await chrome.storage.local.get(KEYS.trustedOrigins);
  return trustedOrigins;
}

async function setTrustedOrigins(origins) {
  const { KEYS } = await import(chrome.runtime.getURL("app/lib/storage-keys.js"));
  await chrome.storage.local.set({ [KEYS.trustedOrigins]: origins });
}

// The tab this popup opened on, read once at open: the side-panel link
// needs its window synchronously, inside the click.
let currentTab = null;

// True while a toggle is in flight. render() consults it so the button
// stays disabled across the awaits inside onToggle; without this a second
// click could interleave with the first (permission granted, scripts not
// yet registered) and leave the two out of step.
let busy = false;

async function render() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab || null;
  const pattern = tab && tab.url ? originPatternFor(tab.url) : null;

  if (!pattern) {
    originLabel.textContent = "this site";
    toggle.textContent = "Not available here";
    toggle.disabled = true;
    status.textContent = "Open the Azure portal's Logs blade (or a Splunk Web page), then reopen this popup.";
    enableHint.hidden = true;
    updateLayout(false);
    return null;
  }

  let origin = pattern.slice(0, -2); // drop the trailing "/*"
  const sentinel = isSentinelOrigin(origin);
  const splunk = sentinel ? false : await looksLikeSplunk(tab && tab.id);
  const kind = classify({ sentinel, splunk });
  if (sentinel) origin = SENTINEL.origin;
  originLabel.textContent = sentinel ? "the Azure portal (Logs blade)" : origin;

  const enabled = await chrome.permissions.contains({ origins: sentinel ? SENTINEL.patterns : [pattern] });
  toggle.disabled = busy;
  toggle.classList.toggle("enabled", enabled);
  toggle.textContent = enabled
    ? "Enabled: click to disable"
    : sentinel
      ? "Enable in the Azure portal"
      : splunk
        ? "Enable on this Splunk instance"
        : "Enable Reach on this site if it is a Splunk instance";
  status.textContent = enabled
    ? "Reload the page for this to take effect if you just enabled it."
    : kind === "unknown"
      ? "This doesn't look like a Splunk Web page; enabling here won't do anything unless it is one."
      : "";
  // A recognized page (real Splunk, or the Azure portal) not yet enabled:
  // the reviewer path and a real first user both need to know the button
  // grants a host permission and that nothing runs from it on its own.
  enableHint.hidden = !(kind !== "unknown" && !enabled);
  if (!enableHint.hidden) enableHint.textContent = ENABLE_HINT;
  // Already enabled (however that happened) stays primary: a small line is
  // the wrong shape for a button that also needs to offer turning it off.
  updateLayout(kind !== "unknown" || enabled);

  return { pattern, origin, enabled, sentinel };
}

// Register-or-update, whichever the id needs. The worker registers the same
// ids the moment the grant lands (background.js registerForGrant), so a
// check-then-register here can lose the race and see "Duplicate script
// ID"; that means the entry exists, and an update finishes the job.
async function upsertScripts(entries) {
  for (const entry of entries) {
    try {
      await chrome.scripting.registerContentScripts([entry]);
    } catch {
      await chrome.scripting.updateContentScripts([entry]);
    }
  }
}

async function onToggle() {
  if (busy) return;
  busy = true;
  toggle.disabled = true;
  let state = null;
  try {
    state = await render();
    if (!state) return;
    const { pattern, origin, enabled, sentinel } = state;
    const id = CONTENT_SCRIPT_ID_PREFIX + origin;
    const patterns = sentinel ? SENTINEL.patterns : [pattern];

    if (enabled) {
      await chrome.scripting.unregisterContentScripts({ ids: sentinel ? SENTINEL.entries.map((e) => e.id) : [id] }).catch(() => {});
      await chrome.permissions.remove({ origins: patterns }).catch(() => {});
      const origins = await getTrustedOrigins();
      await setTrustedOrigins(origins.filter((o) => o !== origin));
      status.textContent = "Disabled. Reload the page to remove it there.";
    } else {
      const granted = await chrome.permissions.request({ origins: patterns });
      if (!granted) {
        status.textContent = "Permission was not granted.";
        return;
      }
      try {
        await upsertScripts(sentinel ? SENTINEL.entries : [{ id, matches: [pattern], js: CONTENT_SCRIPTS, runAt: "document_idle" }]);
        const origins = await getTrustedOrigins();
        if (!origins.includes(origin)) await setTrustedOrigins([...origins, origin]);
        status.textContent = "Enabled. Reload the page for it to take effect.";
      } catch (err) {
        status.textContent = "Registration failed: " + (err && err.message ? err.message : String(err));
        return;
      }
    }
  } finally {
    busy = false;
    toggle.disabled = !state; // "Not available here" stays disabled
  }
  await render();
}

toggle.addEventListener("click", onToggle);

// The catalogue app is told which platform to be, from the tab this popup
// was opened on (see app/lib/platform.js).
async function platformHere() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const pattern = tab && tab.url ? originPatternFor(tab.url) : null;
  return { tab, platform: pattern && isSentinelOrigin(pattern.slice(0, -2)) ? "sentinel" : "splunk" };
}

appLink.addEventListener("click", async (e) => {
  e.preventDefault();
  const { platform } = await platformHere();
  chrome.tabs.create({ url: chrome.runtime.getURL(`index.html?platform=${platform}`) });
});

// The side panel is the same app, one per window, beside whatever tab is
// active. Its page cannot carry a query string, so the platform goes in
// through the memory platform.js reads next (rememberPlatform): this popup
// and the panel are the same extension origin, so one localStorage. Chrome
// opens a panel only inside a user gesture, so sidePanel.open() is called
// synchronously in the click, off the tab read when the popup opened;
// nothing awaited first. platform.js is loaded when the popup opens so the
// click has it in hand.
let platformLib = null;
import(chrome.runtime.getURL("app/lib/platform.js")).then((m) => {
  platformLib = m;
}).catch(() => {});
document.getElementById("panelLink").addEventListener("click", (e) => {
  e.preventDefault();
  if (!currentTab || !Number.isInteger(currentTab.windowId)) {
    status.textContent = "No window to open the panel in; reopen this popup on a page.";
    return;
  }
  const pattern = currentTab.url ? originPatternFor(currentTab.url) : null;
  const platform = pattern && isSentinelOrigin(pattern.slice(0, -2)) ? "sentinel" : "splunk";
  if (platformLib) platformLib.rememberPlatform(platform);
  chrome.sidePanel
    .open({ windowId: currentTab.windowId })
    .then(() => window.close())
    .catch((err) => {
      status.textContent = "Could not open the side panel: " + (err && err.message ? err.message : String(err));
    });
});
// options.html draws one platform's module list, scoped by ?platform=:
// the tab this popup is on names it, the way the catalogue link does.
document.getElementById("settingsLink").addEventListener("click", async (e) => {
  e.preventDefault();
  const { platform } = await platformHere();
  chrome.tabs.create({ url: chrome.runtime.getURL(`options.html?platform=${platform}`) });
});
render();
