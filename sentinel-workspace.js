// Top-frame content script for portal.azure.com. The Logs blade itself is a
// cross-origin iframe (sandbox-N.reactblade.portal.azure.net, see
// docs/SENTINEL.md §5.6) and its URL does not say which workspace it is on;
// the top frame's hash does (the Logs deep link's …/resourceId/<ARM id>/…,
// Sentinel's menu blade's …/id/<ARM id>, or the workspace menu's raw
// …/resource/<ARM id>/logs; kql.resourceIdFromHash reads them all). This script
// reads that, remembers the workspace for the app's recipe view and hands it
// to sentinel-grid.js in the blade frame, which needs the resource id to
// build a deep link for a pivot.
//
// Two channels, both one-way from here:
//   chrome.storage.local   sentinel.workspaces (seen list, via recipe.js) and
//                          sentinel.currentWorkspace ({ resourceId, name, at })
//   window.postMessage     nothing: the blade frame reads storage
//
// And one channel the other way: the blade frame asks for a query to be
// opened as a tab of the Logs screen (below). Nothing else is accepted.
//
// Reads the URL and the storage API. Never fetches.

(function () {
  if (window.top !== window) return; // the blade frame has its own script
  if (!/(^|\.)portal\.azure\.com$/.test(location.hostname)) return;

  // A cheap "is Reach running here" signal for a developer's console; the
  // version, so a stale load is obvious. Data on the DOM, nothing more.
  try {
    document.documentElement.dataset.reachSentinel = chrome.runtime.getManifest().version;
  } catch {
    /* no manifest access, fine */
  }
  let modules = null;
  function lib() {
    if (!modules) {
      modules = Promise.all([import(chrome.runtime.getURL("app/lib/kql.js")), import(chrome.runtime.getURL("app/lib/recipe.js")), import(chrome.runtime.getURL("app/lib/storage-keys.js"))]).then(([kql, recipe, keys]) => ({ kql, recipe, KEYS: keys.KEYS }));
    }
    return modules;
  }

  let last = null;
  async function noteWorkspace() {
    const { kql, recipe, KEYS } = await lib();
    const rid = kql.resourceIdFromHash(location.hash);
    if (!rid || rid === last) return;
    last = rid;
    const name = kql.workspaceNameOf(rid);
    try {
      await recipe.rememberWorkspace(rid, { name });
      await chrome.storage.local.set({ [KEYS.sentinelWorkspace]: { resourceId: rid, name, at: new Date().toISOString() } });
    } catch (err) {
      console.warn("[Reach] could not remember the workspace:", err);
    }
  }

  window.addEventListener("hashchange", () => noteWorkspace().catch(() => {}));
  noteWorkspace().catch(() => {});
  // The portal also moves between blades with pushState, which fires no
  // hashchange; a cheap poll catches those.
  let seenHref = location.href;
  setInterval(() => {
    if (location.href === seenHref) return;
    seenHref = location.href;
    noteWorkspace().catch(() => {});
  }, 1500);

  function fromBlade(e) {
    try {
      return /\.reactblade\.portal\.azure\.net$/.test(new URL(e.origin).hostname);
    } catch {
      return false;
    }
  }

  // "Open as query tab": the blade frame cannot navigate the portal (a
  // cross-origin, sandboxed frame), so it asks. Only a Logs-blade deep link
  // on this portal is ever followed (the same URL shape Reach itself
  // builds via kql.deepLink) and only from the blade's origin. Navigating
  // the hash makes the portal open the query as a new tab of the Logs
  // screen, already run.
  const DEEP_LINK_RE = /^https:\/\/portal\.azure\.com\/#view\/Microsoft_Azure_Monitoring_Logs\/LogsBlade\/resourceId\/[^/]+\/source\/LogsBlade\.AnalyticsShareLinkToQuery\/q\/[^/]+\/timespan\/[A-Za-z0-9%]+$/;
  window.addEventListener("message", (e) => {
    const msg = e.data;
    if (!msg || msg.type !== "reach:open" || !fromBlade(e)) return;
    const url = String(msg.url || "");
    if (!DEEP_LINK_RE.test(url)) return;
    location.assign(url);
  });

})();
