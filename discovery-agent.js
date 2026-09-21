// Runs discovery searches on this Splunk page on behalf of the Reach app
// page. The app page cannot POST to Splunk itself: the web proxy needs the
// CSRF cookie only this page can read (and GET on jobs/export is refused).
// So the app asks the background worker, which asks the open Splunk tab,
// which runs the search through live-lookup.js with this page's own session:
// nothing new is authenticated, nothing leaves the user's own Splunk.
//
// Only messages from this extension are honoured, and every search is one
// of the fixed reporting searches discovery.js builds or a pack workflow's
// hunt as pivot.js rendered it from the pack's template; there is no
// free-form SPL surface here. Each arrives because the user clicked: one
// search per click, or a full discovery sweep's listed batch of them,
// cancellable, never one from a timer.

(function () {
  if (!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]')) return;
  if (!chrome.runtime || !chrome.runtime.onMessage) return;

  let liveReady = null;
  function live() {
    if (!liveReady) liveReady = import(chrome.runtime.getURL("live-lookup.js"));
    return liveReady;
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== "reach:run" || sender.id !== chrome.runtime.id) return false;
    (async () => {
      try {
        const lib = await live();
        const app = msg.app || "search";
        // A batch bounds each job shorter than the ten-minute default;
        // clamped so a message can neither disable the deadline nor extend it.
        const t = Number(msg.timeoutMs);
        const timeoutMs = Number.isFinite(t) && t > 0 ? Math.max(1000, Math.min(600000, t)) : undefined;
        const out = await lib.runReporting(msg.spl, { app, earliest: msg.earliest || "0", latest: msg.latest || "now", timeoutMs });
        sendResponse({ ok: true, rows: out.rows, messages: out.messages, origin: location.origin });
      } catch (err) {
        console.warn("[Reach] agent: failed", err);
        sendResponse({ ok: false, error: err && err.message ? err.message : String(err), status: err && err.status });
      }
    })();
    return true; // async sendResponse
  });

  // Read-only REST reads of declared structure (props, transforms), GET
  // only, on a fixed allowlist of paths, plus the one job read below.
  // Same session, same origin.
  const REST_ALLOW = [
    "servicesNS/-/-/data/props/extractions",
    "servicesNS/-/-/data/props/fieldaliases",
    "servicesNS/-/-/data/props/calcfields",
    "servicesNS/-/-/data/props/lookups",
    "servicesNS/-/-/data/transforms/extractions",
    "servicesNS/-/-/data/transforms/lookups",
    "servicesNS/-/-/data/indexes",
    "servicesNS/-/-/datamodel/model",
    "servicesNS/-/-/configs/conf-macros",
    "servicesNS/-/-/configs/conf-props",
  ];
  // One more GET, on a job the user already ran: its counts (scanCount,
  // eventCount, resultCount, runDuration) and the search Splunk optimised
  // it to, for the advisor's measured reading. The sid must match this
  // pattern, the URL is built here from it, and only these keys go back.
  const JOB_RE = /^servicesNS\/-\/-\/search\/v2\/jobs\/((?=[._-]*[A-Za-z0-9])[A-Za-z0-9._-]{1,200})$/;
  const JOB_KEYS = ["sid", "isDone", "dispatchState", "scanCount", "eventCount", "resultCount", "runDuration", "earliestTime", "latestTime", "search", "optimizedSearch"];
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== "reach:rest" || sender.id !== chrome.runtime.id) return false;
    (async () => {
      try {
        const path = String(msg.path || "");
        const locale = location.pathname.split("/")[1] || "en-US";
        const job = JOB_RE.exec(path);
        if (job) {
          const res = await fetch(`/${locale}/splunkd/__raw/servicesNS/-/-/search/v2/jobs/${encodeURIComponent(job[1])}?output_mode=json`, { credentials: "include", headers: { "X-Requested-With": "XMLHttpRequest" } });
          if (!res.ok) throw new Error(res.status === 404 ? `Job ${job[1]} is gone from Splunk` : `Splunk returned ${res.status} for the job`);
          const json = await res.json();
          const entries = (json.entry || []).map((e) => ({ name: e.name, app: e.acl && e.acl.app, content: Object.fromEntries(JOB_KEYS.filter((k) => k in (e.content || {})).map((k) => [k, e.content[k]])) }));
          sendResponse({ ok: true, entries });
          return;
        }
        if (!REST_ALLOW.includes(path)) throw new Error(`REST path not allowed: ${path}`);
        const qs = new URLSearchParams({ output_mode: "json", count: String(msg.count || 0), ...(msg.search ? { search: msg.search } : {}) });
        const res = await fetch(`/${locale}/splunkd/__raw/${path}?${qs}`, { credentials: "include", headers: { "X-Requested-With": "XMLHttpRequest" } });
        if (!res.ok) throw new Error(`Splunk returned ${res.status} for ${path}`);
        const json = await res.json();
        const entries = (json.entry || []).map((e) => ({ name: e.name, app: e.acl && e.acl.app, content: Object.fromEntries(Object.entries(e.content || {}).filter(([k]) => !k.startsWith("eai:"))) }));
        sendResponse({ ok: true, entries });
      } catch (err) {
        sendResponse({ ok: false, error: err && err.message ? err.message : String(err) });
      }
    })();
    return true;
  });

  // Lets the app page find out which Splunk tabs can run discovery.
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== "reach:ping" || sender.id !== chrome.runtime.id) return false;
    sendResponse({ ok: true, origin: location.origin, locale: location.pathname.split("/")[1] || "en-US" });
    return false;
  });
})();
