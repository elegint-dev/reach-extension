// Click-only live search dispatch against the user's own Splunk instance.
// Every function here runs because the user clicked: a popup's approval
// click (event.isTrusted checked by the caller) dispatches that one search;
// the app's Discover page dispatches one fixed discovery search per click,
// or, from its Full discovery button, a bounded batch of the same fixed
// searches, enumerated before it starts and cancellable while it runs. This
// module has no automatic or background trigger of its own, and never will.
//
// All requests target this page's own origin (relative paths only, never a
// literal or Reach-controlled hostname), riding the browser's existing
// Splunk Web session: no new auth, no data leaves the browser except to
// the user's own Splunk instance.

import { localePrefix } from "./app/lib/runtime.js";

export class LiveLookupError extends Error {
  constructor(status, body) {
    const reason =
      status === 401 ? "Your Splunk session needs a refresh."
      : status === 403 ? "Splunk rejected the request (CSRF mismatch or no search permission)."
      : status === 0 ? "Could not reach Splunk (network error)."
      : `Splunk returned ${status}.`;
    super(reason);
    this.name = "LiveLookupError";
    this.status = status;
    this.body = body;
  }
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

// Read fresh on every call. Never cache. The token can rotate mid-session.
// Matched by pattern, not by location.port: Splunk Web names this cookie
// after the port it thinks it's listening on internally, which differs from
// the browser-visible port behind any reverse proxy or port mapping (e.g. a
// Docker container exposing 8000 internally on host port 8001). Guessing
// the suffix from location.port silently produces the wrong cookie name and
// every dispatch fails CSRF validation.
function csrfToken() {
  const exact = getCookie("splunkweb_csrf_token") || getCookie(`splunkweb_csrf_token_${location.port}`);
  if (exact) return exact;
  const m = document.cookie.match(/(?:^|; )splunkweb_csrf_token_\d+=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : "";
}

function jobsBase(app) {
  return `/${localePrefix()}/splunkd/__raw/servicesNS/-/${encodeURIComponent(app)}/search/v2/jobs`;
}

async function authedFetch(url, opts = {}) {
  // opts spreads AFTER the merged headers default, or opts.headers (e.g.
  // dispatch()'s X-Splunk-Form-Key) clobbers the whole headers object and
  // silently drops X-Requested-With, which Splunk's CSRF check requires to
  // treat the call as a genuine AJAX request. Every prior 401 in this file's
  // testing was this, not a bad token.
  const { headers: optHeaders, ...restOpts } = opts;
  const res = await fetch(url, {
    credentials: "include",
    ...restOpts,
    headers: { "X-Requested-With": "XMLHttpRequest", ...(optHeaders || {}) },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new LiveLookupError(res.status, body);
  }
  return res;
}

// Dispatch exactly the SPL string the user approved. The caller must
// capture it at render time and pass it verbatim, never re-read from the
// DOM at click time (a page could rewrite the DOM between render and click).
export async function dispatch(spl, { app = "search" } = {}) {
  const body = new URLSearchParams({ output_mode: "json", search: spl });
  const token = csrfToken();
  const res = await authedFetch(jobsBase(app), {
    method: "POST",
    headers: { "X-Splunk-Form-Key": token },
    body,
  });
  const json = await res.json();
  return json.sid;
}

// Polls until the job is done, calling onPreview(rows, isFinal) with
// whatever partial rows results_preview has while it's still running: the
// literal mechanism for streaming into a tooltip instead of blocking on a
// spinner. isCancelled() is checked before every poll tick so a closed
// popup or a cancelled job stops the loop promptly.
//
// The loop has two other exits, both thrown so every caller's existing
// catch shows them: a job Splunk marks failed (a bad search, a quota
// refusal), and a job still not done after timeoutMs (queued behind a full
// search head, or a search that just runs on). Without them a stuck job
// was polled forever and the caller's spinner never cleared.
export async function pollUntilDone(sid, { app = "search", onPreview, isCancelled, intervalMs = 700, timeoutMs = 120000 } = {}) {
  const base = `${jobsBase(app)}/${encodeURIComponent(sid)}`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (isCancelled && isCancelled()) return { cancelled: true };
    const statusRes = await authedFetch(`${base}?output_mode=json`);
    const statusJson = await statusRes.json();
    const content = statusJson.entry && statusJson.entry[0] && statusJson.entry[0].content;
    if (content && (content.isFailed || content.dispatchState === "FAILED")) {
      const why = (content.messages || []).filter((m) => m && (m.type === "FATAL" || m.type === "ERROR")).map((m) => m.text).join("; ");
      throw new Error(why ? `Splunk job failed: ${why}` : `Splunk job ${sid} failed`);
    }
    const isDone = Boolean(content && content.isDone);
    if (!isDone && onPreview) {
      const previewRes = await fetch(`${base}/results_preview?output_mode=json&count=20`, { credentials: "include" }).catch(() => null);
      if (previewRes && previewRes.ok) {
        const previewJson = await previewRes.json().catch(() => null);
        if (previewJson) onPreview(previewJson.results || [], false);
      }
    }
    if (isDone) return { done: true, messages: (content && content.messages) || [] };
    if (Date.now() >= deadline) throw new Error(`Splunk job ${sid} did not finish within ${Math.round(timeoutMs / 1000)}s`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export async function fetchResults(sid, { app = "search", count = 20 } = {}) {
  const base = `${jobsBase(app)}/${encodeURIComponent(sid)}`;
  const res = await authedFetch(`${base}/events?output_mode=json&count=${count}`);
  const json = await res.json();
  return json.results || [];
}

// Transformed results (stats, tstats, fieldsummary, rest…). /events only
// has raw events, which a reporting search does not produce. count=0 is
// Splunk's "all of them".
export async function fetchStats(sid, { app = "search", count = 0 } = {}) {
  const base = `${jobsBase(app)}/${encodeURIComponent(sid)}`;
  const res = await authedFetch(`${base}/results?output_mode=json&count=${count}`);
  const json = await res.json();
  return json.results || [];
}

// dispatch + poll + fetchStats in one call, for the discovery agent. Time
// bounds are passed to the job, not spliced into the SPL. A discovery
// sweep (tstats over months of an index) can legitimately run for
// minutes on a busy search head, so its deadline is well past the
// tooltip's: ten minutes, then the job is cancelled and the caller told.
export async function runReporting(spl, { app = "search", earliest = "0", latest = "now", isCancelled, timeoutMs = 600000 } = {}) {
  const body = new URLSearchParams({ output_mode: "json", search: spl, earliest_time: earliest, latest_time: latest });
  const res = await authedFetch(jobsBase(app), { method: "POST", headers: { "X-Splunk-Form-Key": csrfToken() }, body });
  const { sid } = await res.json();
  try {
    const outcome = await pollUntilDone(sid, { app, isCancelled, intervalMs: 500, timeoutMs });
    if (outcome.cancelled) return { cancelled: true, rows: [], messages: [] };
    const rows = await fetchStats(sid, { app });
    return { sid, rows, messages: outcome.messages || [] };
  } finally {
    cancelJob(sid, { app }); // reporting jobs are one-shot; free the slot
  }
}

// Best-effort: an abandoned job shouldn't keep burning search-head
// concurrency. Never throws: cleanup failing is not the user's problem.
export async function cancelJob(sid, { app = "search" } = {}) {
  const base = `${jobsBase(app)}/${encodeURIComponent(sid)}`;
  await fetch(base, {
    method: "DELETE",
    credentials: "include",
    headers: { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" },
  }).catch(() => {});
}
