// when: the one timestamp formatter the app shares, so a provenance line,
// a held or marked date and a notebook entry all read the same way instead
// of drifting through toLocaleString()'s locale- and platform-dependent
// output. Always UTC, always stated, so the same investigation reads the
// same on any machine.
//
//   when(ts) -> "2026-09-17 20:58:59 UTC" | ""
//     ts: epoch milliseconds, epoch seconds, an ISO string or anything
//     Date.parse() reads. A number under 1e12 is read as seconds (Splunk's
//     _time, Unix epoch conventions); at or above, as milliseconds
//     (Date.now(), the notebook's own added_at/at). "" for null, undefined,
//     empty string or a value that does not parse to a real instant.
//   toMillis(ts) -> epoch milliseconds | undefined     the parse alone, no formatting

const pad = (n, w = 2) => String(n).padStart(w, "0");

// A real ISO 8601 instant only: YYYY-MM-DD, optionally a T- or
// space-separated time, optionally a zone. Free text in a host page's own
// locale ("9/18/26 2:03 PM") is deliberately left alone: Date.parse reads
// it as local time with no zone stated, so reformatting it would answer a
// different, machine-dependent instant instead of leaving the page's own
// words as they were.
const ISO_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?(Z|[+-]\d{2}:?\d{2})?$/;

export function toMillis(ts) {
  if (ts === null || ts === undefined || ts === "") return undefined;
  if (typeof ts === "number") {
    if (!Number.isFinite(ts)) return undefined;
    return Math.abs(ts) < 1e12 ? ts * 1000 : ts;
  }
  const s = String(ts).trim();
  if (!s) return undefined;
  if (/^-?\d+(\.\d+)?$/.test(s)) return toMillis(Number(s));
  if (!ISO_RE.test(s)) return undefined;
  const p = Date.parse(s);
  return Number.isNaN(p) ? undefined : p;
}

export function when(ts) {
  const ms = toMillis(ts);
  if (ms === undefined) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

export default { when, toMillis };
