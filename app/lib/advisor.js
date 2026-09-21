// The query advisor: rules-based lint over SPL and KQL, one line of why
// per finding, and the reading of a job's own numbers when Splunk has
// run the search. Advisory only: nothing here refuses a query (spl.lint
// and kql.lint are the gates); every finding is a note the analyst can
// ignore.
//
//   lint(text, platform, ctx?) -> [Finding]        cheapest reading of the text, by position
//   summary(findings)          -> "advisor: 2 notes, 1 caution" | "advisor: no notes"
//   rulesFor(platform)         -> the rules that run on that platform
//   parseJob(entry)            -> Stats | null      from a GET on search/jobs/<sid>
//   explain(stats, text?, ctx?) -> Reading           the ratio and the one finding that most likely explains it
//   RULES, SEVERITIES
//
// Finding: { rule, title, severity, span: [start, end], text, why, fix }
//   severity  caution (the scan or the search head pays for it) | note (worth knowing)
//   fix       { text, construct?, label } | null   construct names a ladder rung when one applies
// ctx: { classOf(field) -> efficiency class | null }   optional, from efficiency.js
//
// Stats: { sid, scanCount, eventCount, resultCount, runDuration, optimizedSearch, search, earliestTime, latestTime, isDone }
// Reading: { ratio, dropped, line, finding, findings }
//   ratio     scanCount / eventCount: how many events were read per event that matched
//   dropped   eventCount / resultCount: how many matched per result the pipeline kept
//
// Job stats are Splunk's: Reach never runs a query on Sentinel, so there
// is no measured side there (docs: SECURITY.md, the Sentinel section).
//
// Plain ES module. No DOM, no store, no network.

import { RULES } from "./advisor-rules/index.js";

export { RULES };

export const SEVERITIES = Object.freeze(["caution", "note"]);

function norm(platform) {
  return platform === "kql" || platform === "sentinel" ? "kql" : "spl";
}

export function rulesFor(platform) {
  const p = norm(platform);
  return RULES.filter((r) => r.platform === p);
}

export function lint(text, platform, ctx = {}) {
  const s = String(text || "");
  if (!s.trim()) return [];
  const out = [];
  for (const rule of rulesFor(platform)) {
    let hits = [];
    try {
      hits = rule.find(s, ctx) || [];
    } catch {
      continue; // a rule that cannot read the text has nothing to say about it
    }
    for (const h of hits) {
      const start = Math.max(0, Math.min(s.length, h.start | 0));
      const end = Math.max(start, Math.min(s.length, h.end | 0));
      out.push({
        rule: rule.id,
        title: rule.title,
        severity: SEVERITIES.includes(h.severity) ? h.severity : rule.severity,
        span: [start, end],
        text: s.slice(start, end),
        why: h.why || rule.why,
        fix: h.fix ? { text: String(h.fix.text || ""), construct: h.fix.construct || null, label: h.fix.label || "" } : null,
      });
    }
  }
  out.sort((a, b) => a.span[0] - b.span[0] || a.span[1] - b.span[1] || (a.severity === b.severity ? 0 : a.severity === "caution" ? -1 : 1));
  return out;
}

export function summary(findings) {
  const list = findings || [];
  if (!list.length) return "advisor: no notes";
  const cautions = list.filter((f) => f.severity === "caution").length;
  const notes = list.length - cautions;
  const parts = [];
  if (notes) parts.push(`${notes} note${notes === 1 ? "" : "s"}`);
  if (cautions) parts.push(`${cautions} caution${cautions === 1 ? "" : "s"}`);
  return `advisor: ${parts.join(", ")}`;
}

// ---------------------------------------------------------------------------
// Job stats

const NUM = ["scanCount", "eventCount", "resultCount", "runDuration"];

function num(v) {
  if (v === null || v === undefined || String(v).trim() === "") return null;
  const n = typeof v === "number" ? v : Number(String(v).trim());
  return Number.isFinite(n) ? n : null;
}

// entry: the REST entry ({ name, content }) or its content alone.
export function parseJob(entry) {
  if (!entry || typeof entry !== "object") return null;
  const c = entry.content && typeof entry.content === "object" ? entry.content : entry;
  const stats = { sid: String(entry.name || c.sid || ""), optimizedSearch: typeof c.optimizedSearch === "string" ? c.optimizedSearch : "", search: typeof c.search === "string" ? c.search : "", earliestTime: c.earliestTime || null, latestTime: c.latestTime || null, isDone: c.isDone === true || c.isDone === "1" || c.isDone === 1 || c.dispatchState === "DONE" };
  let any = false;
  for (const k of NUM) {
    const n = num(c[k]);
    stats[k] = n;
    if (n !== null) any = true;
  }
  return any ? stats : null;
}

const SCAN_RULES = ["spl/leading-wildcard", "spl/scan-not-narrowed", "spl/index-star", "spl/neq-null"];
const PIPE_RULES = ["spl/filter-after-scan", "spl/table-before-stats", "spl/join-to-stats", "spl/subsearch-limits"];

function fmt(n) {
  return n === null || n === undefined ? "?" : Math.round(n).toLocaleString("en-US");
}

function ratioOf(a, b) {
  if (a === null || b === null) return null;
  if (b <= 0) return a > 0 ? Infinity : 1;
  return a / b;
}

function ratioText(r) {
  if (r === null) return "?";
  if (r === Infinity) return "everything read, nothing matched";
  return `${r >= 10 ? Math.round(r) : Math.round(r * 10) / 10}:1`;
}

// The one finding that most likely explains the numbers: the scan ratio
// first (what the lexicon could not narrow), the pipeline drop second
// (what ran after the scan), each from the rules that touch that stage,
// cautions before notes, and the text the job actually ran (its
// optimizedSearch, then the search as typed) is what gets read.
export function explain(stats, text, ctx = {}) {
  const s = stats || {};
  const source = s.optimizedSearch || s.search || text || "";
  const findings = lint(source, "spl", ctx);
  const ratio = ratioOf(s.scanCount, s.eventCount);
  const dropped = ratioOf(s.eventCount, s.resultCount);
  const pick = (ids) => {
    for (const sev of SEVERITIES) for (const id of ids) {
      const f = findings.find((x) => x.rule === id && x.severity === sev);
      if (f) return f;
    }
    return null;
  };
  let finding = null;
  let line;
  const dur = s.runDuration !== null && s.runDuration !== undefined ? ` in ${Math.round(s.runDuration * 10) / 10} s` : "";
  if (ratio !== null && ratio >= 3) {
    finding = pick(SCAN_RULES);
    line = `read ${fmt(s.scanCount)} events to match ${fmt(s.eventCount)} (${ratioText(ratio)})${dur}: ${finding ? `${finding.title} is the likely reason` : "no rule here names the reason; the tested fields may be calculated or lookup outputs, which the index cannot narrow on"}`;
  } else if (dropped !== null && dropped >= 3) {
    finding = pick(PIPE_RULES);
    line = `matched ${fmt(s.eventCount)} events for ${fmt(s.resultCount)} results (${ratioText(dropped)})${dur}: ${finding ? `${finding.title} is where they went` : "the pipeline after the scan drops most of them; a test that could be a search term would drop them before the scan"}`;
  } else if (ratio !== null) {
    finding = pick([...SCAN_RULES, ...PIPE_RULES]);
    line = `read ${fmt(s.scanCount)} events, matched ${fmt(s.eventCount)}, kept ${fmt(s.resultCount)}${dur}: the terms did the narrowing${finding ? `; ${finding.title} is still worth a look` : ""}`;
  } else {
    line = `the job reports no counts yet${s.isDone ? "" : " (still running)"}`;
  }
  return { ratio, dropped, line, finding, findings };
}

export default { lint, summary, rulesFor, parseJob, explain, RULES, SEVERITIES };
