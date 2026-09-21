// notebook-md: an investigation as a document. The notebook store
// (app/lib/notebook.js) keeps the graph; this module writes it out as
// Markdown in one fixed layout (title, trigger, the timeline as narrative
// paragraphs in entry order, findings, open threads, an appendix of raw
// values with their provenance, and a fenced machine copy so the same text
// imports back losslessly), as plain text for a notes box that takes no
// Markdown (Enterprise Security's notable notes, an incident comment), and
// reads either back.
//
//   toMarkdown(investigation, { entries?, searches? })   → string
//   toText(investigation, { entries?, searches? })       → string, no Markdown syntax, no machine copy
//       searches: the investigation's search-history entries (app/lib/searches.js),
//       written under their own heading when there are any, never in the machine copy
//   parse(text | object)                      → a sanitized investigation, or throws
//   sanitize(object)                          → the same, for a document already parsed
//   sanitizeOrigin(object)                    → { ruleKey, ruleName?, platform?, at? } or undefined
//   sanitizeOutcome(object)                   → { result, at, evidence?, reason? } or undefined
//   originWords(origin), outcomeWords(outcome) → one line each, as the header prints them
//   narrative(investigation, entries?)        → [{ day, lines: [{ time, text }] }]
//   findings(investigation, entries?)         → [string]
//   openThreads(investigation, entries?)      → [string]
//   displayTitle(investigation)               → the title, or "Untitled investigation (date)"
//
// Pure: no DOM, no store, no network. Times are printed in UTC so the same
// investigation renders the same everywhere.

import { when } from "./when.js";

export const KINDS = ["pin", "pivot", "note", "enrichment", "parked", "verdict", "benign"];
export const OUTCOMES = ["benign", "escalated", "inconclusive"];
export const DOC_KIND = "reach-notebook";
export const DOC_VERSION = 1;
const FENCE = "```json " + DOC_KIND;

const PLATFORM_WORDS = {
  splunk: { name: "Splunk", container: "sourcetype", scope: "index", column: "field", language: "SPL" },
  sentinel: { name: "Sentinel", container: "table", scope: "workspace", column: "column", language: "KQL" },
};

function words(platform) {
  return PLATFORM_WORDS[platform] || { name: platform || "the SIEM", container: "container", scope: "scope", column: "field", language: "query" };
}

function pad(n) {
  return String(n).padStart(2, "0");
}

export function day(ts) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function clock(ts, { seconds = false } = {}) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${seconds ? ":" + pad(d.getUTCSeconds()) : ""}`;
}

// The one shared stamp (app/lib/when.js): "2026-09-17 20:58:59 UTC", the
// same style provenance, held-at and marked-at read everywhere else.
export function stamp(ts) {
  return when(ts);
}

// One line of text: no newlines, no backticks (they would close the code
// span), pipes escaped for the table.
function one(s) {
  return String(s ?? "").replace(/\s+/g, " ").trim();
}

function code(s, md) {
  const t = one(s).replace(/`/g, "'");
  return md ? "`" + t + "`" : t;
}

function cell(s) {
  return one(s).replace(/\|/g, "\\|");
}

function short(s, max = 80) {
  const t = one(s);
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
}

export function displayTitle(inv) {
  const t = one(inv && inv.title);
  return t || `Untitled investigation (${day(inv && inv.created) || "undated"})`;
}

function byId(entries) {
  const m = new Map();
  for (const e of entries) m.set(e.id, e);
  return m;
}

// "`field` = `value`" for anything that carries a value.
function fv(e, md) {
  const field = e.field || (e.from && e.from.column);
  return field ? `${code(field, md)} = ${code(short(e.value), md)}` : code(short(e.value), md);
}

// "on aws:cloudtrail (index main, Splunk)": where the value was seen.
function where(from) {
  if (!from) return "";
  const w = words(from.platform);
  const parts = [];
  if (from.container) parts.push(`on ${from.container}`);
  const inner = [];
  if (from.scope) inner.push(`${w.scope} ${from.scope}`);
  if (from.platform) inner.push(w.name);
  if (inner.length) parts.push(`(${inner.join(", ")})`);
  return parts.join(" ");
}

// What was searched: the search text when there is one, else the sid.
function searchWords(search, md) {
  if (!search) return "";
  if (search.text) return `in search ${code(short(search.text, 120), md)}`;
  if (search.sid) return `in search job ${code(search.sid, md)}`;
  return "";
}

// The event's time as a clock when it is the same UTC day as the entry,
// the full stamp when it is not.
function eventWords(event, entryAt) {
  if (!event) return "";
  const at = event.time ? (day(event.time) === day(entryAt) ? clock(event.time, { seconds: true }) : `${day(event.time)} ${clock(event.time, { seconds: true })} UTC`) : "";
  const id = event.id ? ` ${one(event.id)}` : "";
  if (!at && !id) return "";
  return `from event${id}${at ? ` at ${at}` : ""}`;
}

function target(e, ids, md) {
  const t = e.on ? ids.get(e.on) : null;
  if (!t) return "";
  if (t.value !== undefined && t.value !== null && t.value !== "") return ` on ${fv(t, md)}`;
  if (t.kind === "note") return " on a note";
  if (t.kind === "pivot") return " on a pivot";
  return "";
}

function tail(e) {
  const r = one(e.reason);
  return r ? ` Reason: ${r.replace(/[.]?$/, ".")}` : "";
}

export function sentence(e, ids, md = true) {
  const w = words(e.from && e.from.platform);
  switch (e.kind) {
    case "pin": {
      const bits = [`Pinned ${fv(e, md)}`, where(e.from), eventWords(e.from && e.from.event, e.at), searchWords(e.from && e.from.search, md)].filter(Boolean);
      return `${bits.join(" ")}.${tail(e)}`;
    }
    case "pivot": {
      const o = e.origin ? ids.get(e.origin) : null;
      const t = e.target ? ids.get(e.target) : null;
      const q = e.query && e.query.text ? ` with ${code(short(e.query.text, 160), md)}${e.query.language ? ` (${e.query.language})` : ""}` : "";
      const to = e.name ? ` to ${one(e.name)}` : t && t.from && t.from.container ? ` to ${t.from.container}` : "";
      let s = o ? `From ${fv(o, md)}, pivoted${to}${q}` : `Pivoted${to}${q}`;
      if (e.found !== undefined && e.found !== null && e.found !== "") s += `: found ${one(e.found)}`;
      if (t) s += `, which surfaced ${fv(t, md)}`;
      return `${s}.${tail(e)}`;
    }
    case "note":
      return `${e.finding ? "Finding" : "Note"}${target(e, ids, md)}: ${one(e.text)}${tail(e)}`;
    case "enrichment": {
      const src = one(e.source) || "Enrichment";
      const summary = one(e.summary) || "no result";
      return `${src}${target(e, ids, md)}: ${summary}.${tail(e)}`;
    }
    case "parked": {
      const head = e.value !== undefined && e.value !== null && e.value !== "" ? `Parked ${fv(e, md)}` : e.on ? `Parked the thread${target(e, ids, md)}` : "Parked a thread";
      const why = one(e.why || e.reason);
      const state = e.state === "resumed" ? " Picked up again later." : "";
      return `${head}${why ? `: ${why}` : ""}.${state}`;
    }
    case "verdict": {
      const v = one(e.verdict) || "no verdict";
      const src = e.source ? ` (${one(e.source)})` : "";
      return `Verdict${target(e, ids, md)}: ${v}${src}.${tail(e)}`;
    }
    case "benign": {
      const t = e.on ? ids.get(e.on) : null;
      const what = t && t.value !== undefined && t.value !== null && t.value !== "" ? fv(t, md) : e.value !== undefined && e.value !== null && e.value !== "" ? fv(e, md) : t ? "the thread" : "it";
      return `Marked ${what} known benign.${tail(e)}`;
    }
    default:
      return `${one(e.kind)}: ${one(e.text || e.value || "")}`;
  }
}

function pick(inv, entries) {
  const all = Array.isArray(inv && inv.entries) ? inv.entries : [];
  if (!entries) return all;
  const keep = new Set(entries.map((e) => (typeof e === "string" ? e : e.id)));
  return all.filter((e) => keep.has(e.id));
}

// The timeline: entries in order, grouped by UTC day, one sentence each.
export function narrative(inv, entries, md = true) {
  const all = pick(inv, entries);
  const ids = byId(Array.isArray(inv && inv.entries) ? inv.entries : all);
  const days = [];
  for (const e of all) {
    const d = day(e.at) || "undated";
    let g = days[days.length - 1];
    if (!g || g.day !== d) {
      g = { day: d, lines: [] };
      days.push(g);
    }
    g.lines.push({ time: clock(e.at), text: sentence(e, ids, md) });
  }
  return days;
}

// Findings: notes marked as findings, verdicts and enrichment results.
export function findings(inv, entries, md = true) {
  const all = pick(inv, entries);
  const ids = byId(Array.isArray(inv && inv.entries) ? inv.entries : all);
  const out = [];
  for (const e of all) {
    if (e.kind === "note" && e.finding) out.push(`${one(e.text)}${target(e, ids, md) ? ` (${target(e, ids, md).trim()})` : ""}`);
    else if (e.kind === "verdict") out.push(sentence(e, ids, md));
    else if (e.kind === "enrichment" && e.summary) out.push(sentence(e, ids, md));
  }
  return out;
}

// Open threads: parked entries not picked up again, and pins nothing was
// done with (no pivot from them, nothing attached to them).
export function openThreads(inv, entries, md = true) {
  const all = pick(inv, entries);
  const ids = byId(Array.isArray(inv && inv.entries) ? inv.entries : all);
  const touched = new Set();
  for (const e of all) {
    if (e.origin) touched.add(e.origin);
    if (e.on) touched.add(e.on);
    for (const l of e.links || []) touched.add(l.to);
  }
  const out = [];
  for (const e of all) {
    if (e.kind === "parked" && e.state !== "resumed") {
      const why = one(e.why || e.reason);
      out.push(`${e.value !== undefined && e.value !== null && e.value !== "" ? fv(e, md) : `parked thread${target(e, ids, md)}`}${why ? `: ${why}` : ""}`);
    } else if (e.kind === "pin" && !touched.has(e.id)) {
      out.push(`${fv(e, md)} ${where(e.from)}, not followed up`.replace(/\s+,/, ","));
    }
  }
  return out;
}

// "Disabled Kerberos Pre-Authentication Discovery (escu:name:..., Splunk)":
// the rule the investigation started from.
export function originWords(origin) {
  if (!origin || !origin.ruleKey) return "";
  const inner = [origin.ruleName ? one(origin.ruleKey) : "", origin.platform ? words(origin.platform).name : ""].filter(Boolean);
  return `${one(origin.ruleName || origin.ruleKey)}${inner.length ? ` (${inner.join(", ")})` : ""}`;
}

// "benign, on Mark benign of dest = WIN-DC01": how it closed and the
// evidence it closed on.
export function outcomeWords(outcome) {
  if (!outcome || !outcome.result) return "";
  const ev = outcome.evidence;
  const what = ev ? `${ev.kind === "benign" ? "Mark benign" : "Hold"}${ev.field || ev.value ? ` of ${[ev.field, ev.value].filter(Boolean).join(" = ")}` : ""}` : "";
  const bits = [one(outcome.result), what ? `on ${what}` : "", outcome.reason ? `reason: ${one(outcome.reason)}` : ""].filter(Boolean);
  return bits.join(", ");
}

function header(inv) {
  const status = inv.status === "closed" ? `closed ${stamp(inv.closed || inv.updated)}` : "open";
  const w = inv.from && inv.from.platform ? words(inv.from.platform).name : "";
  const started = [`Started ${stamp(inv.created)}`, w ? `on ${w}` : "", inv.from && inv.from.scope ? `(${words(inv.from.platform).scope} ${inv.from.scope})` : ""].filter(Boolean).join(" ");
  return { status, started, lastChange: `last change ${stamp(inv.updated || inv.created)}`, rule: originWords(inv.origin), outcome: outcomeWords(inv.outcome) };
}

function appendixRows(inv, entries) {
  const rows = [];
  for (const e of pick(inv, entries)) {
    if (e.value === undefined || e.value === null || e.value === "") continue;
    const f = e.from || {};
    rows.push({
      value: String(e.value),
      field: e.field || f.column || "",
      container: f.container || "",
      scope: f.scope || "",
      platform: f.platform || "",
      event: f.event ? [f.event.id, f.event.time ? stamp(f.event.time) : ""].filter(Boolean).join(" ") : "",
      search: f.search ? f.search.text || f.search.sid || "" : "",
      when: stamp(e.at),
      kind: e.kind,
      reason: e.reason || e.why || "",
    });
  }
  return rows;
}

// One line per search Reach handed on: the time, the language, the
// control, what it was named and where it ran, then the text.
export function searchLines(searches, md = true) {
  const out = [];
  for (const s of Array.isArray(searches) ? searches : []) {
    if (!s || !s.text) continue;
    const bits = [stamp(s.at), s.language === "kql" ? "KQL" : "SPL", s.source || "copy"];
    if (s.name) bits.push(one(s.name));
    if (s.container) bits.push(`on ${one(s.container)}`);
    if (s.sid) bits.push(`sid ${one(s.sid)}`);
    out.push(`${bits.join(" · ")}: ${code(s.text, md)}`);
  }
  return out;
}

export function toMarkdown(inv, { entries = null, machine = true, searches = null } = {}) {
  const h = header(inv);
  const out = [];
  out.push(`# ${displayTitle(inv)}`, "");
  out.push(`Trigger: ${one(inv.trigger) || "not recorded"}  `);
  if (h.rule) out.push(`Rule: ${h.rule}  `);
  if (h.outcome) out.push(`Outcome: ${h.outcome}  `);
  out.push(`${h.started}; ${h.lastChange}. Status: ${h.status}.`, "");
  const days = narrative(inv, entries, true);
  const f = findings(inv, entries, true);
  const o = openThreads(inv, entries, true);
  const rows = appendixRows(inv, entries);
  const sl = searchLines(searches, true);
  if (!days.length && !f.length && !o.length && !rows.length && !sl.length) {
    out.push("Nothing held yet. Hold a value from a popup to start the timeline.", "");
  } else {
    out.push("## Timeline", "");
    if (!days.length) out.push("Nothing recorded yet.", "");
    for (const g of days) {
      out.push(`### ${g.day}`, "");
      for (const l of g.lines) out.push(`${l.time}  ${l.text}`, "");
    }
    out.push("## Findings", "");
    if (!f.length) out.push("None recorded.", "");
    else {
      for (const s of f) out.push(`- ${s}`);
      out.push("");
    }
    out.push("## Open threads", "");
    if (!o.length) out.push("None.", "");
    else {
      for (const s of o) out.push(`- ${s}`);
      out.push("");
    }
    if (sl.length) {
      out.push("## Search history", "");
      for (const s of sl) out.push(`- ${s}`);
      out.push("");
    }
    out.push("## Appendix: values", "");
    if (!rows.length) out.push("No values.", "");
    else {
      out.push("| value | field | container | scope | platform | event | search | when | kind | reason |");
      out.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
      for (const r of rows) out.push(`| ${[r.value, r.field, r.container, r.scope, r.platform, r.event, r.search, r.when, r.kind, r.reason].map(cell).join(" | ")} |`);
      out.push("");
    }
  }
  if (machine) {
    out.push("<details><summary>Machine copy (for import into Reach)</summary>", "");
    out.push(FENCE);
    out.push(JSON.stringify({ kind: DOC_KIND, v: DOC_VERSION, investigation: entries ? { ...inv, entries: pick(inv, entries) } : inv }));
    out.push("```", "", "</details>", "");
  }
  return out.join("\n");
}

// The same document with no Markdown syntax, for a notes box.
export function toText(inv, { entries = null, searches = null } = {}) {
  const h = header(inv);
  const out = [];
  out.push(displayTitle(inv).toUpperCase(), "");
  out.push(`Trigger: ${one(inv.trigger) || "not recorded"}`);
  if (h.rule) out.push(`Rule: ${h.rule}`);
  if (h.outcome) out.push(`Outcome: ${h.outcome}`);
  out.push(`${h.started}; ${h.lastChange}. Status: ${h.status}.`, "");
  const days = narrative(inv, entries, false);
  const f = findings(inv, entries, false);
  const o = openThreads(inv, entries, false);
  const rows = appendixRows(inv, entries);
  const sl = searchLines(searches, false);
  if (!days.length && !f.length && !o.length && !rows.length && !sl.length) {
    out.push("Nothing held yet. Hold a value from a popup to start the timeline.", "");
  } else {
    out.push("TIMELINE", "");
    if (!days.length) out.push("Nothing recorded yet.", "");
    for (const g of days) {
      out.push(g.day, "");
      for (const l of g.lines) out.push(`${l.time}  ${l.text}`);
      out.push("");
    }
    out.push("FINDINGS", "");
    if (!f.length) out.push("None recorded.", "");
    else {
      for (const s of f) out.push(`- ${s}`);
      out.push("");
    }
    out.push("OPEN THREADS", "");
    if (!o.length) out.push("None.", "");
    else {
      for (const s of o) out.push(`- ${s}`);
      out.push("");
    }
    if (sl.length) {
      out.push("SEARCH HISTORY", "");
      for (const s of sl) out.push(`- ${s}`);
      out.push("");
    }
    out.push("VALUES", "");
    if (!rows.length) out.push("No values.");
    for (const r of rows) {
      const bits = [`${r.field ? r.field + " = " : ""}${r.value}`, r.container ? `on ${r.container}` : "", r.scope ? `${words(r.platform).scope} ${r.scope}` : "", r.platform ? words(r.platform).name : "", r.event ? `event ${r.event}` : "", r.search ? `search: ${short(r.search, 120)}` : "", r.when, r.reason].filter(Boolean);
      out.push(`- ${bits.join("; ")}`);
    }
  }
  return out.join("\n").replace(/\n+$/, "") + "\n";
}

// ---- reading it back -------------------------------------------------

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

function str(v, max = 20000) {
  if (v === undefined || v === null) return undefined;
  const s = typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
  return s.length > max ? s.slice(0, max) : s;
}

function num(v) {
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) ? n : undefined;
}

// Provenance, whitelisted key by key: platform, container, column, scope,
// event { id, time, summary }, search { text, sid, earliest, latest, at }, at.
export function sanitizeFrom(from) {
  if (!from || typeof from !== "object") return undefined;
  const out = {};
  for (const k of ["platform", "container", "column", "scope"]) {
    const v = str(from[k], 500);
    if (v) out[k] = v;
  }
  if (from.event && typeof from.event === "object") {
    const ev = {};
    const id = str(from.event.id, 500);
    const time = num(from.event.time);
    const summary = str(from.event.summary, 2000);
    if (id) ev.id = id;
    if (time !== undefined) ev.time = time;
    if (summary) ev.summary = summary;
    if (Object.keys(ev).length) out.event = ev;
  }
  if (from.search && typeof from.search === "object") {
    const s = {};
    for (const k of ["text", "sid", "earliest", "latest"]) {
      const v = str(from.search[k], k === "text" ? 4000 : 200);
      if (v) s[k] = v;
    }
    const at = num(from.search.at);
    if (at !== undefined) s.at = at;
    if (Object.keys(s).length) out.search = s;
  }
  const at = num(from.at);
  if (at !== undefined) out.at = at;
  return Object.keys(out).length ? out : undefined;
}

// The rule an investigation started from: the rule key string the
// runbooks store is keyed by, the rule's display name, the platform and
// when. Never a scope fact: an index or a workspace is configuration.
export function sanitizeOrigin(origin) {
  if (!origin || typeof origin !== "object") return undefined;
  const ruleKey = str(origin.ruleKey, 600);
  if (!ruleKey || !ruleKey.trim()) return undefined;
  const out = { ruleKey: ruleKey.trim() };
  const ruleName = str(origin.ruleName, 300);
  if (ruleName && ruleName.trim()) out.ruleName = ruleName.trim();
  if (origin.platform === "splunk" || origin.platform === "sentinel") out.platform = origin.platform;
  const at = num(origin.at);
  if (at !== undefined) out.at = at;
  return out;
}

// How an investigation closed: one of OUTCOMES, when, the Hold or Mark
// benign it closed on (the entry's id, field and value) and a reason.
export function sanitizeOutcome(outcome) {
  if (!outcome || typeof outcome !== "object") return undefined;
  if (!OUTCOMES.includes(outcome.result)) return undefined;
  const out = { result: outcome.result, at: num(outcome.at) ?? 0 };
  if (outcome.evidence && typeof outcome.evidence === "object") {
    const ev = {};
    if (outcome.evidence.kind === "hold" || outcome.evidence.kind === "benign") ev.kind = outcome.evidence.kind;
    const entry = str(outcome.evidence.entry, 100);
    if (entry && !UNSAFE.has(entry)) ev.entry = entry;
    const field = str(outcome.evidence.field, 500);
    if (field) ev.field = field;
    const value = str(outcome.evidence.value, 4000);
    if (value) ev.value = value;
    if (ev.kind) out.evidence = ev;
  }
  const reason = str(outcome.reason, 2000);
  if (reason && reason.trim()) out.reason = reason.trim();
  return out;
}

export function sanitizeEntry(e) {
  if (!e || typeof e !== "object") return null;
  if (!KINDS.includes(e.kind)) return null;
  const id = str(e.id, 100);
  if (!id || UNSAFE.has(id)) return null;
  const out = { id, kind: e.kind, at: num(e.at) ?? 0 };
  for (const k of ["reason", "field", "text", "name", "source", "summary", "why", "verdict", "state", "on", "origin", "target"]) {
    const v = str(e[k], k === "text" || k === "summary" ? 20000 : 2000);
    if (v !== undefined && v !== "") out[k] = v;
  }
  if (e.value !== undefined && e.value !== null) {
    const v = str(e.value, 4000);
    if (v !== undefined) out.value = v;
  }
  if (e.found !== undefined && e.found !== null && e.found !== "") out.found = typeof e.found === "number" ? e.found : str(e.found, 200);
  if (e.finding === true) out.finding = true;
  if (e.query && typeof e.query === "object") {
    const q = {};
    const text = str(e.query.text, 4000);
    const language = str(e.query.language, 20);
    if (text) q.text = text;
    if (language) q.language = language;
    if (Object.keys(q).length) out.query = q;
  }
  if (e.result !== undefined && e.result !== null) {
    try {
      const raw = JSON.stringify(e.result);
      if (raw && raw.length <= 20000) out.result = JSON.parse(raw);
    } catch {
      /* not serialisable: dropped */
    }
  }
  const from = sanitizeFrom(e.from);
  if (from) out.from = from;
  if (Array.isArray(e.links)) {
    const links = [];
    for (const l of e.links) {
      if (!l || typeof l !== "object") continue;
      const to = str(l.to, 100);
      const rel = str(l.rel, 50);
      if (to && !UNSAFE.has(to)) links.push(rel ? { to, rel } : { to });
    }
    if (links.length) out.links = links;
  }
  return out;
}

// An investigation object from any source (an import, an older store):
// whitelisted keys, entries each checked, unsafe ids dropped.
export function sanitize(inv) {
  if (!inv || typeof inv !== "object") throw new Error("Not an investigation.");
  const id = str(inv.id, 100);
  if (!id || UNSAFE.has(id)) throw new Error("An investigation needs an id.");
  const out = {
    id,
    title: str(inv.title, 500) ?? null,
    created: num(inv.created) ?? 0,
    updated: num(inv.updated) ?? num(inv.created) ?? 0,
    trigger: str(inv.trigger, 2000) ?? "",
    status: inv.status === "closed" ? "closed" : "open",
    entries: [],
  };
  if (out.title === "") out.title = null;
  const closed = num(inv.closed);
  if (closed !== undefined) out.closed = closed;
  const from = sanitizeFrom(inv.from);
  if (from) out.from = from;
  const origin = sanitizeOrigin(inv.origin);
  if (origin) out.origin = origin;
  const outcome = out.status === "closed" ? sanitizeOutcome(inv.outcome) : undefined;
  if (outcome) out.outcome = outcome;
  const seen = new Set();
  for (const e of Array.isArray(inv.entries) ? inv.entries : []) {
    const s = sanitizeEntry(e);
    if (s && !seen.has(s.id)) {
      seen.add(s.id);
      out.entries.push(s);
    }
  }
  return out;
}

// JSON (the export document or a bare investigation) or Markdown carrying
// the machine copy. Markdown without one is not parsed: the narrative is
// for people, and half a document would be worse than none.
export function parse(text) {
  let doc = text;
  if (typeof text === "string") {
    const t = text.trim();
    if (t.startsWith("{")) doc = JSON.parse(t);
    else {
      const i = t.indexOf(FENCE);
      if (i < 0) throw new Error("No machine copy in this text: only a Reach export can be imported.");
      const start = i + FENCE.length;
      const end = t.indexOf("\n```", start);
      if (end < 0) throw new Error("The machine copy is cut off.");
      doc = JSON.parse(t.slice(start, end).trim());
    }
  }
  if (!doc || typeof doc !== "object") throw new Error("Not a Reach notebook document.");
  if (doc.kind === DOC_KIND) {
    if (doc.v !== DOC_VERSION) throw new Error(`Notebook document version ${doc.v} is not one this build reads.`);
    return sanitize(doc.investigation);
  }
  if (Array.isArray(doc.entries)) return sanitize(doc);
  throw new Error("Not a Reach notebook document.");
}

export default { toMarkdown, toText, parse, sanitize, sanitizeEntry, sanitizeFrom, sanitizeOrigin, sanitizeOutcome, originWords, outcomeWords, narrative, findings, openThreads, displayTitle, sentence, KINDS, OUTCOMES, DOC_KIND, DOC_VERSION };
