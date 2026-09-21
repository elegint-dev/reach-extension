// benign: the values an analyst has marked known benign, and the exclusion
// that keeps them out of a search. A value is marked from a popup with the
// field and container it was seen on, a reason, and an optional expiry;
// the set is deduplicated; when the search editor is focused the app can
// offer (never inject) the cheapest exclusion that is still exact enough
// to be safe. The data stays inside Reach: no lookup, no watchlist, no
// artifact on either platform.
//
// Store. One document under store key "benign" (reach.benign in
// chrome.storage.local, so the in-page popups and the app share it;
// localStorage, then memory, when served as a plain page):
//
//   { v: 1, entries: [entry, ...] }
//   entry  { id, value, field, container, platform, reason, added_at, expires_at?, from? }
//   from   provenance as the notebook keeps it: { platform, container, column, scope,
//          event { id, time, summary }, search { text, sid, earliest, latest, at }, at }
//
// One entry per (field, value, container): marking the same value again
// refreshes its reason, expiry and provenance and keeps its id. platform
// on an entry is provenance; the platform argument to exclusion() picks
// the output language, it does not filter entries (a container name
// belongs to one platform already). Times are epoch milliseconds.
//
//   await load()                                  → the document; the readers below are
//                                                   synchronous and answer empty until it resolves
//   list({ container?, field?, platform?, includeExpired?, now? })   → entries, newest first
//   get(id)                                       → entry | null
//   await add({ value, field, container, platform?, reason?, expires_at?, from? })   → the entry
//   await remove(id | { field, value, container })   → the removed entry | null
//   await expire({ now? })                        → the entries that had lapsed
//   await purge({ container?, field? })           → how many were removed (no filter: all)
//   await prune()                                 → { pruned, warning } past MAX_BYTES, oldest first
//   subscribe(fn)                                 → fn({ type: "change" | "pruned" | "expired", ... })
//   exportJSON()                                  → a JSON string of the live entries
//   await importJSON(text | object, { replace? })  → { added, updated, kept }
//   await attach(entry | id, { on?, reason?, investigation?, notebook? })
//                                                 → { ok, entry } | { ok: false, reason }; never throws
//   exclusion(field, container, platform, opts?)  → the offer, or null with nothing to exclude
//
// Exclusion. exclusion(field, container, platform, { threshold = 50, fold = "auto",
// ci?, dynamic?, samples?, values?, now? }) reads the live entries for the
// field on the container (opts.values replaces them for a pure call) and
// returns
//
//   { text, form, place, why, caveats, count, values, exact, field, container, platform,
//     apply: { text, form: place, field, mode: "append", platform, trace }, alternative? }
//
//   form     not       one value: NOT field="v"                 KQL not(field == "v")
//            not_in    up to threshold values: NOT field IN (...)   KQL not(field in (...))
//            wildcard  the values fold to one pattern through the ladder:
//                      NOT field="C:\\Windows\\*.exe"          KQL not(field startswith "..." and ...)
//                      NOT field="prefix*"                     KQL field !startswith "prefix"
//            chain     past the threshold with no fold: NOT field="a" NOT field="b" ...
//                      KQL not(field == "a") and not(field == "b") ...
//            where     Splunk only: a value holds *, which a search term reads as a
//                      wildcard, so the whole set moves to
//                      | where isnull(field) OR NOT in(field, ...)
//   place    term or stage, the word editor-bridge.place() takes; apply is the request
//            bridge.apply() takes as it is
//   why      one line: the form, then how events without the field fare (NOT keeps them,
//            field!= would drop them; a Kusto string column is never null, so the
//            negated match keeps the row)
//   exact    false only for wildcard, which is wider than the marked values
//
// The wildcard fold: every value is cut by segments.segment(); the run of
// leading pieces and the run of trailing pieces the values share are kept,
// what differs between them is opened, and ladder.build() renders the
// spec. Only a rung the ladder calls exact and emits as a search term
// (trailing_wildcard or wildcard) qualifies, so a leading wildcard is
// never offered; the pattern must match every marked value and, when
// samples are given, no sample value that was not marked. With fold
// "auto" the fold is chosen only past the threshold and otherwise returned
// as `alternative`; true prefers it whenever it exists; false never folds.
// Every text is linted (spl.lint, kql.lint) before it is returned.
//
// Quoting is spl.quote and kql.quote, always. Writes are serialised
// through one chain. No DOM.

import { versionedDocument, newId as makeId } from "./document.js";
import { segment } from "./segments.js";
import { build, lintable, LINT_COMMANDS, LadderError } from "./ladder.js";
import * as spl from "./spl.js";
import { LANG } from "./lang.js";

export const KEY = "benign";
export const VERSION = 1;
export const MAX_BYTES = 500_000;
export const THRESHOLD = 50;
export const MAX_VALUE = 4000;
const MAX_TEXT = 2000;
const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
const SPL_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_.{}]*$/;
const SPL_PLAIN_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export class BenignError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "BenignError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Shapes

export function normPlatform(p) {
  const s = String(p == null ? "" : p).toLowerCase();
  if (s === "splunk" || s === "spl") return "splunk";
  if (s === "sentinel" || s === "kql") return "sentinel";
  return "";
}

function lang(platform) {
  const p = normPlatform(platform);
  if (!p) throw new BenignError("bad_platform", `platform must be splunk or sentinel, not ${String(platform)}`);
  return p === "splunk" ? "spl" : "kql";
}

function str(v, max) {
  if (v === undefined || v === null) return undefined;
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function now() {
  return Date.now();
}

function newId() {
  return makeId("b");
}

export function keyOf(e) {
  return [(str(e.field, MAX_TEXT) || "").trim(), str(e.value, MAX_VALUE) || "", (str(e.container, MAX_TEXT) || "").trim()].join("\u0000");
}

function sanitizeFrom(from) {
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
    const summary = str(from.event.summary, MAX_TEXT);
    if (id) ev.id = id;
    if (time !== undefined) ev.time = time;
    if (summary) ev.summary = summary;
    if (Object.keys(ev).length) out.event = ev;
  }
  if (from.search && typeof from.search === "object") {
    const s = {};
    for (const k of ["text", "sid", "earliest", "latest"]) {
      const v = str(from.search[k], k === "text" ? MAX_VALUE : 200);
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

// An entry from any source: the popup, the store, an import. null when it
// cannot be kept (no value, no field, an unsafe id).
export function sanitizeEntry(e) {
  if (!e || typeof e !== "object") return null;
  const value = str(e.value, MAX_VALUE);
  const field = str(e.field, MAX_TEXT);
  if (value === undefined || value === "" || !field || !field.trim()) return null;
  const id = str(e.id, 100);
  if (id !== undefined && (id === "" || UNSAFE.has(id))) return null;
  const out = {
    id: id || newId(),
    value,
    field: field.trim(),
    container: (str(e.container, MAX_TEXT) || "").trim(),
    platform: normPlatform(e.platform) || normPlatform(e.from && e.from.platform) || "",
    reason: str(e.reason, MAX_TEXT) || "",
    added_at: num(e.added_at) ?? now(),
  };
  const exp = num(e.expires_at);
  if (exp !== undefined && exp > 0) out.expires_at = exp;
  const from = sanitizeFrom(e.from);
  if (from) out.from = from;
  return out;
}

export function isExpired(e, at = now()) {
  return typeof e.expires_at === "number" && e.expires_at <= at;
}

// ---------------------------------------------------------------------------
// Document

function empty() {
  return { v: VERSION, entries: [] };
}

function adopt(raw) {
  const out = empty();
  if (!raw || typeof raw !== "object") return out;
  const seen = new Map();
  for (const e of Array.isArray(raw.entries) ? raw.entries : []) {
    const s = sanitizeEntry(e);
    if (!s) continue;
    const k = keyOf(s);
    const prev = seen.get(k);
    if (!prev || prev.added_at <= s.added_at) seen.set(k, s);
  }
  out.entries = Array.from(seen.values());
  return out;
}

// Past the bound the oldest entries go first, expired ones before live
// ones; the newest entry is never pruned.
function pruneInPlace(d, { at, bytes: size, budget }) {
  const pruned = [];
  const order = d.entries
    .slice()
    .sort((a, b) => Number(isExpired(b, at)) - Number(isExpired(a, at)) || a.added_at - b.added_at);
  const newest = order[order.length - 1];
  for (const e of order) {
    if (size(d) <= budget) break;
    if (e === newest) break;
    d.entries = d.entries.filter((x) => x !== e);
    pruned.push({ id: e.id, field: e.field, value: e.value, container: e.container });
  }
  let warning = "";
  if (pruned.length) warning = `The known-benign set was over its ${Math.round(budget / 1000)} KB bound: the ${pruned.length === 1 ? "oldest entry was" : `${pruned.length} oldest entries were`} removed. Export what you want to keep before it grows again.`;
  if (size(d) > budget) warning = `${warning ? warning + " " : ""}The newest entry alone is over the bound.`;
  return { pruned, warning };
}

const D = versionedDocument({ key: KEY, version: VERSION, empty, adopt, prune: pruneInPlace, budget: MAX_BYTES });

export function load(opts) {
  return D.load(opts);
}

export function bytes(d) {
  return D.bytes(d);
}

// mutate(d) returns [result, changed]; an unchanged document is not
// written. The store's own change notification is the one "change" event
// per write, on every backend.
function write(mutate, at = now()) {
  return D.update(
    (d) => {
      const [result, changed] = mutate(d);
      return changed ? result : D.unchanged(result);
    },
    { at },
  );
}

export function prune() {
  return D.prune();
}

// ---------------------------------------------------------------------------
// Entries

function copy(e) {
  return JSON.parse(JSON.stringify(e));
}

function matches(e, { container, field, platform }) {
  if (container !== undefined && container !== null && e.container !== String(container).trim()) return false;
  if (field !== undefined && field !== null && e.field !== String(field).trim()) return false;
  if (platform && e.platform && e.platform !== normPlatform(platform)) return false;
  return true;
}

export function list({ container, field, platform, includeExpired = false, now: at = now() } = {}) {
  const d = D.get();
  return d.entries
    .map((e, i) => ({ e, i }))
    .filter(({ e }) => matches(e, { container, field, platform }) && (includeExpired || !isExpired(e, at)))
    .sort((a, b) => b.e.added_at - a.e.added_at || b.i - a.i)
    .map(({ e }) => copy(e));
}

export function get(id) {
  const d = D.get();
  const e = d.entries.find((x) => x.id === id);
  return e ? copy(e) : null;
}

function find(d, ref) {
  if (typeof ref === "string") return d.entries.find((x) => x.id === ref) || null;
  if (ref && typeof ref === "object") {
    const k = keyOf(ref);
    return d.entries.find((x) => keyOf(x) === k) || null;
  }
  return null;
}

export async function add(entry) {
  const e = sanitizeEntry({ ...(entry || {}), id: undefined, added_at: undefined });
  if (!e) throw new BenignError("bad_entry", "A known-benign entry needs a value and a field.");
  const given = entry || {};
  return write((d) => {
    const prev = find(d, e);
    if (prev) {
      if (given.reason !== undefined && given.reason !== null && String(given.reason) !== "") prev.reason = e.reason;
      if (given.expires_at === null) delete prev.expires_at;
      else if (e.expires_at !== undefined) prev.expires_at = e.expires_at;
      else if (isExpired(prev)) delete prev.expires_at; // marked again after it lapsed
      if (e.from) prev.from = e.from;
      if (e.platform) prev.platform = e.platform;
      return [copy(prev), true];
    }
    d.entries.push(e);
    return [copy(e), true];
  });
}

export async function remove(ref) {
  return write((d) => {
    const e = find(d, ref);
    if (!e) return [null, false];
    d.entries = d.entries.filter((x) => x !== e);
    return [copy(e), true];
  });
}

export async function expire({ now: at = now() } = {}) {
  return write((d) => {
    const gone = d.entries.filter((e) => isExpired(e, at)).map(copy);
    if (!gone.length) return [gone, false];
    d.entries = d.entries.filter((e) => !isExpired(e, at));
    D.emit({ type: "expired", entries: gone });
    return [gone, true];
  }, at);
}

export async function purge({ container, field } = {}) {
  return write((d) => {
    const keep = d.entries.filter((e) => !matches(e, { container, field }));
    const n = d.entries.length - keep.length;
    d.entries = keep;
    return [n, n > 0];
  });
}

export function subscribe(fn) {
  return D.subscribe(fn);
}

// ---------------------------------------------------------------------------
// Export and import

export function exportJSON() {
  return D.exportJSON({ entries: list() });
}

// Merge by (field, value, container): a newer added_at wins, an entry not
// here is added. replace drops what is here first.
export async function importJSON(text, { replace = false } = {}) {
  let raw = text;
  if (typeof text === "string") {
    try {
      raw = JSON.parse(text);
    } catch {
      throw new BenignError("bad_json", "Not a JSON document.");
    }
  }
  const incoming = adopt(Array.isArray(raw) ? { entries: raw } : raw).entries;
  return write((d) => {
    if (replace) d.entries = [];
    let added = 0;
    let updated = 0;
    let kept = 0;
    for (const e of incoming) {
      const prev = find(d, e);
      if (!prev) {
        d.entries.push({ ...e, id: d.entries.some((x) => x.id === e.id) ? newId() : e.id });
        added += 1;
      } else if (prev.added_at < e.added_at) {
        Object.assign(prev, { ...e, id: prev.id });
        if (e.expires_at === undefined) delete prev.expires_at;
        updated += 1;
      } else kept += 1;
    }
    return [{ added, updated, kept }, Boolean(added || updated || replace)];
  });
}

// ---------------------------------------------------------------------------
// Notebook

// Attaches the mark to the current investigation as a benign entry. The
// notebook is loaded on demand; when it cannot be (a page that does not
// ship it, a store that refuses) the mark stays in this set and the
// result says why.
export async function attach(ref, { on = null, reason = null, investigation = null, notebook = null } = {}) {
  let e = typeof ref === "string" ? get(ref) : sanitizeEntry(ref);
  if (typeof ref === "string" && !e) return { ok: false, reason: `No known-benign entry ${ref}.` };
  if (!e) return { ok: false, reason: "A known-benign entry needs a value and a field." };
  try {
    const nb = notebook || (await import("./notebook.js"));
    if (!nb || typeof nb.add !== "function") return { ok: false, reason: "The notebook is not available here." };
    await nb.load();
    const from = { ...(e.from || {}) };
    if (!from.platform && e.platform) from.platform = e.platform;
    if (!from.container && e.container) from.container = e.container;
    if (!from.column) from.column = e.field;
    const entry = { kind: "benign", field: e.field, value: e.value, reason: reason || e.reason || null, from };
    if (on) {
      const inv = investigation ? nb.get(investigation) : nb.current();
      if (inv && inv.entries.some((x) => x.id === on)) entry.on = on;
    }
    const out = await nb.add(entry, { investigation });
    return { ok: true, entry: out };
  } catch (err) {
    return { ok: false, reason: err && err.message ? err.message : String(err) };
  }
}

// ---------------------------------------------------------------------------
// Exclusion

const NULL_NOTE = {
  spl: "NOT keeps events that lack the field, where field!= would drop them",
  kql: "a Kusto string column is never null: an empty or missing value fails the match, so the row is kept",
};

function splField(field) {
  const s = String(field == null ? "" : field).trim();
  if (!SPL_FIELD_RE.test(s)) throw new BenignError("bad_field", `not a valid Splunk field name: ${s || "(empty)"}`);
  return s;
}

function splEvalField(field) {
  const s = splField(field);
  return SPL_PLAIN_RE.test(s) ? s : `'${s}'`;
}

function lintOrThrow(l, text, place) {
  const verdict = LANG[l].lint(lintable({ platform: l, form: place, text }), { commands: LINT_COMMANDS });
  if (!verdict.ok) throw new BenignError("lint", `exclusion failed lint: ${verdict.violations.join("; ")}: ${text}`);
}

function rungs(spec, o) {
  try {
    return build(spec, o);
  } catch (err) {
    if (err instanceof LadderError) throw new BenignError(err.code, err.message);
    throw err;
  }
}

function termRung(list, construct) {
  return list.find((r) => r.construct === construct && r.form === "term") || null;
}

// KQL: a single startswith takes its native negation; a compound (the
// wildcard rung's startswith and endswith and strlen) keeps the not()
// wrapper, since distributing ! over the conjunction would widen it.
function negate(l, text, construct) {
  if (l === "spl") return `NOT ${text}`;
  if (construct === "trailing_wildcard" && / startswith /.test(text) && !/ and /.test(text)) return text.replace(" startswith ", " !startswith ");
  return `not(${text})`;
}

function sameSeg(a, b) {
  return Boolean(a && b) && a.text === b.text && a.sep === b.sep && Boolean(a.quoted) === Boolean(b.quoted);
}

// The spec the values share: the leading run and the trailing run of
// equal pieces kept, at least one piece per value opened between them.
export function foldSpec(values) {
  if (!Array.isArray(values) || values.length < 2) return null;
  const segs = values.map((v) => segment(v));
  const first = segs[0];
  if (segs.some((s) => s.shape !== first.shape || s.detail !== first.detail || s.tail !== first.tail)) return null;
  const minLen = Math.min(...segs.map((s) => s.segments.length));
  if (minLen < 2) return null;
  let lead = 0;
  while (lead < minLen - 1 && segs.every((s) => sameSeg(s.segments[lead], first.segments[lead]))) lead++;
  if (lead === 0 || !first.segments.slice(0, lead).some((g) => g.text !== "")) return null;
  let trail = 0;
  while (lead + trail < minLen - 1 && segs.every((s) => sameSeg(s.segments[s.segments.length - 1 - trail], first.segments[first.segments.length - 1 - trail]))) trail++;
  const n = first.segments.length;
  return {
    shape: first.shape,
    detail: first.detail,
    tail: first.tail,
    truncated: segs.some((s) => s.truncated),
    segments: first.segments.map((g, i) => ({ ...g, state: i < lead || i >= n - trail ? "keep" : "any" })),
  };
}

function foldRung(l, values, o) {
  const spec = foldSpec(values);
  if (!spec) return null;
  const list = rungs(spec, { platform: l, field: o.field, ci: o.ci, dynamic: o.dynamic, samples: o.samples });
  const r = list.find((x) => x.form === "term" && x.exact && (x.construct === "trailing_wildcard" || x.construct === "wildcard") && x.pattern);
  if (!r) return null;
  const re = new RegExp(r.pattern, "i");
  if (!values.every((v) => re.test(v))) return null;
  if (Array.isArray(o.samples)) {
    const marked = new Set(values.map((v) => v.toLowerCase()));
    const stray = o.samples.filter((s) => s && s.value !== undefined && s.value !== null && re.test(String(s.value)) && !marked.has(String(s.value).toLowerCase()));
    if (stray.length) return null;
  }
  let opened = 0;
  let prevAny = false;
  for (const g of spec.segments) {
    if (g.state === "any" && !prevAny) opened += 1;
    prevAny = g.state === "any";
  }
  return { rung: r, opened };
}

function defaultCi(values) {
  return values.every((v) => {
    const s = segment(v);
    return s.shape === "path" && (s.detail === "windows" || s.detail === "unc" || s.detail === "registry");
  });
}

export function exclusion(field, container, platform, opts = {}) {
  const l = lang(platform);
  const at = opts.now === undefined ? now() : opts.now;
  const raw = Array.isArray(opts.values) ? opts.values : list({ field, container, now: at }).map((e) => e.value).sort();
  const values = Array.from(new Set(raw.map((v) => String(v == null ? "" : v)).filter((v) => v !== "")));
  if (!values.length) return null;
  const threshold = Number.isInteger(opts.threshold) && opts.threshold > 0 ? opts.threshold : THRESHOLD;
  const ci = opts.ci === undefined ? defaultCi(values) : Boolean(opts.ci);
  const o = { field, ci, dynamic: opts.dynamic, samples: opts.samples };
  const n = values.length;
  const P = normPlatform(platform);

  const finish = (text, form, place, why, caveats, exact, extra = {}) => {
    lintOrThrow(l, text, place);
    return { text, form, place, why: `${why}; ${NULL_NOTE[l]}`, caveats, count: n, values, exact, field, container: container == null ? "" : String(container), platform: P, apply: { text, form: place, field, mode: "append", platform: P, trace: { origin: "exclusion", container: container == null ? "" : String(container) } }, ...extra };
  };

  // The literal form: exact, one of not, not_in, chain or where.
  let literal;
  const starred = l === "spl" && values.some((v) => v.includes("*"));
  if (starred) {
    const E = splEvalField(field);
    literal = finish(`| where isnull(${E}) OR NOT in(${E}, ${spl.quoteList(values)})`, "where", "stage", `${n === 1 ? "the value holds" : "a value holds"} *, which a search term reads as a wildcard: in() compares the whole string`, ["runs after the scan, so every event in the range is read: keep the terms before the pipe narrow", "case-sensitive, unlike a search term"], true);
  } else if (n === 1) {
    const r = termRung(rungs({ values }, { platform: l, ...o }), "literal");
    literal = finish(negate(l, r.text), "not", "term", `one value: its own ${l === "spl" ? "NOT term" : "negated comparison"}${ci && l === "kql" ? " (=~, case-insensitive)" : ""}`, [], true);
  } else if (n <= threshold) {
    const r = termRung(rungs({ values }, { platform: l, ...o }), "in");
    literal = finish(negate(l, r.text), "not_in", "term", `${n} values in one ${l === "spl" ? "NOT IN term, read from the index like the terms around it" : `negated in${ci ? "~" : ""} predicate`}`, [], true);
  } else {
    const parts = values.map((v) => negate(l, termRung(rungs({ values: [v] }, { platform: l, ...o }), "literal").text));
    literal = finish(parts.join(l === "spl" ? " " : " and "), "chain", "term", `${n} values, past the ${threshold}-value bound for one in list and no shared pattern: one negated term per value`, ["long: prune the set, or mark values that share a path so they fold"], true);
  }

  // The fold: wider than the values, so it is offered on its own terms.
  let wild = null;
  if (opts.fold !== false && n >= 2) {
    const f = foldRung(l, values, o);
    if (f) {
      const r = f.rung;
      wild = finish(negate(l, r.text, r.construct), "wildcard", "term", `${n} values fold to one pattern, ${f.opened} piece${f.opened === 1 ? "" : "s"} opened: ${r.construct === "trailing_wildcard" ? "a trailing wildcard, the kept prefix still narrows the scan" : "a wildcard inside the value, the kept text still narrows the scan"}`, [`wider than the ${n} marked values: anything matching the pattern is excluded${Array.isArray(opts.samples) ? "; no other sampled value matches it" : "; check it against the field's values first"}`, ...r.caveats], false);
    }
  }

  const preferFold = wild && (opts.fold === true || (opts.fold !== false && n > threshold));
  if (preferFold) {
    wild.alternative = strip(literal);
    return wild;
  }
  if (wild) literal.alternative = strip(wild);
  return literal;
}

function strip(ex) {
  const { alternative, ...rest } = ex;
  return rest;
}

export default { KEY, VERSION, MAX_BYTES, THRESHOLD, MAX_VALUE, BenignError, load, list, get, add, remove, expire, purge, prune, subscribe, bytes, exportJSON, importJSON, attach, exclusion, foldSpec, sanitizeEntry, keyOf, isExpired, normPlatform };
