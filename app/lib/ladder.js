// The construct ladder: given a field, a value cut into segments with a
// state per segment (keep, any, like) and, when known, the field's
// efficiency class, emit every construct that says the same thing on the
// target platform, cheapest first, each with the one-line reason it sits
// where it does. The UI shows the ladder and inserts a rung; the benign
// cache wraps a rung in NOT; the advisor names a rung in a fix.
//
//   build(spec, { platform, field, fieldClass?, samples?, ci?, dynamic? }) -> [Rung]
//   specFor(value, states?, shape?)   -> a spec: segments.segment() plus a state per segment
//   lintable(rung)                    -> the text spl.lint or kql.lint was run on
//   COSTS, ORDER, MAJOR_BREAKERS, TERM_BARE, LINT_COMMANDS
//
// spec is one of:
//   a string                          the value itself, every segment kept
//   { segments: [{ text, kind, sep, state? }], tail?, shape?, detail?, truncated?, states? }
//                                     segments.segment() output with a state per segment, given
//                                     either on the segment or as a parallel states array
//   { values: [string] }              a literal set (one value is a literal, more are an IN list)
// state is keep (the text as it is), any (anything at all in its place, including
// nothing) or like (the same kind of thing: digits for digits, one path segment
// for a directory, four hex digits for a GUID group; segments.KINDS holds the
// class). anything and like_this are accepted as aliases.
//
// Rung: { construct, platform, text, form, cost, why, caveats, exact, pattern, preview }
//   construct  term | literal | trailing_wildcard | cidr | in | wildcard | like | regex | rex
//   form       term: goes in the search block (SPL) or after | where (KQL)
//              stage: a whole pipeline stage starting with |
//   why        one line: what makes this rung cost what it costs
//   caveats    lines a person should read before inserting it
//   exact      the rung matches exactly the values the spec describes; has (KQL) is the
//              one rung that is wider, and says so
//   pattern    the JavaScript regex source the offline preview used, or null (in, cidr)
//   preview    { matched, total, hits } over samples [{ value, count }] as shapes.classify
//              counts them: total is the count sum, matched the count sum of matching
//              values, hits the number of distinct values matched; null without samples
//
// Rungs by platform (cost in COSTS; sort is cost then ORDER, so it is stable):
//   SPL   TERM(v) field="v" (term)  ->  field="v" (literal)  ->  field="prefix*" (trailing_wildcard)
//         ->  field="10.0.0.0/16" (cidr)  ->  field IN (...) (in)  ->  field="a*b" (wildcard)
//         ->  | where like(lower(field), "%suffix") (like)  ->  | regex field="(?i)^...$" (regex)
//         ->  | rex field=field "^...(?<name>...)$" (rex)
//   KQL   field == "v" (literal; =~ when case-insensitive)  ->  field has "term" (term, wider)
//         ->  field startswith "prefix" (trailing_wildcard)  ->  endswith / contains (like)
//         ->  startswith and endswith and strlen (wildcard)  ->  ipv4_is_in_range(...) (cidr)
//         ->  field in (...) (in; in~ when case-insensitive)  ->  field matches regex "^...$" (regex)
//         ->  | extend name = extract("^...$", 1, field) (rex)
// Every rung has a form on both platforms; a rung the spec cannot reach on a
// platform is simply absent (SPL has no has; a like state reaches only regex and rex).
//
// A leading wildcard is never emitted as a search term: a spec that opens
// its first segment falls to like (SPL where like(), KQL endswith or
// contains) and regex, each carrying the caveat that the index cannot help.
// A value that itself contains * is compared in a where stage, since a
// search term would read the star as a wildcard; a where like() is skipped
// when the kept text holds % or _, which like() cannot escape.
//
// TERM() is emitted only when fieldClass is raw_token or indexed and the
// whole value is one indexed token: no major breaker (MAJOR_BREAKERS, the
// segmenters.conf default), no star, and only characters that can stand
// bare inside TERM() (TERM_BARE: letters, digits and the minor breakers
// . - _ : / @ # $ %). A backslash or a quote is left out on purpose: the
// search parser reads a bare backslash as an escape and a quoted TERM
// argument is not documented, so a Windows path takes the literal rung.
// The KQL counterpart, has, needs no class: Kusto indexes every string
// column's terms (of four characters or more; shorter ones are scanned).
//
// Case: SPL search terms are case-insensitive, so the SPL where and regex
// rungs lower() the field and set (?i) to match the same events the search
// term would. KQL == and in are case-sensitive; the ladder emits =~ and in~
// and (?i) when ci is true, which defaults to true for a Windows path,
// registry key or Windows command line and false otherwise. KQL startswith,
// endswith, contains and has are case-insensitive by definition.
//
// Quoting: spl.quote and kql.quote on every value; a regex source is
// escaped first (metacharacters, backslashes), then quoted, so a literal
// backslash reaches the engine as \\ and appears in the text as four. The
// IN list is quoted item by item here; it moves onto spl.quoteList and
// kql.quoteList once those land. Every rung is linted before it is
// returned: SPL through spl.lint with LINT_COMMANDS added (regex and rex
// are Splunk Cloud safe but not on the pivot allowlist), KQL through
// kql.lint; a fragment is wrapped for the check (lintable) since neither
// linter accepts a bare term.
//
// A truncated spec (the stored value was cut at 200 characters) is matched
// as a prefix: the literal rung is withheld and the trailing wildcard
// carries the reason. No DOM, no store, no network.

import { segment, KINDS } from "./segments.js";
import * as spl from "./spl.js";
import * as kql from "./kql.js";
import { LANG } from "./lang.js";

export class LadderError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "LadderError";
    this.code = code;
  }
}

export const ORDER = Object.freeze(["term", "literal", "trailing_wildcard", "cidr", "in", "wildcard", "like", "regex", "rex"]);

export const COSTS = Object.freeze({
  spl: Object.freeze({ term: 0, literal: 1, trailing_wildcard: 2, cidr: 3, in: 3, wildcard: 4, like: 5, regex: 6, rex: 7 }),
  kql: Object.freeze({ literal: 1, term: 2, trailing_wildcard: 3, like: 3, wildcard: 3, cidr: 3, in: 4, regex: 6, rex: 7 }),
});

// Splunk's default major breakers (segmenters.conf): a value holding one is
// more than one indexed token, so TERM() cannot name it.
export const MAJOR_BREAKERS = /[\s[\]<>(){}|!;,'"*&?+]|--|%(?:21|26|2526|3B|7C|20|2B|3D|2520|5D|5B|3A|0A|2C|28|29)/i;

// Commands the ladder emits that spl.lint's pivot allowlist does not carry.
export const LINT_COMMANDS = Object.freeze(["regex", "rex"]);

// What can stand bare inside TERM(): letters, digits and the minor breakers.
export const TERM_BARE = /^[A-Za-z0-9._:/@#$%-]+$/;

const STATES = { keep: "keep", any: "any", like: "like", anything: "any", like_this: "like" };
const SPL_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_.{}]*$/;
const SPL_PLAIN_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const KUSTO_TERM_RE = /^[A-Za-z0-9]+$/;

// ---------------------------------------------------------------------------
// Spec

export function specFor(value, states, shape) {
  const s = segment(value, shape);
  s.segments = s.segments.map((g, i) => ({ ...g, state: normState(states ? states[i] : "keep") }));
  return s;
}

function normState(s) {
  if (s === undefined || s === null || s === "") return "keep";
  const got = STATES[String(s)];
  if (!got) throw new LadderError("bad_state", `unknown segment state: ${String(s)} (keep, any or like)`);
  return got;
}

function normSpec(spec) {
  if (typeof spec === "string") return { kind: "pattern", ...specFor(spec) };
  if (!spec || typeof spec !== "object") throw new LadderError("bad_spec", "build takes a value, a segment spec or a literal set");
  if (Array.isArray(spec.values)) {
    const values = spec.values.map((v) => String(v == null ? "" : v)).filter((v) => v !== "");
    if (!values.length) throw new LadderError("bad_spec", "a literal set needs at least one value");
    return { kind: "set", values: Array.from(new Set(values)) };
  }
  if (!Array.isArray(spec.segments)) throw new LadderError("bad_spec", "a segment spec needs segments");
  const segments = spec.segments.map((g, i) => {
    if (!g || typeof g.text !== "string") throw new LadderError("bad_spec", `segment ${i} needs text`);
    return { text: g.text, kind: g.kind || "word", sep: g.sep || "", quoted: Boolean(g.quoted), state: normState(g.state !== undefined ? g.state : spec.states ? spec.states[i] : "keep") };
  });
  return { kind: "pattern", shape: spec.shape || null, detail: spec.detail || null, segments, tail: spec.tail || "", truncated: Boolean(spec.truncated) };
}

// ---------------------------------------------------------------------------
// Pattern parts: [{ lit } | { any } | { like: kind, cls }], adjacent
// literals merged, adjacent anys collapsed.

function likeClass(g) {
  if (g.quoted) return '[^"]*';
  if (g.kind === "hex" && g.text) return `[0-9a-fA-F]{${g.text.length}}`;
  if (g.kind === "account" && g.text) return "\\d{12}";
  return KINDS[g.kind] || "[^\\s]+";
}

function partsOf(p) {
  const parts = [];
  const lit = (t) => {
    if (!t) return;
    const last = parts[parts.length - 1];
    if (last && last.lit !== undefined) last.lit += t;
    else parts.push({ lit: t });
  };
  let prevAny = false;
  for (const g of p.segments) {
    // A run of open segments is one opening: the separators inside the run
    // are absorbed (any basename and any extension is *, not *.*), the one
    // before the run is kept.
    if (!(prevAny && g.state === "any")) lit(g.sep);
    if (g.state === "keep") lit(g.text);
    else if (g.state === "any") {
      if (!prevAny) parts.push({ any: true });
    } else parts.push({ like: g.kind, cls: likeClass(g) });
    prevAny = g.state === "any";
  }
  lit(p.tail);
  if (p.truncated) {
    const last = parts[parts.length - 1];
    if (!(last && last.any)) parts.push({ any: true });
  }
  return parts;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// groups: "none" (a filter), "named" ((?<name>...) for Splunk rex) or
// "numbered" (plain parentheses, 1..n, for KQL extract()).
function regexOf(parts, groups = "none") {
  let n = 0;
  const src = parts.map((p) => {
    if (p.lit !== undefined) return escapeRegex(p.lit);
    n += 1;
    const body = p.any ? ".*" : p.cls;
    if (groups === "named") return `(?<${captureName(p, n)}>${body})`;
    if (groups === "numbered") return `(${body})`;
    return body;
  });
  return `^${src.join("")}$`;
}

function captureName(p, n) {
  return `${p.any ? "any" : p.like}_${n}`;
}

function captures(parts) {
  const out = [];
  let n = 0;
  for (const p of parts) if (p.lit === undefined) out.push(captureName(p, ++n));
  return out;
}

// ---------------------------------------------------------------------------
// Field rendering

function splField(field) {
  const s = String(field == null ? "" : field).trim();
  if (!SPL_FIELD_RE.test(s)) throw new LadderError("bad_field", `not a valid Splunk field name: ${s || "(empty)"}`);
  return s;
}

function splEvalField(field) {
  const s = splField(field);
  return SPL_PLAIN_RE.test(s) ? s : `'${s}'`;
}

function kqlField(field, dynamic) {
  let col;
  try {
    col = kql.column(field);
  } catch (e) {
    throw new LadderError("bad_field", e.message);
  }
  const [head, ...rest] = col.split(".");
  const expr = rest.reduce((acc, seg) => (seg.includes("-") ? `${acc}["${seg}"]` : `${acc}.${seg}`), head);
  return dynamic || rest.length ? `tostring(${expr})` : expr;
}

// ---------------------------------------------------------------------------
// Offline preview

function previewOf(test, samples) {
  if (!Array.isArray(samples)) return null;
  const list = samples.filter((v) => v && v.value !== undefined && v.value !== null && String(v.value) !== "");
  let total = 0;
  let matched = 0;
  let hits = 0;
  for (const v of list) {
    const w = Number.isFinite(Number(v.count)) ? Number(v.count) : 1;
    total += w;
    if (test(String(v.value))) {
      matched += w;
      hits += 1;
    }
  }
  return { matched, total, hits };
}

function regexTest(source, ci) {
  const re = new RegExp(source, ci ? "i" : "");
  return (v) => re.test(v);
}

function v4ToInt(s) {
  const o = s.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

function v6Groups(s) {
  const zone = s.indexOf("%");
  const bare = (zone >= 0 ? s.slice(0, zone) : s).replace(/^\[|\]$/g, "");
  if (!bare.includes(":")) return null;
  const halves = bare.split("::");
  if (halves.length > 2) return null;
  const expand = (h) => (h === "" ? [] : h.split(":").map((g) => (/^[0-9a-fA-F]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const left = expand(halves[0]);
  const right = halves.length === 2 ? expand(halves[1]) : [];
  if ([...left, ...right].some(Number.isNaN)) return null;
  const fill = 8 - left.length - right.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  return [...left, ...new Array(fill).fill(0), ...right];
}

// A sample carrying its own /prefix is tested by its address, as Kusto's
// ipv4_is_in_range reads a masked address.
function cidrTest(addr, bits, detail) {
  if (detail === "v4") {
    const base = v4ToInt(addr);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (v) => {
      const n = v4ToInt(v.split("/")[0]);
      return n !== null && ((n & mask) >>> 0) === ((base & mask) >>> 0);
    };
  }
  const base = v6Groups(addr);
  return (v) => {
    const g = v6Groups(v.split("/")[0]);
    if (!g || !base) return false;
    let left = bits;
    for (let i = 0; i < 8 && left > 0; i++) {
      const take = Math.min(16, left);
      const mask = ((0xffff << (16 - take)) & 0xffff) >>> 0;
      if ((g[i] & mask) !== (base[i] & mask)) return false;
      left -= take;
    }
    return true;
  };
}

// ---------------------------------------------------------------------------
// Lint

// A rung as a whole query the platform's lint can read: a term after the
// search command, a stage after a scan.
const LINTABLE = {
  spl: { term: (t) => `search ${t}`, stage: (t) => `search * ${t}` },
  kql: { term: (t) => `Table | where ${t}`, stage: (t) => `Table ${t}` },
};

export function lintable(rung) {
  const forms = LINTABLE[rung.platform];
  return (forms[rung.form] || forms.term)(rung.text);
}

function checked(rung) {
  const text = lintable(rung);
  const verdict = LANG[rung.platform].lint(text, { commands: LINT_COMMANDS });
  if (!verdict.ok) throw new LadderError("lint", `${rung.construct} (${rung.platform}) failed lint: ${verdict.violations.join("; ")}: ${rung.text}`);
  return rung;
}

// ---------------------------------------------------------------------------
// Build

function defaultCi(p) {
  if (p.kind !== "pattern") return false;
  if (p.shape === "path") return p.detail === "windows" || p.detail === "unc" || p.detail === "registry";
  if (p.shape === "cmdline") return p.segments.some((g) => g.kind === "drive") || p.segments.some((g) => g.text.includes("\\") || g.sep.includes("\\"));
  return false;
}

function classWhy(fieldClass) {
  switch (fieldClass) {
    case "indexed": return "exact match on an indexed field: answered from the index alone";
    case "raw_token": return "exact match; the value is a raw token, so the index narrows the scan before the field is read";
    case "calculated": return "exact match on a calculated field: every event in the range is evaluated, the index cannot narrow on the value";
    case "lookup_output": return "exact match on a lookup output: the lookup runs on every event in the range first";
    case "pipeline_derived": return "the field exists only after the stage that derives it, so this is a | search stage, not a term";
    default: return "exact match; Splunk narrows the scan with the value's own tokens before extracting the field";
  }
}

// One rung, sorted later. preview and lint are applied by finish().
function rung(platform, construct, text, form, why, extra) {
  return { construct, platform, text, form, cost: COSTS[platform][construct], why, caveats: [], exact: true, pattern: null, preview: null, test: null, ...extra };
}

function buildSpl(p, o) {
  const F = splField(o.field);
  const E = splEvalField(o.field);
  const out = [];
  const stageOnly = o.fieldClass === "pipeline_derived";
  const asTerm = (r) => {
    if (!stageOnly) return r;
    r.text = `| search ${r.text}`;
    r.form = "stage";
    return r;
  };
  if (p.kind === "set") {
    const vals = p.values;
    if (vals.length === 1) {
      out.push(...literalRungs("spl", vals[0], { F, E, o, asTerm }));
    } else {
      const star = vals.some((v) => v.includes("*"));
      const r = rung("spl", "in", `${F} IN (${vals.map((v) => spl.quote(v)).join(", ")})`, "term", `one term with ${vals.length} values: cheaper than ${vals.length} ORed terms and read from the index the same way`);
      if (star) r.caveats.push("a value holds *, which a search term reads as a wildcard");
      r.test = (v) => vals.some((x) => x.toLowerCase() === v.toLowerCase());
      out.push(asTerm(r));
    }
    return out;
  }
  const parts = partsOf(p);
  const allKeep = parts.every((x) => x.lit !== undefined);
  const value = allKeep ? parts.map((x) => x.lit).join("") : null;
  if (allKeep) {
    const rungs = literalRungs("spl", value, { F, E, o, asTerm });
    const cidr = cidrOf(p);
    if (cidr) {
      for (const r of rungs) {
        if (r.construct !== "literal") continue;
        r.why = "the value is a CIDR block: the search command reads it as a range on an IP field";
        r.caveats.push(`the eval form is | where cidrmatch(${spl.quote(value)}, ${E})`);
        r.test = cidrTest(cidr.addr, cidr.bits, cidr.detail);
      }
    }
    out.push(...rungs);
    return out;
  }
  const hasLike = parts.some((x) => x.like);
  const leading = parts[0].lit === undefined;
  const lits = parts.filter((x) => x.lit !== undefined).map((x) => x.lit);
  const star = lits.some((l) => l.includes("*"));
  const src = regexOf(parts);
  const test = regexTest(src, true);
  if (!hasLike && !leading && !star) {
    const wild = parts.map((x) => (x.lit !== undefined ? x.lit : "*")).join("");
    const trailing = parts.length === 2 && parts[1].any;
    if (trailing) {
      const r = rung("spl", "trailing_wildcard", `${F}=${spl.quote(wild)}`, "term", p.truncated ? "the stored value was cut at 200 characters, so it is matched as a prefix: a trailing wildcard" : "prefix kept, the rest open: a trailing wildcard still narrows from the index on the leading text");
      r.pattern = src;
      r.test = test;
      out.push(asTerm(r));
    } else {
      const r = rung("spl", "wildcard", `${F}=${spl.quote(wild)}`, "term", "a wildcard inside the value: the index narrows on the text before it only, the rest is checked per event");
      r.pattern = src;
      r.test = test;
      out.push(asTerm(r));
    }
  }
  const cidr = cidrOf(p);
  if (cidr) {
    const r = rung("spl", "cidr", `${F}=${spl.quote(`${cidr.addr}/${cidr.bits}`)}`, "term", `the kept ${cidr.detail === "v4" ? "octets" : "groups"} form a network: a CIDR range match on the field`);
    r.caveats.push(`the search command matches CIDR on an IP field; the eval form is | where cidrmatch(${spl.quote(`${cidr.addr}/${cidr.bits}`)}, ${E})`);
    r.test = cidrTest(cidr.addr, cidr.bits, cidr.detail);
    out.push(asTerm(r));
  }
  if (!hasLike && leading && !lits.some((l) => /[%_]/.test(l))) {
    const pat = parts.map((x) => (x.lit !== undefined ? x.lit : "%")).join("").toLowerCase();
    const r = rung("spl", "like", `| where like(lower(${E}), ${spl.quote(pat)})`, "stage", "leading wildcard avoided in the search term: like() runs after the scan, so every event in the range is read");
    r.caveats.push("no index help: add a term the index can use (a file name, a host) before the pipe");
    r.pattern = src;
    r.test = test;
    out.push(r);
  }
  {
    const r = rung("spl", "regex", `| regex ${F}=${spl.quote(`(?i)${src}`)}`, "stage", hasLike ? "a segment kind (digits, one path segment, hex) needs a character class: only a regex says that" : leading ? "leading wildcard avoided in the search term: the regex runs after the scan, so every event in the range is read" : star ? "the value holds *, which a search term reads as a wildcard: the regex matches it literally" : "the same pattern as a regex: exact, evaluated per event after the scan");
    if (leading) r.caveats.push("no index help: add a term the index can use before the pipe");
    r.pattern = src;
    r.test = test;
    out.push(r);
  }
  {
    const named = regexOf(parts, "named");
    const r = rung("spl", "rex", `| rex field=${F} ${spl.quote(`(?i)${named}`)}`, "stage", `captures the open segments (${captures(parts).join(", ")}) into fields for stats: a regex per event, the costliest rung`);
    r.caveats.push("rex extracts, it does not filter: add | where isnotnull(...) or the regex rung to keep only matches");
    r.pattern = src;
    r.test = test;
    out.push(r);
  }
  return out;
}

// The literal, term and where-literal rungs for one whole value.
function literalRungs(platform, value, { F, E, o, asTerm, ci }) {
  const out = [];
  const star = value.includes("*");
  if (platform === "spl") {
    const test = (v) => v.toLowerCase() === value.toLowerCase();
    if (termable(value, o.fieldClass)) {
      const r = rung("spl", "term", `TERM(${value}) ${F}=${spl.quote(value)}`, "term", o.fieldClass === "indexed" ? "the value is one indexed token: TERM() reads it from the lexicon whole, the field test confirms it" : "the value is one raw token: TERM() reads it from the lexicon without recombining minor breakers, the field test confirms it");
      r.test = test;
      out.push(asTerm(r));
    }
    if (star) {
      const r = rung("spl", "literal", `| where ${E}=${spl.quote(value)}`, "stage", "the value holds *, which a search term reads as a wildcard: where compares the whole string");
      r.caveats.push("where = is case-sensitive, unlike a search term");
      r.test = (v) => v === value;
      out.push(r);
    } else {
      const r = rung("spl", "literal", `${F}=${spl.quote(value)}`, "term", classWhy(o.fieldClass));
      r.test = test;
      out.push(asTerm(r));
    }
    return out;
  }
  const opEq = ci ? "=~" : "==";
  const r = rung("kql", "literal", `${F} ${opEq} ${kql.quote(value)}`, "term", ci ? "case-insensitive exact match: =~, since this value compares that way on its platform" : "exact, case-sensitive: the fastest string predicate, answered from the term index");
  r.test = ci ? (v) => v.toLowerCase() === value.toLowerCase() : (v) => v === value;
  out.push(r);
  return out;
}

function termable(value, fieldClass) {
  return (fieldClass === "raw_token" || fieldClass === "indexed") && TERM_BARE.test(value) && !MAJOR_BREAKERS.test(value);
}

// A CIDR from an ip spec: kept address segments, then open ones, no zone,
// no compression for v6 (group positions would be ambiguous); or a kept
// cidr segment on a value that already carries one.
function cidrOf(p) {
  if (p.kind !== "pattern" || p.shape !== "ip") return null;
  const segs = p.segments;
  if (segs.some((g) => g.kind === "zone")) return null;
  const cidrSeg = segs.find((g) => g.kind === "cidr");
  const addrSegs = segs.filter((g) => g.kind === "octet" || g.kind === "group");
  const width = p.detail === "v4" ? 8 : 16;
  if (cidrSeg) {
    if (!segs.every((g) => g.state === "keep")) return null;
    return { addr: addrSegs.map((g, i) => (i ? g.sep : "") + g.text).join(""), bits: Number(cidrSeg.text), detail: p.detail };
  }
  if (p.detail === "v6" && (addrSegs.length !== 8 || addrSegs.some((g) => g.text === ""))) return null;
  if (p.detail === "v4" && addrSegs.length !== 4) return null;
  let kept = 0;
  while (kept < addrSegs.length && addrSegs[kept].state === "keep") kept++;
  if (kept === 0 || kept === addrSegs.length) return null;
  if (addrSegs.slice(kept).some((g) => g.state === "keep")) return null;
  const addr = addrSegs.map((g, i) => (i ? g.sep : "") + (i < kept ? g.text : "0")).join("");
  return { addr, bits: kept * width, detail: p.detail };
}

function cidrRung(F, cidr) {
  const fn = cidr.detail === "v4" ? "ipv4_is_in_range" : "ipv6_is_in_range";
  const r = rung("kql", "cidr", `${fn}(${F}, ${kql.quote(`${cidr.addr}/${cidr.bits}`)})`, "term", `the kept ${cidr.detail === "v4" ? "octets" : "groups"} form a network: ${fn} tests the address against the range`);
  r.caveats.push("the column must hold plain addresses; a value with a port or brackets does not match");
  r.test = cidrTest(cidr.addr, cidr.bits, cidr.detail);
  return r;
}

function buildKql(p, o) {
  const F = kqlField(o.field, o.dynamic);
  const ci = o.ci;
  const out = [];
  if (p.kind === "set") {
    const vals = p.values;
    if (vals.length === 1) return literalRungs("kql", vals[0], { F, o, ci });
    const r = rung("kql", "in", `${F} ${ci ? "in~" : "in"} (${vals.map((v) => kql.quote(v)).join(", ")})`, "term", `one predicate with ${vals.length} values${ci ? ", case-insensitive (in~)" : ""}: cheaper than ${vals.length} ORed comparisons`);
    r.test = ci ? (v) => vals.some((x) => x.toLowerCase() === v.toLowerCase()) : (v) => vals.includes(v);
    out.push(r);
    return out;
  }
  const parts = partsOf(p);
  const allKeep = parts.every((x) => x.lit !== undefined);
  if (allKeep) {
    const rungs = literalRungs("kql", parts.map((x) => x.lit).join(""), { F, o, ci });
    const cidr = cidrOf(p);
    if (cidr) {
      for (const r of rungs) r.caveats.push("== compares the text of the block; the cidr rung tests addresses against it");
      rungs.push(cidrRung(F, cidr));
    }
    return rungs;
  }
  const hasLike = parts.some((x) => x.like);
  const src = regexOf(parts);
  const test = regexTest(src, ci);
  const shapeIs = (...kinds) => parts.length === kinds.length && kinds.every((k, i) => (k === "lit" ? parts[i].lit !== undefined : Boolean(parts[i].any)));
  if (!hasLike) {
    if (shapeIs("lit", "any")) {
      const r = rung("kql", "trailing_wildcard", `${F} startswith ${kql.quote(parts[0].lit)}`, "term", p.truncated ? "the stored value was cut at 200 characters, so it is matched as a prefix: startswith" : "prefix kept, the rest open: startswith, KQL's form of a trailing wildcard (case-insensitive)");
      r.pattern = src;
      r.test = regexTest(src, true);
      out.push(r);
    } else if (shapeIs("any", "lit")) {
      const r = rung("kql", "like", `${F} endswith ${kql.quote(parts[1].lit)}`, "term", "leading part open: endswith scans the column, it cannot use the term index (case-insensitive)");
      r.caveats.push("no index help: put a has or == predicate on another column first when there is one");
      r.pattern = src;
      r.test = regexTest(src, true);
      out.push(r);
    } else if (shapeIs("any", "lit", "any")) {
      const r = rung("kql", "like", `${F} contains ${kql.quote(parts[1].lit)}`, "term", "both ends open: contains scans the column for the kept text (case-insensitive)");
      r.caveats.push("no index help: has is cheaper when the kept text is one whole term");
      r.pattern = src;
      r.test = regexTest(src, true);
      out.push(r);
      const kept = p.segments.filter((g) => g.state === "keep");
      if (kept.length === 1 && KUSTO_TERM_RE.test(kept[0].text)) {
        const t = kept[0].text;
        const h = rung("kql", "term", `${F} has ${kql.quote(t)}`, "term", t.length >= 4 ? "one whole term kept: has reads the term index, the cheapest way to find text inside a column" : "one whole term kept: has; under four characters the term is not indexed, so the column is scanned");
        h.exact = false;
        h.caveats.push(`has matches the term at any non-alphanumeric boundary, not only between ${JSON.stringify(kept[0].sep)} and what follows: wider than contains, which keeps the exact separators`);
        const bre = new RegExp(`(^|[^A-Za-z0-9])${escapeRegex(t)}([^A-Za-z0-9]|$)`, "i");
        h.pattern = bre.source;
        h.test = (v) => bre.test(v);
        out.push(h);
      }
    } else if (shapeIs("lit", "any", "lit")) {
      const a = parts[0].lit;
      const b = parts[2].lit;
      const r = rung("kql", "wildcard", `${F} startswith ${kql.quote(a)} and ${F} endswith ${kql.quote(b)} and strlen(${F}) >= ${a.length + b.length}`, "term", "kept at both ends, open between: startswith and endswith, with strlen so the two cannot overlap (case-insensitive)");
      r.pattern = src;
      r.test = regexTest(src, true);
      out.push(r);
    }
  }
  const cidr = cidrOf(p);
  if (cidr) out.push(cidrRung(F, cidr));
  {
    const r = rung("kql", "regex", `${F} matches regex ${kql.quote(`${ci ? "(?i)" : ""}${src}`)}`, "term", hasLike ? "a segment kind (digits, one path segment, hex) needs a character class: only a regex says that" : "the same pattern as a regex: exact, evaluated per row, no index help");
    r.pattern = src;
    r.test = test;
    out.push(r);
  }
  {
    const names = captures(parts);
    const body = `${ci ? "(?i)" : ""}${regexOf(parts, "numbered")}`;
    const r = rung("kql", "rex", `| extend ${names.map((n, i) => `${n} = extract(${kql.quote(body)}, ${i + 1}, ${F})`).join(", ")}`, "stage", `captures the open segments (${names.join(", ")}) into columns for summarize: a regex per row, the costliest rung`);
    r.caveats.push("extend extracts, it does not filter: add | where isnotempty(...) or the regex rung to keep only matches");
    r.pattern = src;
    r.test = test;
    out.push(r);
  }
  return out;
}

export function build(spec, opts = {}) {
  const platform = opts.platform === "kql" || opts.platform === "sentinel" ? "kql" : opts.platform === "spl" || opts.platform === "splunk" ? "spl" : null;
  if (!platform) throw new LadderError("bad_platform", `platform must be spl or kql, not ${String(opts.platform)}`);
  if (!opts.field) throw new LadderError("bad_field", "build needs a field");
  const p = normSpec(spec);
  const o = { ...opts, ci: opts.ci === undefined ? defaultCi(p) : Boolean(opts.ci) };
  const rungs = platform === "spl" ? buildSpl(p, o) : buildKql(p, o);
  for (const r of rungs) {
    r.preview = r.test ? previewOf(r.test, opts.samples) : null;
    delete r.test;
    checked(r);
  }
  rungs.sort((a, b) => a.cost - b.cost || ORDER.indexOf(a.construct) - ORDER.indexOf(b.construct));
  return rungs;
}

export default { build, specFor, lintable, COSTS, ORDER, MAJOR_BREAKERS, TERM_BARE, LINT_COMMANDS, LadderError };
