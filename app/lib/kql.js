// KQL text primitives, the twin of spl.js: the string literal, the list
// literal, identifiers and columns, the time literal, the shape lint, the
// reserved-word bracket, and which tables a query reads. Every module that
// writes KQL (pivot.js, compile-kql.js, ladder.js, recipe.js) quotes and
// lints through here; a value is never interpolated raw.
//
//   quote(value)             "…" with the four KQL escapes
//   quoteList(values)        the inside of an in (...) term
//   ident(name), table(name), column(path)
//   timeLiteral(value)       -24h → ago(24h), now → now(), an ISO stamp → datetime(...)
//   windowSpan(value)        1d, 7d, 12h for a recipe window
//   lint(kql, opts?)         → { ok, violations, warnings }
//   isReserved(name), bracket(name), tablesIn(text)
//
// The discovery recipe's queries and envelope live in recipe.js; the
// portal's Logs-blade deep link and workspace ids are at the end of this
// file. Reach never runs any of this. The user does, in the portal.
//
// No DOM. Safe from a content script and under node.

export class KqlError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "KqlError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Literals and identifiers

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
// A column, or a path into a dynamic column: UserIdentity.type
const COLUMN_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$/;

export function ident(name, what = "identifier") {
  const s = String(name == null ? "" : name).trim();
  if (!IDENT_RE.test(s)) throw new KqlError("bad_identifier", `${what} is not a valid KQL identifier: ${s || "(empty)"}`);
  return s;
}

// A table name is an identifier; ['Table Name'] quoting is deliberately not
// supported: packs name tables, and every Log Analytics table is an identifier.
export function table(name) {
  return ident(name, "table");
}

export function column(path) {
  const s = String(path == null ? "" : path).trim();
  if (!COLUMN_RE.test(s)) throw new KqlError("bad_column", `not a valid column or dynamic path: ${s || "(empty)"}`);
  return s;
}

// A KQL string literal. Backslash escapes; the same four the language
// defines, so a value can never close the quote or start a comment.
export function quote(value) {
  const s = String(value == null ? "" : value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
  return `"${s}"`;
}

// A list of values as the inside of an in (...) term: each quoted as
// above, comma-separated. An empty list is refused: in () is a syntax
// error, and a caller that has nothing to list has nothing to search.
export function quoteList(values) {
  if (!Array.isArray(values) || !values.length) throw new KqlError("bad_list", "a list needs at least one value");
  return values.map(quote).join(", ");
}

const RELATIVE_RE = /^-?(\d+)([smhd])$/; // -24h, 7d, 30m: Splunk's shape and KQL's timespan shape both land here
const AGO_RE = /^ago\(\s*(\d+)([smhd])\s*\)$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?(?:Z|[+-]\d{2}:?\d{2})?$/;

// A point in time as a KQL expression: `-24h` → ago(24h), `now` → now(),
// `ago(7d)` as is, an ISO timestamp → datetime(...). Anything else is
// refused: a time parameter is never quoted into a string.
export function timeLiteral(value) {
  const s = String(value == null ? "" : value).trim();
  if (!s) throw new KqlError("bad_time", "a time is required");
  if (/^now(\(\))?$/i.test(s)) return "now()";
  let m = RELATIVE_RE.exec(s);
  if (m) return `ago(${m[1]}${m[2]})`;
  m = AGO_RE.exec(s);
  if (m) return `ago(${m[1]}${m[2]})`;
  if (ISO_RE.test(s)) return `datetime(${s})`;
  throw new KqlError("bad_time", `not a time: ${s} (use -24h, 7d, now, ago(1d) or an ISO timestamp)`);
}

// A window for the recipe queries: 1d, 7d, 30d, 12h.
export function windowSpan(value, fallback = "1d") {
  const s = String(value == null ? "" : value).trim().replace(/^-/, "") || fallback;
  const m = RELATIVE_RE.exec(s);
  if (!m) throw new KqlError("bad_window", `not a window: ${value}`);
  return `${m[1]}${m[2]}`;
}

// ---------------------------------------------------------------------------
// lint(): the hazards worth refusing in generated KQL. The Splunk allowlist
// does not apply (join is first-class here), so this checks shape:
// something to query, balanced quotes and brackets, no unbounded scan.
// opts is the same slot spl.lint takes; no option changes the verdict here.

const UNBOUNDED_RE = /(^|\|)\s*(search|union)\s+\*(\s|$)/;
const TIME_RE = /\b(TimeGenerated|ago\(|datetime\(|between\s*\(|now\(\))/;

// `name =` outside quotes and brackets, not `==`, `=~`, `!=`, `<=`, `>=`.
const ALIAS_RE = /(?<![\w'\]])([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])/g;

export function lint(text, opts = {}) {
  const violations = [];
  const warnings = [];
  const s = String(text || "").trim();
  if (!s) return { ok: false, violations: ["empty query"], warnings };
  if (s.startsWith("|")) violations.push("query starts with a pipe: nothing to query");
  if (UNBOUNDED_RE.test(s)) violations.push("unbounded search * / union * over the whole workspace");
  let inQ = false;
  let depth = 0;
  let square = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQ) {
      if (ch === "\\") { i++; continue; }
      if (ch === '"') inQ = false;
      continue;
    }
    if (ch === '"') inQ = true;
    else if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "[") square++;
    else if (ch === "]") square--;
    else if (ch === "/" && s[i + 1] === "/") { // line comment
      const nl = s.indexOf("\n", i);
      i = nl < 0 ? s.length : nl;
    }
    if (depth < 0 || square < 0) break;
  }
  if (inQ) violations.push("unterminated string literal");
  if (depth !== 0) violations.push("unbalanced parentheses");
  if (square !== 0) violations.push("unbalanced brackets");
  if (!TIME_RE.test(s)) warnings.push("no time predicate: the portal's time picker decides the window");
  // A reserved word used bare as a summarize/extend/project alias is a
  // syntax error on the platform (`last = max(TimeGenerated)`); the
  // bracketed form ['last'] is fine and does not match here.
  const unquoted = s.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  for (const m of unquoted.matchAll(ALIAS_RE)) {
    if (isReserved(m[1])) violations.push(`reserved word used as a name: ${m[1]} (write ['${m[1]}'] or pick another alias)`);
  }
  return { ok: violations.length === 0, violations, warnings };
}

// ---------------------------------------------------------------------------
// Which tables a query reads. For the content script: the table name opens
// every query, `union` names several, `let` binds one. Used when a row has
// no Type column to read; a heuristic, not a parser.

const KEYWORDS = new Set(["let", "union", "search", "find", "print", "range", "datatable", "externaldata", "materialize", "toscalar", "withsource", "kind", "isfuzzy", "in", "and", "or", "not", "true", "false", "where", "project", "extend", "summarize", "take", "limit", "top", "order", "sort", "by", "join", "on", "as", "evaluate", "invoke", "parse", "mv-expand", "distinct", "count", "getschema", "render", "set", "declare", "query_parameters", "restrict", "access", "to"]);

// Names Kusto will not take bare as a column or alias (`last = max(...)`
// is SYN0002 on the platform; verified live 2026-09-18). A superset of
// KEYWORDS: operator keywords plus the ones the parser reserves in name
// position. Bracketed as ['name'] they are legal; RESERVED lets the KQL
// emitter bracket and lint refuse the bare form.
export const RESERVED = new Set([...KEYWORDS, "first", "last", "earliest", "latest", "missing", "title", "null", "default", "asc", "desc", "nulls", "has", "contains", "startswith", "endswith", "matches", "regex", "between", "step", "from", "of", "with", "filter", "fork", "serialize", "consume", "lookup", "typeof"]);

export function isReserved(name) {
  return RESERVED.has(String(name || "").toLowerCase());
}

// A name safe in column or alias position: bracket-quoted when reserved.
export function bracket(name) {
  return isReserved(name) ? `['${name}']` : name;
}

export function tablesIn(text) {
  const out = [];
  const seen = new Set();
  const add = (name) => {
    if (!name || KEYWORDS.has(name.toLowerCase()) || !IDENT_RE.test(name) || seen.has(name)) return;
    seen.add(name);
    out.push(name);
  };
  const src = String(text || "").replace(/\/\/[^\n]*/g, " ").replace(/"(?:[^"\\]|\\.)*"/g, '""');
  // Statements: split on ";". Each one starts with a table unless it is a let.
  for (const stmt of src.split(";")) {
    const body = stmt.replace(/^\s*let\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*/, "").trim();
    if (!body) continue;
    const first = /^\(?\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(body);
    if (first && first[1].toLowerCase() !== "union") add(first[1]);
    // union A, B, (C | where …), withsource=T isfuzzy=true D
    for (const m of body.matchAll(/\bunion\b([^|]*)/gi)) {
      const args = m[1].replace(/\b(withsource|kind|isfuzzy)\s*=\s*[A-Za-z_][A-Za-z0-9_]*/g, " ");
      for (const t of args.matchAll(/\(?\s*([A-Za-z_][A-Za-z0-9_]*)/g)) add(t[1]);
    }
    // (Table | …) sub-expressions anywhere, e.g. inside union or join
    for (const m of body.matchAll(/\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|/g)) add(m[1]);
    // join Table on … / join (Table | …) on …
    for (const m of body.matchAll(/\bjoin\b(?:\s+kind\s*=\s*\w+)?(?:\s+hint\.\w+\s*=\s*\w+)*\s+\(?\s*([A-Za-z_][A-Za-z0-9_]*)/gi)) add(m[1]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The portal deep link (docs/SENTINEL.md §5.6): opens the Logs blade on a
// workspace with the query already run. gzip + base64 of the KQL, as the
// portal's own Share → Link does.

export const PORTAL = "https://portal.azure.com";

async function gzipBase64(text) {
  const bytes = new TextEncoder().encode(text);
  if (typeof CompressionStream === "function") {
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"));
    const buf = new Uint8Array(await new Response(stream).arrayBuffer());
    let bin = "";
    for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  // node without CompressionStream (older releases)
  const zlib = await import("node:zlib");
  return zlib.gzipSync(Buffer.from(bytes)).toString("base64");
}

export function isResourceId(id) {
  return /^\/subscriptions\/[0-9a-f-]{36}\/resourceGroups\/[^/]+\/providers\/Microsoft\.OperationalInsights\/workspaces\/[^/]+$/i.test(String(id || ""));
}

// The workspace named in a portal URL hash, whichever blade carries it:
//   #view/Microsoft_Azure_Monitoring_Logs/LogsBlade/resourceId/<enc>/…        the Logs deep link
//   #view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/8/id/<enc>          Sentinel's menu, Logs included
//   #@tenant/resource/subscriptions/…/workspaces/<name>/logs                    the workspace's own menu, raw
//   #blade/…/resourceId/<enc>, Logs.ReactView/resourceId/<enc>                  older forms
// The ARM id is found by shape rather than by the segment before it, in
// the hash as given and in each decoding of it (a portal link is sometimes
// encoded twice).
const WORKSPACE_ID_RE = /\/subscriptions\/[0-9a-f-]{36}\/resourceGroups\/[^/?#&]+\/providers\/Microsoft\.OperationalInsights\/workspaces\/[^/?#&]+/i;

export function resourceIdFromHash(hash) {
  let form = String(hash || "");
  for (let i = 0; i < 4 && form; i++) {
    const m = WORKSPACE_ID_RE.exec(form);
    if (m && isResourceId(m[0])) return m[0];
    let next;
    try {
      next = decodeURIComponent(form);
    } catch {
      return null;
    }
    if (next === form) return null;
    form = next;
  }
  return null;
}

export function workspaceNameOf(resourceId) {
  const m = /\/workspaces\/([^/]+)$/i.exec(String(resourceId || ""));
  return m ? m[1] : null;
}

// ISO-8601 duration for the blade's time picker; the query's own predicate
// wins when it has one, so this only widens the picker enough not to clip.
export function timespanFor(window) {
  const w = windowSpan(window, "1d");
  const m = RELATIVE_RE.exec(w);
  const n = Number(m[1]);
  return m[2] === "d" ? `P${n}D` : m[2] === "h" ? `PT${n}H` : m[2] === "m" ? `PT${n}M` : `PT${n}S`;
}

export async function deepLink({ resourceId, kql, timespan = "P1D" }) {
  if (!isResourceId(resourceId)) throw new KqlError("bad_resource", "not a Log Analytics workspace resource id");
  const q = await gzipBase64(String(kql || ""));
  return `${PORTAL}/#view/Microsoft_Azure_Monitoring_Logs/LogsBlade/resourceId/${encodeURIComponent(resourceId)}/source/LogsBlade.AnalyticsShareLinkToQuery/q/${encodeURIComponent(q)}/timespan/${encodeURIComponent(timespan)}`;
}

export default {
  KqlError,
  RESERVED,
  isReserved,
  bracket,
  ident,
  table,
  column,
  quote,
  quoteList,
  timeLiteral,
  windowSpan,
  lint,
  tablesIn,
  isResourceId,
  resourceIdFromHash,
  workspaceNameOf,
  timespanFor,
  deepLink,
  PORTAL,
};
