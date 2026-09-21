// SPL emitter for query intent: the Splunk half of the split in
// docs/PROPOSAL.md section 9. Takes a Plan from intent.js (concepts already
// resolved to a container's columns) and returns a template in the exact
// shape pivot.generate() renders, quotes and lints: { required, lines }
// with $param$ tokens, never a rendered query.
//
//   compile(plan) → { required: [param names], lines: [string | { clause, needs }] }
//   throws CompileError on an unresolved filter column, a bad identifier,
//   a pack literal shaped like a token, a take that is not a positive
//   integer, or a mixed any-group
//
// Every identifier written into a line is a pack-authored column, checked
// against IDENT_RE; every value is either the $param$ token pivot.js quotes
// at render time or a pack-authored literal passed through spl.quote(). A
// value the user typed never reaches this module. pivot.js rescans a whole
// line for $tokens$, quotes included, so a literal that would read as a
// token after quoting is refused rather than written.
//
// Search-term ops (eq, eq_ci, in, exists, missing) become terms on the
// first search block, one per line as the hand-written templates do; SPL's
// = is case-insensitive, so eq and eq_ci render the same. An in bound to
// a $param renders as col IN ($param:list$), which pivot.js fills from an
// array through spl.quoteList (a pack's literal list stays an OR of
// terms). contains and prefix cannot be search terms (the token renders
// as a whole quoted string), so they become "| where like(...)" stages
// after the search block. A filter with needs becomes a { clause, needs }
// line that pivot.js drops when the param is unbound. A filter with
// alternatives matches the value in any of its columns (OR); an any-group
// ORs its clauses.
//
// Scope "type" (plan.union, one entry per container the type lands on):
// the first search block carries one group per container, OR-ed,
// (sourcetype=X its terms) so the index is read once; where-ops become one
// "| where" of sourcetype-guarded groups; then one "| eval <type> =
// coalesce(<each container's column>)" per shared alias, so the shape
// below sees one column per type whichever feed the event came from. The
// list tables _time and sourcetype before the aliases; the summary groups
// by sourcetype first, since two feeds' outcome vocabularies are not one.
//
// Field names are written bare (resources{}.ARN, userIdentity.arn) in
// search terms, stats arguments, by and sort: Splunk takes single quotes
// there as part of the name (measured: values('resources{}.type') is
// empty, by 'resources{}.ARN' yields no groups). Only an eval context
// (where, eval(...)) quotes a name that is not plain, since "." reads as
// concatenation there.
//
// Stage order: a list sorts and heads before it tables, so an order column
// the intent does not project still sorts; a summary sorts and heads on the
// epoch before convert ctime() turns a time alias into text.
//
// No DOM.

import { quote } from "./spl.js";
import { CompileError, paramToken as tokenFor, literalText } from "./lang.js";

export { CompileError };

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.{}]*$/;
const PLAIN_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ALIAS_RE = /^[a-z][a-z0-9_]*$/;
const SAFE_SOURCETYPE_RE = /^[A-Za-z0-9_:\-.*]+$/;
const SEARCH_OPS = ["eq", "eq_ci", "in", "exists", "missing"];
const WHERE_OPS = ["contains", "prefix"];

// ---------------------------------------------------------------------------
// Identifiers, in the two places SPL treats them differently

function ident(name, what) {
  const s = typeof name === "string" ? name : "";
  if (!IDENT_RE.test(s)) throw new CompileError("bad_identifier", `${what} is not a valid SPL field name: ${s || "(empty)"}`);
  return s;
}

// A search term, stats argument, by-field or sort field: the name as the
// pack wrote it, bare.
function field(name, what) {
  return ident(name, what);
}

// An eval-context name (where, eval(...)): single quotes unless plain,
// since "." is concatenation there.
function evalField(name, what) {
  const s = ident(name, what);
  return PLAIN_RE.test(s) ? s : `'${s}'`;
}

function alias(name, what) {
  const s = typeof name === "string" ? name : "";
  if (!ALIAS_RE.test(s)) throw new CompileError("bad_identifier", `${what} is not a valid alias: ${s || "(empty)"}`);
  return s;
}

// The $param$ token for a name; used is the set of params the current
// line mentions, so required can be built from what was emitted rather
// than by scanning text.
function paramToken(name, what, used) {
  const t = tokenFor(name, "", what);
  if (used) used.add(name);
  return t;
}

// A pack-authored literal, quoted for SPL; lang.literalText refuses one
// that would carry a token, since pivot.js expands tokens inside quotes too.
function literal(v, what) {
  return quote(literalText(v, what));
}

// ---------------------------------------------------------------------------
// Filters

// The value side of a clause: the $param$ token, or a pack literal quoted.
function valueOf(f, what, used) {
  if (f.param) return paramToken(f.param, what, used);
  return literal(f.value, `${what}: ${f.op}`);
}

function columnsOf(f, what) {
  if (!f.column) throw new CompileError("unresolved", `${what}: unresolved concept ${f.concept || "(unnamed)"} has no column on ${what}`);
  if (f.encoding === "json_string") throw new CompileError("unsupported", `${what}: json_string columns are not compiled on SPL yet`);
  const alts = (f.alternatives || []).filter((a) => a && a.column && a.encoding !== "json_string").map((a) => a.column);
  return [f.column, ...alts];
}

function orJoin(terms) {
  return terms.length === 1 ? terms[0] : `(${terms.join(" OR ")})`;
}

// One clause as a search term (eq, eq_ci, in, exists, missing).
function searchTerm(f, what, used) {
  const cols = columnsOf(f, what).map((c) => field(c, what));
  switch (f.op) {
    case "eq":
    case "eq_ci": {
      const v = valueOf(f, what, used);
      return orJoin(cols.map((c) => `${c}=${v}`));
    }
    case "in": {
      if (f.param) {
        const list = paramToken(f.param, what, used).replace(/\$$/, ":list$");
        return orJoin(cols.map((c) => `${c} IN (${list})`));
      }
      if (!Array.isArray(f.value) || !f.value.length) throw new CompileError("bad_in", `${what}: in needs a non-empty list`);
      const vals = f.value.map((v, j) => literal(v, `${what}: in[${j}]`));
      const terms = [];
      for (const c of cols) for (const v of vals) terms.push(`${c}=${v}`);
      return orJoin(terms);
    }
    case "exists":
      return orJoin(cols.map((c) => `${c}=*`));
    case "missing":
      return `NOT ${orJoin(cols.map((c) => `${c}=*`))}`;
    default:
      throw new CompileError("bad_op", `${what}: ${f.op} is not a search term`);
  }
}

// One clause as an eval expression for a where stage (contains, prefix).
function whereExpr(f, what, used) {
  const cols = columnsOf(f, what).map((c) => evalField(c, what));
  const v = valueOf(f, what, used);
  switch (f.op) {
    // like() is case-sensitive in SPL while search terms (and KQL's
    // contains/startswith) are not; lower both sides so the same intent
    // matches the same rows on both platforms.
    case "contains":
      return orJoin(cols.map((c) => `like(lower(${c}), "%".lower(${v})."%")`));
    case "prefix":
      return orJoin(cols.map((c) => `like(lower(${c}), lower(${v})."%")`));
    default:
      throw new CompileError("bad_op", `${what}: ${f.op} is not a where expression`);
  }
}

function opOf(f, what) {
  if (SEARCH_OPS.includes(f.op)) return "search";
  if (WHERE_OPS.includes(f.op)) return "where";
  throw new CompileError("bad_op", `${what}: unknown op ${String(f.op)}`);
}

// A filter becomes { kind: "search" | "where", text, needs, used }.
function compileFilter(f, i) {
  const what = `filter[${i}]`;
  const needs = Array.isArray(f.needs) ? f.needs : [];
  for (const n of needs) paramToken(n, what);
  const used = new Set();
  if (f.any) {
    if (!Array.isArray(f.any) || !f.any.length) throw new CompileError("bad_any", `${what}: any needs clauses`);
    const kinds = new Set(f.any.map((c, j) => opOf(c, `${what}.any[${j}]`)));
    if (kinds.size > 1) throw new CompileError("unsupported", `${what}: an any-group cannot mix search terms with contains or prefix`);
    const kind = [...kinds][0];
    const parts = f.any.map((c, j) => (kind === "search" ? searchTerm(c, `${what}.any[${j}]`, used) : whereExpr(c, `${what}.any[${j}]`, used)));
    return { kind, text: `(${parts.join(" OR ")})`, needs, used };
  }
  const kind = opOf(f, what);
  return { kind, text: kind === "search" ? searchTerm(f, what, used) : whereExpr(f, what, used), needs, used };
}

// ---------------------------------------------------------------------------
// Shapes

function timeColumn(plan) {
  return ident(plan.time || "_time", "time column");
}

function takeLine(s) {
  if (s.take === undefined || s.take === null) return null;
  if (!Number.isInteger(s.take) || s.take <= 0) throw new CompileError("bad_take", `shape.take must be a positive integer, not ${JSON.stringify(s.take)}`);
  return `| head ${s.take}`;
}

function sortLine(plan, order, aliases) {
  if (!order) return null;
  let f;
  if (order.by === "time") {
    if (plan.shape.kind === "summary") {
      const t = plan.shape.measures.find((m) => m.fn === "max_time") || plan.shape.measures.find((m) => m.fn === "min_time");
      if (!t) throw new CompileError("bad_shape", "summary cannot order by time without a min_time or max_time measure");
      f = alias(t.as, "order.by");
    } else {
      f = timeColumn(plan);
    }
  } else if (aliases.has(order.by)) {
    f = alias(order.by, "order.by");
  } else if (order.column) {
    f = field(order.column, "order.by");
  } else {
    return null; // an unresolved order concept: already listed under plan.unresolved
  }
  return order.dir === "asc" ? `| sort ${f}` : `| sort - ${f}`;
}

// sort, head, then table: the order column need not be projected.
function compileList(plan) {
  const s = plan.shape;
  const time = timeColumn(plan);
  const cols = [];
  for (const p of s.project || []) {
    if (!p.column || p.encoding === "json_string") continue; // unresolved: dropped, the plan lists it
    const c = ident(p.column, `project ${p.concept}`);
    if (c !== time && !cols.includes(c)) cols.push(c);
  }
  const out = [];
  const sort = sortLine(plan, s.order, new Set());
  if (sort) out.push(sort);
  const head = takeLine(s);
  if (head) out.push(head);
  out.push(`| table ${[time, ...cols].join(" ")}`);
  return out;
}

function measureText(m, plan, i) {
  const what = `measure[${i}]`;
  const as = alias(m.as, `${what}.as`);
  const needsColumn = !["count", "min_time", "max_time"].includes(m.fn);
  if (needsColumn && (!m.column || m.encoding === "json_string")) return null; // unresolved: dropped
  switch (m.fn) {
    case "count":
      return `count as ${as}`;
    case "count_where_exists":
      return `count(eval(isnotnull(${evalField(m.column, what)}))) as ${as}`;
    case "dcount":
      return `dc(${field(m.column, what)}) as ${as}`;
    case "min_time":
      return `min(${timeColumn(plan)}) as ${as}`;
    case "max_time":
      return `max(${timeColumn(plan)}) as ${as}`;
    case "values":
      // SPL's values() takes no limit; the hand-written templates drop it too.
      return `values(${field(m.column, what)}) as ${as}`;
    default:
      throw new CompileError("bad_measure", `${what}: unknown measure ${String(m.fn)}`);
  }
}

// stats, sort, head, then convert: the sort sees the epoch, not ctime text.
function compileSummary(plan) {
  const s = plan.shape;
  const by = [];
  for (const b of s.by || []) {
    if (!b.column || b.encoding === "json_string") continue;
    const c = field(b.column, `by ${b.concept}`);
    if (!by.includes(c)) by.push(c);
  }
  if (!by.length) throw new CompileError("unresolved", "summary has no resolved by column");
  const measures = [];
  const aliases = new Set();
  const timeMeasures = [];
  (s.measures || []).forEach((m, i) => {
    const t = measureText(m, plan, i);
    if (!t) return;
    // Two measures on one alias, or an alias that is also a by-field, is
    // a FATAL on the search head ("duplicate rename field", "cannot have
    // the same name as a group-by field"); refuse it here.
    if (aliases.has(m.as)) throw new CompileError("bad_identifier", `duplicate measure alias ${m.as}`);
    if (by.includes(field(m.as, "alias"))) throw new CompileError("bad_identifier", `measure alias ${m.as} is also a by field`);
    measures.push(t);
    aliases.add(m.as);
    if (m.fn === "min_time" || m.fn === "max_time") timeMeasures.push(m.as);
  });
  if (!measures.length) throw new CompileError("unresolved", "summary has no resolved measure");
  const out = [`| stats ${measures.join(", ")} by ${by.join(", ")}`];
  const sort = sortLine(plan, s.order, aliases);
  if (sort) out.push(sort);
  const head = takeLine(s);
  if (head) out.push(head);
  if (timeMeasures.length) out.push(`| convert ${timeMeasures.map((a) => `ctime(${a})`).join(" ")}`);
  return out;
}

// ---------------------------------------------------------------------------

// The sourcetype term of a scoped group: bare when the name is plain, as
// pivot.js writes $sourcetype$, else quoted.
function sourcetypeTerm(name) {
  if (typeof name !== "string" || !name) throw new CompileError("bad_identifier", "union: container is required");
  return `sourcetype=${SAFE_SOURCETYPE_RE.test(name) ? name : literal(name, "union container")}`;
}

// Scope "type": the OR of scoped groups, the where line, the coalesce
// evals, then the shape over the aliases. Returns the lines after the
// window; `always` collects the params they mention.
function compileUnion(plan, always) {
  const union = Array.isArray(plan.union) ? plan.union : [];
  if (!union.length) throw new CompileError("unresolved", "scope type: the plan has no containers");
  const lines = [];
  const groups = [];
  const guarded = [];
  let anyWhere = false;
  for (const u of union) {
    const st = sourcetypeTerm(u.container);
    const compiled = (u.filters || []).map((f, i) => compileFilter({ ...f, needs: [] }, i));
    for (const f of compiled) for (const p of f.used) always.add(p);
    const terms = compiled.filter((f) => f.kind === "search").map((f) => f.text);
    const wheres = compiled.filter((f) => f.kind === "where").map((f) => f.text);
    groups.push(`(${[st, ...terms].join(" ")})`);
    if (wheres.length) anyWhere = true;
    guarded.push(wheres.length ? `(sourcetype=${literal(u.container, "union container")} AND ${wheres.join(" AND ")})` : `sourcetype=${literal(u.container, "union container")}`);
  }
  lines.push(`  ${groups.length === 1 ? groups[0] : `(${groups.join(" OR ")})`}`);
  if (anyWhere) lines.push(`| where ${guarded.length === 1 ? guarded[0] : guarded.join(" OR ")}`);

  // One alias per shared concept: the columns it has across the containers, in union order.
  const s = plan.shape;
  const carried = s.kind === "list" ? s.project : [...s.by, ...s.measures.filter((m) => m.concept)];
  const refs = carried.map((x) => x.concept);
  const orderRef = s.order && s.order.by !== "time" && s.order.alias ? s.order.by : null;
  if (orderRef && !refs.includes(orderRef)) refs.push(orderRef);
  const aliasOf = (ref) => {
    const hit = carried.find((x) => x.concept === ref);
    return hit ? hit.alias : ref === orderRef ? s.order.alias : null;
  };
  const resolved = new Map(); // ref -> alias, when at least one container carries it
  for (const ref of refs) {
    const a = aliasOf(ref);
    if (!a) continue;
    const cols = [];
    for (const u of union) {
      const c = u.columns && u.columns[ref];
      if (!c || !c.column || c.encoding === "json_string") continue;
      const e = evalField(c.column, `${a} on ${u.container}`);
      if (!cols.includes(e)) cols.push(e);
    }
    if (!cols.length) continue;
    const name = alias(a, `alias for ${ref}`);
    resolved.set(ref, name);
    if (cols.length === 1 && cols[0] === name) continue;
    lines.push(`| eval ${name}=${cols.length === 1 ? cols[0] : `coalesce(${cols.join(", ")})`}`);
  }

  // The shape, over the aliases as if they were the container's columns; sourcetype first.
  const col = (ref) => ({ concept: ref, column: resolved.get(ref) || null, dynamic: false, encoding: null, head: null, path: null });
  const order = s.order ? (s.order.by === "time" ? s.order : { by: s.order.by, dir: s.order.dir, column: resolved.get(s.order.by) || null }) : null;
  const sourcetype = { concept: "(sourcetype)", column: "sourcetype" };
  const shape = s.kind === "list"
    ? { kind: "list", project: [sourcetype, ...s.project.map((p) => col(p.concept)), ...(orderRef && resolved.has(orderRef) && !s.project.some((p) => p.concept === orderRef) ? [col(orderRef)] : [])], order, take: s.take }
    : { kind: "summary", by: [sourcetype, ...s.by.map((b) => col(b.concept))], measures: s.measures.map((m) => ({ ...col(m.concept), fn: m.fn, as: m.as, limit: m.limit })), order, take: s.take };
  const inner = { ...plan, shape };
  for (const l of s.kind === "list" ? compileList(inner) : compileSummary(inner)) lines.push(l);
  return lines;
}

export function compile(plan) {
  if (!plan || typeof plan !== "object") throw new CompileError("bad_plan", "compile takes a Plan");
  if (plan.lang && plan.lang !== "spl") throw new CompileError("bad_lang", `compile-spl cannot emit ${plan.lang}`);
  if (!plan.shape || !["list", "summary"].includes(plan.shape.kind)) throw new CompileError("bad_shape", "plan.shape.kind must be list or summary");
  const union = plan.scope === "type";

  const lines = [];
  // Params an always-line mentions; a param only a needs-clause uses is
  // optional by construction.
  const always = new Set();
  const w = plan.window || {};
  const scope = union ? "$index$" : "$index$ $sourcetype$";
  if (w.since) {
    const since = paramToken(w.since, "window.since", always).replace(/\$$/, ":time$");
    lines.push(`search ${scope} earliest=${since}`);
  } else {
    lines.push(`search ${scope}`);
  }
  if (w.until) lines.push({ clause: `  latest=${paramToken(w.until, "window.until").replace(/\$$/, ":time$")}`, needs: [w.until] });

  if (union) {
    if (plan.recordTypes) throw new CompileError("unsupported", "scope type cannot filter record_types");
    for (const l of compileUnion(plan, always)) lines.push(l);
    const order = Array.isArray(plan.params) ? plan.params : [];
    return { required: [...order.filter((p) => always.has(p)), ...[...always].filter((p) => !order.includes(p))], lines };
  }

  if (plan.recordTypes) {
    const rt = plan.recordTypes;
    if (!rt.column) throw new CompileError("unresolved", "record_types: the feed's discriminator has no column on this container");
    if (!Array.isArray(rt.values) || !rt.values.length) throw new CompileError("bad_record_types", "record_types needs at least one value");
    const c = field(rt.column, "record_types");
    lines.push(`  ${orJoin(rt.values.map((v, j) => `${c}=${literal(v, `record_types[${j}]`)}`))}`);
  }

  const filters = (plan.filters || []).map(compileFilter);
  for (const f of filters) {
    if (!f.needs.length) for (const p of f.used) always.add(p);
    if (f.kind === "search") lines.push(line(`  ${f.text}`, f.needs));
  }
  for (const f of filters) if (f.kind === "where") lines.push(line(`| where ${f.text}`, f.needs));

  for (const l of plan.shape.kind === "list" ? compileList(plan) : compileSummary(plan)) lines.push(l);

  const order = Array.isArray(plan.params) ? plan.params : [];
  const required = [...order.filter((p) => always.has(p)), ...[...always].filter((p) => !order.includes(p))];
  return { required, lines };
}

function line(text, needs) {
  return needs && needs.length ? { clause: text, needs } : text;
}

export default { compile, CompileError };
