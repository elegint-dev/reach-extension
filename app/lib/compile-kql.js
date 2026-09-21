// KQL emitter: the Sentinel half of query synthesis. Takes a Plan from
// intent.js (concepts already resolved to a table's columns) and returns a
// template in the exact shape pivot.generate() takes, { required, lines }
// with $param$ tokens, never a rendered query. pivot.js binds, quotes and
// lints the result exactly as it does a hand-written template, so this
// module never sees a user's value: a filter value reaches a line only as
// the $param$ token, or, for a literal the pack authored, through
// kql.quote().
//
//   compile(plan) → { required: [param names], lines: [string | { clause, needs }] }
//   throws CompileError(code) when the plan cannot be emitted safely
//
// Lines, in order: $table$; the window on plan.time (since always, until as
// a needs-clause); the record-type filter; one | where per filter (a filter
// with needs becomes a { clause, needs } line and drops when the param is
// unbound); then the shape: summarize + order + take, or project + order
// + take.
//
// Column expressions: a plain column as is; a dynamic path (dynamic: true)
// as tostring(Col.path); a json_string binding (encoding json_string with
// head and path) as tostring(parse_json(Head).path). Every column and path
// goes through kql.column(), every alias through kql.ident(), so nothing
// but a validated identifier or a $param$ token lands in a line. A path
// segment that is not a bare identifier (kql.column admits a hyphen after
// the first segment) is rendered as Col["x-forwarded-for"], never bare,
// because Kusto reads a bare hyphen as subtraction.
//
// Pack literals go through kql.quote(), which leaves $ alone, and pivot.js
// re-scans the emitted lines for $name$ tokens; so a literal shaped like a
// token would become a live parameter inside quotes this module wrote.
// literal() refuses such a value (CompileError literal_token).
//
// The window is mandatory: a plan without window.since is refused
// (CompileError no_window), because nothing downstream can add the time
// predicate and kql.lint cannot tell a projected TimeGenerated from one in
// a where.
//
// Unresolved concepts: a filter or record-type column of null is a
// CompileError (the pivot would silently widen); an unresolved projected
// or measure concept is dropped (the plan lists it under unresolved); an
// unresolved by-column is a CompileError (dropping a grouping key changes
// what the rows mean).
//
// An in filter bound to a $param renders as col in ($param:list$), which
// pivot.js fills from an array through kql.quoteList; a pack's literal
// list is written out.
//
// Scope "type" (plan.union, one entry per container the type lands on):
// a union of one parenthesised branch per table, each with the window,
// its own where predicates and a project of TimeGenerated, Type (the
// table name, on every Log Analytics row) and the shared aliases, one per
// projected concept, named by the concept's type id. Every alias is
// tostring()ed: union splits a column whose type differs between branches
// into two, and a cross-feed lead list is text anyway; the time column
// stays datetime. Then the shape after the union: order and take for a
// list; summarize by Type and the by-aliases for a summary, since two
// feeds' outcome vocabularies are not one. A branch lacking a projected
// concept leaves that column empty for its rows.
//
// No DOM.

import * as kql from "./kql.js";
import { CompileError, PARAM_RE, paramToken, literalText } from "./lang.js";

export { CompileError };

function fail(code, message) {
  throw new CompileError(code, message);
}

function wrap(fn, code) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof CompileError) throw err;
    throw new CompileError(code, err.message);
  }
}

function token(name) {
  return paramToken(name);
}

function timeToken(name) {
  return paramToken(name, "time");
}

function positiveInt(n, what) {
  if (!Number.isInteger(n) || n <= 0) fail("bad_number", `${what} must be a positive integer`);
  return n;
}

const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// Member accessors for the segments after a column: .seg for an identifier,
// ["seg"] for anything else kql.column let through (a hyphen). The quote is
// safe: a segment is confined to [A-Za-z0-9_-] by the validator.
function members(segments) {
  return segments.map((s) => (IDENT_RE.test(s) ? `.${s}` : `[${kql.quote(s)}]`)).join("");
}

// A validated column path as a KQL expression: the column bare, the rest as members.
function columnExpr(path) {
  const [first, ...rest] = wrap(() => kql.column(path), "bad_column").split(".");
  return kql.bracket(first) + members(rest); // a column named like a keyword is legal bracketed
}

// The KQL expression that reads a resolved column: { column, dynamic, encoding, head, path }.
function expr(col, what = "column") {
  if (!col || typeof col.column !== "string" || !col.column) fail("unresolved", `${what}: concept is not bound on this table`);
  if (col.encoding === "json_string" && col.head && col.path) {
    const head = wrap(() => kql.column(col.head), "bad_column");
    if (head.includes(".")) fail("bad_column", `json_string head must be a column, not a path: ${head}`);
    const path = wrap(() => kql.column(col.path), "bad_column");
    return `tostring(parse_json(${head})${members(path.split("."))})`;
  }
  const c = columnExpr(col.column);
  if (col.dynamic) return `tostring(${c})`;
  return c;
}

// A short name for an expression column in a projection or a by-list: the
// concept's own id (after the pack prefix, if any).
function aliasFor(conceptRef) {
  const ref = String(conceptRef || "");
  const id = ref.includes("/") ? ref.slice(ref.lastIndexOf("/") + 1) : ref;
  const name = wrap(() => kql.ident(id, "projection alias"), "bad_alias");
  if (kql.isReserved(name)) fail("bad_alias", `reserved word as a projection alias: ${name}`);
  return name;
}

// A literal the pack authored. A number or a boolean goes out as itself
// (StatusCode == 403, not "403"); a string is quoted. lang.literalText
// refuses one that contains a $name$ shape: pivot.js would bind it as a
// parameter inside the quotes written here.
function literal(v) {
  if (typeof v === "number" && !Number.isFinite(v)) fail("bad_literal", "a pack literal must be a finite number");
  const s = literalText(v, "pack literal");
  if (typeof v === "number" || typeof v === "boolean") return s;
  return kql.quote(s);
}

// One comparison term for a clause on one column expression.
function term(e, op, f) {
  const hasParam = typeof f.param === "string" && f.param;
  const rhs = () => (hasParam ? token(f.param) : literal(f.value));
  switch (op) {
    case "eq": return `${e} == ${rhs()}`;
    case "eq_ci": return `${e} =~ ${rhs()}`;
    case "contains": return `${e} contains ${rhs()}`;
    case "prefix": return `${e} startswith ${rhs()}`;
    case "exists": return `isnotempty(${e})`;
    case "missing": return `isempty(${e})`;
    case "in": {
      if (hasParam) return `${e} in (${token(f.param).replace(/\$$/, ":list$")})`;
      if (!Array.isArray(f.value) || !f.value.length) fail("bad_in", "in takes a non-empty list of literals");
      return `${e} in (${f.value.map(literal).join(", ")})`;
    }
    default: fail("bad_op", `unknown op ${String(op)}`);
  }
}

// A clause over its column and the column's alternatives. eq-like ops
// match in any of them (OR); missing means missing in all of them (AND).
function clauseTerms(f, what) {
  const cols = [{ column: f.column, dynamic: f.dynamic, encoding: f.encoding, head: f.head, path: f.path }, ...(f.alternatives || [])];
  return cols.map((c) => term(expr(c, what), f.op, f));
}

function joinTerms(terms, op) {
  if (terms.length === 1) return terms[0];
  return `(${terms.join(` ${op} `)})`;
}

function filterPredicate(f, i) {
  const what = `filter[${i}]`;
  if (f.any) {
    if (!Array.isArray(f.any) || f.any.length < 2) fail("bad_any", `${what}: any needs at least two clauses`);
    const parts = [];
    for (const [j, c] of f.any.entries()) {
      const terms = clauseTerms(c, `${what}.any[${j}]`);
      if (c.op === "missing") parts.push(joinTerms(terms, "and")); // one AND group inside the OR
      else parts.push(...terms);
    }
    return `(${parts.join(" or ")})`;
  }
  const terms = clauseTerms(f, what);
  return f.op === "missing" ? joinTerms(terms, "and") : joinTerms(terms, "or");
}

function needsOf(f, what) {
  const needs = f.needs || [];
  if (!Array.isArray(needs) || needs.some((n) => typeof n !== "string" || !PARAM_RE.test(n))) fail("bad_needs", `${what}: needs must be a list of param names`);
  return needs;
}

function line(clause, needs) {
  return needs.length ? { clause, needs } : clause;
}

function measureExpr(m, plan) {
  switch (m.fn) {
    case "count": return "count()";
    case "min_time": return `min(${kql.column(plan.time)})`;
    case "max_time": return `max(${kql.column(plan.time)})`;
    case "dcount": return `dcount(${expr(m)})`;
    case "count_where_exists": return `countif(isnotempty(${expr(m)}))`;
    case "values": return m.limit != null ? `make_set(${expr(m)}, ${positiveInt(m.limit, "values limit")})` : `make_set(${expr(m)})`;
    default: fail("bad_measure", `unknown measure ${String(m.fn)}`);
  }
}

function needsColumn(fn) {
  return !["count", "min_time", "max_time"].includes(fn);
}

// An alias shared across the union's branches: the concept's type id,
// validated like any other name.
function unionAlias(name) {
  const a = wrap(() => kql.ident(name, "union alias"), "bad_alias");
  if (kql.isReserved(a)) fail("bad_alias", `reserved word as a union alias: ${a}`);
  return a;
}

// Scope "type": union (T1 | window | filters | project shared), (T2 ...)
// then the shape over the shared aliases.
function compileUnion(plan, time, lines, require) {
  const union = Array.isArray(plan.union) ? plan.union : [];
  if (!union.length) fail("unresolved", "scope type: the plan has no containers");
  if (plan.recordTypes) fail("bad_record_types", "scope type cannot filter record_types");
  const s = plan.shape;
  if (!s || typeof s !== "object") fail("bad_shape", "plan has no shape");
  const carried = s.kind === "list" ? s.project || [] : [...(s.by || []), ...(s.measures || []).filter((m) => m.concept)];
  const order = s.order || null;
  const orderRef = order && order.by !== "time" && order.alias && !(s.kind === "summary" && (s.measures || []).some((m) => m.as === order.by)) ? order.by : null;
  const shared = []; // [{ concept, alias }], one per concept, in shape order
  for (const x of carried) if (!shared.some((y) => y.concept === x.concept)) shared.push({ concept: x.concept, alias: unionAlias(x.alias) });
  if (orderRef && !shared.some((y) => y.concept === orderRef)) shared.push({ concept: orderRef, alias: unionAlias(order.alias) });
  const seen = new Set(["Type", time]);
  for (const x of shared) {
    if (seen.has(x.alias)) fail("bad_alias", `two shared columns would be named ${x.alias}`);
    seen.add(x.alias);
  }
  const resolved = new Set(); // aliases at least one branch carries

  union.forEach((u, n) => {
    const table = wrap(() => kql.table(u.container), "bad_column");
    lines.push(`${n === 0 ? "union " : ""}(${table}`);
    lines.push(`  | where ${time} > ${timeToken(plan.window.since)}`);
    if (plan.window.until) lines.push({ clause: `  | where ${time} < ${timeToken(plan.window.until)}`, needs: [plan.window.until] });
    for (const [i, f] of (u.filters || []).entries()) {
      lines.push(`  | where ${filterPredicate(f, i)}`);
      for (const c of f.any ? f.any : [f]) if (typeof c.param === "string" && c.param) require(c.param);
    }
    const cols = [time, "Type"];
    for (const x of shared) {
      const c = u.columns && u.columns[x.concept];
      if (!c || !c.column) continue;
      const e = expr(c, `${x.alias} on ${u.container}`);
      cols.push(`${x.alias} = ${e.startsWith("tostring(") ? e : `tostring(${e})`}`);
      resolved.add(x.alias);
    }
    lines.push(`  | project ${cols.join(", ")})${n < union.length - 1 ? "," : ""}`);
  });

  const dir = order ? (order.dir === "asc" ? "asc" : "desc") : null;
  if (s.kind === "list") {
    if (order) {
      const target = order.by === "time" ? time : orderRef ? shared.find((y) => y.concept === orderRef).alias : null;
      if (target && (target === time || resolved.has(target))) lines.push(`| order by ${target} ${dir}`);
    }
  } else if (s.kind === "summary") {
    const by = ["Type"];
    for (const b of s.by || []) {
      const a = shared.find((y) => y.concept === b.concept).alias;
      if (!resolved.has(a)) fail("unresolved", `by ${b.concept}: no container carries it`);
      if (!by.includes(a)) by.push(a);
    }
    const measures = [];
    const aliases = new Set();
    for (const m of s.measures || []) {
      const col = m.concept ? shared.find((y) => y.concept === m.concept).alias : null;
      if (needsColumn(m.fn) && !resolved.has(col)) continue; // no container carries it: dropped
      const as = wrap(() => kql.ident(m.as, "measure alias"), "bad_alias");
      if (kql.isReserved(as)) fail("bad_alias", `reserved word as a measure alias: ${as} (Kusto refuses it bare)`);
      if (aliases.has(as) || by.includes(as)) fail("bad_alias", `duplicate name ${as} in summarize`);
      aliases.add(as);
      measures.push(`${as} = ${measureExpr({ fn: m.fn, column: col, dynamic: false, encoding: null, head: null, path: null, limit: m.limit }, plan)}`);
    }
    if (!measures.length) fail("no_measures", "no measure resolved on any table");
    lines.push(`| summarize ${measures.join(", ")} by ${by.join(", ")}`);
    if (order) {
      const target = order.by === "time" ? null : aliases.has(order.by) ? order.by : orderRef && by.includes(shared.find((y) => y.concept === orderRef).alias) ? shared.find((y) => y.concept === orderRef).alias : null;
      if (target) lines.push(`| order by ${target} ${dir}`);
    }
  } else {
    fail("bad_shape", `shape.kind must be list or summary, not ${String(s.kind)}`);
  }
  if (s.take != null) lines.push(`| take ${positiveInt(s.take, "take")}`);
}

export function compile(plan) {
  if (!plan || typeof plan !== "object") fail("bad_plan", "compile takes a Plan");
  if (plan.lang && plan.lang !== "kql") fail("bad_lang", `not a KQL plan: ${plan.lang}`);
  const time = wrap(() => kql.column(plan.time), "bad_column");
  if (time.includes(".")) fail("bad_column", `time column must be a column, not a path: ${time}`);
  const required = [];
  const require = (name) => {
    if (!required.includes(name)) required.push(name);
  };

  // Window: since always (a plan without one is refused, nothing downstream
  // can add the predicate), until only when bound.
  if (!plan.window || typeof plan.window !== "object" || !plan.window.since) fail("no_window", "the plan has no window.since: a KQL pivot must bound its scan");
  if (plan.scope === "type") {
    const lines = [];
    require(plan.window.since);
    compileUnion(plan, time, lines, require);
    return { required, lines };
  }
  const lines = ["$table$"];
  lines.push(`| where ${time} > ${timeToken(plan.window.since)}`);
  require(plan.window.since);
  if (plan.window.until) lines.push({ clause: `| where ${time} < ${timeToken(plan.window.until)}`, needs: [plan.window.until] });

  // Record types: the feed's discriminator, literal values authored in the pack.
  if (plan.recordTypes) {
    const rt = plan.recordTypes;
    const values = Array.isArray(rt.values) ? rt.values : [];
    if (!values.length) fail("bad_record_types", "record_types needs at least one value");
    const e = expr(rt, "record_types");
    lines.push(values.length === 1 ? `| where ${e} == ${literal(values[0])}` : `| where ${e} in (${values.map(literal).join(", ")})`);
  }

  // Filters: one | where each; needs-gated ones drop when unbound.
  for (const [i, f] of (plan.filters || []).entries()) {
    const needs = needsOf(f, `filter[${i}]`);
    const predicate = filterPredicate(f, i);
    lines.push(line(`| where ${predicate}`, needs));
    if (!needs.length) {
      for (const c of f.any ? f.any : [f]) if (typeof c.param === "string" && c.param) require(c.param);
    }
  }

  // Shape.
  const s = plan.shape;
  if (!s || typeof s !== "object") fail("bad_shape", "plan has no shape");
  const order = s.order || null;
  const orderDir = order ? (order.dir === "asc" ? "asc" : "desc") : null;
  if (s.kind === "summary") {
    // After summarize only the by-columns and the measure aliases exist, so
    // a by expression that is not a bare column is named like a projection.
    // Two by-entries may share a name only when they are the same
    // expression (then one is enough); Kusto refuses a duplicate name.
    const available = new Set();
    const byExpr = new Map(); // name → expression text
    const by = [];
    for (const [i, c] of (s.by || []).entries()) {
      const e = expr(c, `by[${i}]`);
      const name = e === c.column ? e : aliasFor(c.concept);
      if (byExpr.has(name)) {
        if (byExpr.get(name) !== e) fail("bad_alias", `duplicate name ${name} in summarize by`);
        continue;
      }
      byExpr.set(name, e);
      available.add(name);
      by.push(name === e ? e : `${name} = ${e}`);
    }
    const measures = [];
    const aliases = new Set();
    for (const m of s.measures || []) {
      if (needsColumn(m.fn) && !m.column) continue; // unresolved measure concept: dropped, the plan lists it
      const as = wrap(() => kql.ident(m.as, "measure alias"), "bad_alias");
      if (kql.isReserved(as)) fail("bad_alias", `reserved word as a measure alias: ${as} (Kusto refuses it bare)`);
      if (aliases.has(as) || available.has(as)) fail("bad_alias", `duplicate name ${as} in summarize`);
      aliases.add(as);
      available.add(as);
      measures.push(`${as} = ${measureExpr(m, plan)}`);
    }
    if (!measures.length) fail("no_measures", "no measure resolved on this table");
    lines.push(`| summarize ${measures.join(", ")}${by.length ? ` by ${by.join(", ")}` : ""}`);
    if (order) {
      // "time" is the time column, which survives only as a by-column; a
      // measure alias by name; a concept by the name its by-column has.
      const target = order.by === "time" ? time : aliases.has(order.by) ? order.by : order.column ? (expr(order, "order") === order.column ? order.column : aliasFor(order.by)) : null;
      // Anything summarize did not keep (a dropped measure, an unresolved
      // concept, a column outside by) gets no order line rather than a
      // reference the portal would refuse.
      if (target && available.has(target)) lines.push(`| order by ${target} ${orderDir}`);
    }
  } else if (s.kind === "list") {
    const cols = [];
    const seen = new Map();
    const shown = new Map(); // concept ref → the name the projection gives it
    // The same plain column twice (time first, then projected again) is
    // one column; two different expressions landing on one name would
    // silently lose one of them, so that is an error instead.
    const add = (name, text) => {
      if (seen.has(name)) {
        if (seen.get(name) !== text) fail("bad_alias", `two projected columns would be named ${name}`);
        return;
      }
      seen.set(name, text);
      cols.push(text);
    };
    const byTime = order && order.by === "time";
    if (byTime) add(time, time);
    for (const c of s.project || []) {
      if (!c.column) continue; // unresolved projected concept: dropped, the plan lists it
      const e = expr(c, "project");
      if (e === c.column) {
        add(e, e);
        shown.set(c.concept, e);
      } else {
        const as = aliasFor(c.concept);
        add(as, `${as} = ${e}`);
        shown.set(c.concept, as);
      }
    }
    if (!cols.length) fail("no_columns", "no projected concept resolved on this table");
    let orderLine = null;
    let orderBefore = false;
    if (order) {
      if (byTime) orderLine = `| order by ${time} ${orderDir}`;
      else if (order.column) {
        const name = shown.get(order.by);
        if (name) orderLine = `| order by ${name} ${orderDir}`;
        else { orderLine = `| order by ${expr(order, "order")} ${orderDir}`; orderBefore = true; } // not projected: order first
      }
    }
    if (orderLine && orderBefore) lines.push(orderLine);
    lines.push(`| project ${cols.join(", ")}`);
    if (orderLine && !orderBefore) lines.push(orderLine);
  } else {
    fail("bad_shape", `shape.kind must be list or summary, not ${String(s.kind)}`);
  }
  if (s.take != null) lines.push(`| take ${positiveInt(s.take, "take")}`);

  return { required, lines };
}

export default { compile, CompileError };
