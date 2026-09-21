// Query intent: what a pivot means, without saying it in SPL or KQL.
//
// A v2 edge may carry `intent` beside (or instead of) a template. It names
// concepts, never columns: "filter principal_arn to the value, over a
// window, list these concepts newest first" is the same pivot on
// aws:cloudtrail, AWSCloudTrail and ReachCloudTrail_CL; only the columns
// and the language differ, and those come from the bindings of the
// destination container. This module is the platform-neutral half:
//
//   validate(intent, refOk)            → [errors]        structure; refOk(conceptRef) says whether a concept ref is known
//   plan(intent, { pack, platform, container, type }) → Plan   concept refs resolved to the container's columns;
//                                                             scope "type": to the columns of every container the type lands on
//
// The other half, one module per language, takes a Plan and emits a
// template ({ required, lines } with $param$ tokens) that pivot.js renders,
// quotes and lints exactly as it does a hand-written one. So the compilers
// never see a user's value, and a template on the edge still wins.
//
//   intent = {
//     filter: [ { concept, op, value, needs } | { any: [ { concept, op, value } ], needs } ],
//                                                  op: eq | eq_ci | in | contains | prefix | exists | missing
//                                                  value: "$param" (bound at render time) | literal | [literals]
//                                                  needs: [param]: the clause is dropped when any is unbound
//                                                  any: the clauses OR-ed (a value that may sit in either of two columns)
//     record_types: [literal],                    a filter on the feed's discriminator concept
//     window: { since: "$param", until: "$param" },   on the platform's event time
//     shape: { kind: "list", project: [concept], order: { by: "time" | concept | alias, dir: "asc" | "desc" }, take }
//          | { kind: "summary", by: [concept], measures: [ { fn, concept, as, limit } ], order, take }
//                                                  fn: count | dcount | min_time | max_time | values | count_where_exists
//     scope: "container" | "type"                 type: every container bound to the edge's dst type (union / OR)
//   }
//
//   Plan = { platform, lang, container, time: <column | "_time">,
//            filters: [ { column, op, value, param, dynamic, encoding, head, path, needs, alternatives }
//                     | { any: [ { column, op, value, param, dynamic, encoding, head, path } ], needs } ],
//              alternatives: the other columns the same concept binds on this container (AccessKeyId and
//              UserIdentity.accessKeyId both carry access_key_id): an eq filter matches any of them
//              encoding "json_string": head is the JSON-string column and path the way into it
//              (KQL: tostring(parse_json(head).path); SPL: spath), else both null
//            recordTypes: { column, values } | null, window: { since, until } | null,
//            shape: { kind, project: [{ concept, column, dynamic }], by: [...], measures: [{ fn, column, as, limit, dynamic }], order: { by, dir }, take },
//            unresolved: [concept ref], params: [param names the plan binds] }
//
// Scope "type" ("this address in every feed I have"): the intent still
// names the edge pack's concepts, and the plan resolves each of them on
// every container the taxonomy type lands on (concepts.containersOfType),
// the container in hand first. On a container the concept is bound to,
// that binding; elsewhere, the concept of the same type bound there: the
// one bound on the most containers across both platforms (the feed's main
// carrier of the type, so both SIEMs pick alike), then a top-level column
// before a path into one, then the order the packs declare them. A
// container that cannot resolve a filter concept is dropped (the query
// would silently widen); none left is a PlanError. The shared shape names
// each projected concept by its type id (`principal`, `outcome`), one
// concept per type, and each union entry carries that container's column
// for it (null where it has none: the emitter leaves the branch's column
// empty). record_types and needs-gated filters do not combine with scope
// "type"; validate() refuses them. A type the feed defines (text, enum,
// identifier, count, flag, version, raw_object) never stands in across
// feeds: such a concept resolves on its own bindings only.
//
//   Plan (scope "type") = { ...as above, scope: "type", type: <taxonomy type>, filters: [],
//            union: [ { container, filters: [as Plan.filters], columns: { <concept ref>: { column, dynamic, encoding, head, path, via } | null } } ],
//            dropped: [ { container, reason } ],
//            shape: { kind, project: [{ concept, type, alias }] | by: [...], measures: [{ fn, concept, type, alias, as, limit }], order, take } }
//              via: the concept key the column carries on that container (the ref's own, or its type's stand-in)
//
// A dotted column on Sentinel is a path into a dynamic column and is
// flagged so the KQL side can tostring() it. No DOM.

import * as concepts from "./concepts.js";
import { RESERVED as KQL_RESERVED } from "./kql.js";

// Aliases no measure may take: Kusto's reserved words (bare, they are a
// syntax error) plus SPL's own command and function words a stats alias
// would shadow. One list, both platforms, so a pack is right everywhere.
const RESERVED_ALIASES = new Set([...KQL_RESERVED, "count", "values", "list", "sum", "avg", "min", "max", "dc", "stats", "eval", "where", "table", "sort", "head", "search", "index", "sourcetype", "source", "host", "time"]);

export class PlanError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "PlanError";
    this.code = code;
  }
}

export const OPS = ["eq", "eq_ci", "in", "contains", "prefix", "exists", "missing"];
export const MEASURES = ["count", "dcount", "min_time", "max_time", "values", "count_where_exists"];
const PARAM_RE = /^\$[A-Za-z_][A-Za-z0-9_]*$/;
const TIME_COLUMN = { splunk: "_time", sentinel: "TimeGenerated" };

function isParam(v) {
  return typeof v === "string" && PARAM_RE.test(v);
}

function paramName(v) {
  return isParam(v) ? v.slice(1) : null;
}

export function validate(intent, refOk = () => true) {
  const errors = [];
  if (!intent || typeof intent !== "object" || Array.isArray(intent)) return ["intent must be an object"];
  const ref = (r, what) => {
    if (typeof r !== "string" || !r) errors.push(`${what}: concept ref required`);
    else if (!refOk(r)) errors.push(`${what}: unknown concept ${r}`);
  };
  if (intent.filter !== undefined) {
    if (!Array.isArray(intent.filter)) errors.push("filter must be an array");
    const checkClause = (f, what) => {
      ref(f.concept, what);
      if (!OPS.includes(f.op)) errors.push(`${what}: op must be one of ${OPS.join(", ")}`);
      const needsValue = !["exists", "missing"].includes(f.op);
      if (needsValue && f.value === undefined) errors.push(`${what}: ${f.op} needs a value`);
      if (f.op === "in" && f.value !== undefined && !Array.isArray(f.value) && !isParam(f.value)) errors.push(`${what}: in takes a list or a $param`);
      if (f.op !== "in" && Array.isArray(f.value)) errors.push(`${what}: only in takes a list`);
    };
    for (const [i, f] of (Array.isArray(intent.filter) ? intent.filter : []).entries()) {
      const what = `filter[${i}]`;
      if (!f || typeof f !== "object") { errors.push(`${what} must be an object`); continue; }
      if (f.any !== undefined) {
        if (!Array.isArray(f.any) || f.any.length < 2) errors.push(`${what}: any needs at least two clauses`);
        for (const [j, c] of (Array.isArray(f.any) ? f.any : []).entries()) {
          if (!c || typeof c !== "object") { errors.push(`${what}.any[${j}] must be an object`); continue; }
          checkClause(c, `${what}.any[${j}]`);
        }
      } else {
        checkClause(f, what);
      }
      if (f.needs !== undefined && (!Array.isArray(f.needs) || f.needs.some((n) => typeof n !== "string"))) errors.push(`${what}: needs must be a list of param names`);
    }
  }
  if (intent.record_types !== undefined && (!Array.isArray(intent.record_types) || intent.record_types.some((v) => typeof v !== "string" || !v))) errors.push("record_types must be a list of values");
  if (intent.window !== undefined) {
    const w = intent.window;
    if (!w || typeof w !== "object") errors.push("window must be an object");
    else {
      if (w.since !== undefined && !isParam(w.since)) errors.push("window.since must be a $param");
      if (w.until !== undefined && !isParam(w.until)) errors.push("window.until must be a $param");
    }
  }
  const s = intent.shape;
  if (!s || typeof s !== "object") errors.push("shape is required");
  else if (s.kind === "list") {
    if (!Array.isArray(s.project) || !s.project.length) errors.push("shape.project must name at least one concept");
    for (const r of Array.isArray(s.project) ? s.project : []) ref(r, "shape.project");
  } else if (s.kind === "summary") {
    if (!Array.isArray(s.by) || !s.by.length) errors.push("shape.by must name at least one concept");
    for (const r of Array.isArray(s.by) ? s.by : []) ref(r, "shape.by");
    if (!Array.isArray(s.measures) || !s.measures.length) errors.push("shape.measures must have at least one measure");
    const aliases = new Set();
    for (const [i, m] of (Array.isArray(s.measures) ? s.measures : []).entries()) {
      const what = `shape.measures[${i}]`;
      if (!m || typeof m !== "object") { errors.push(`${what} must be an object`); continue; }
      if (!MEASURES.includes(m.fn)) errors.push(`${what}: fn must be one of ${MEASURES.join(", ")}`);
      if (!["count", "min_time", "max_time"].includes(m.fn)) ref(m.concept, what);
      if (!m.as || !/^[a-z][a-z0-9_]*$/.test(m.as)) errors.push(`${what}: as must be a lowercase identifier`);
      else if (RESERVED_ALIASES.has(m.as)) errors.push(`${what}: ${m.as} is a reserved word on one of the platforms; pick another alias`);
      else if (aliases.has(m.as)) errors.push(`${what}: alias ${m.as} is used twice`);
      else if ((s.by || []).includes(m.as)) errors.push(`${what}: alias ${m.as} is also a by concept`);
      aliases.add(m.as);
    }
  } else {
    errors.push("shape.kind must be list or summary");
  }
  if (s && s.order !== undefined) {
    if (!s.order || typeof s.order !== "object" || typeof s.order.by !== "string") errors.push("shape.order needs by");
    else if (s.order.dir !== undefined && !["asc", "desc"].includes(s.order.dir)) errors.push("shape.order.dir must be asc or desc");
  }
  if (s && s.take !== undefined && (!Number.isInteger(s.take) || s.take <= 0)) errors.push("shape.take must be a positive integer");
  if (intent.scope !== undefined && !["container", "type"].includes(intent.scope)) errors.push("scope must be container or type");
  if (intent.scope === "type") {
    if (!Array.isArray(intent.filter) || !intent.filter.length) errors.push("scope type needs at least one filter: the concept whose type spans the feeds");
    if (intent.record_types !== undefined) errors.push("scope type cannot filter record_types: each feed has its own discriminator");
    for (const [i, f] of (Array.isArray(intent.filter) ? intent.filter : []).entries()) if (f && Array.isArray(f.needs) && f.needs.length) errors.push(`filter[${i}]: a scope type filter cannot be needs-gated`);
  }
  return errors;
}

// The column carrying a concept on a container: a direct binding before an
// alias, so a Splunk plan says sourceIPAddress rather than src.
function columnFor(pack, ref, platform, container) {
  const key = concepts.keyOf(pack.id, ref);
  const list = concepts.bindingsOf(key, platform).filter((b) => b.container === container);
  const b = list.find((x) => !x.alias_of) || list[0];
  if (!b) return null;
  const shape = (x) => {
    const json = x.encoding === "json_string";
    const dot = x.column.indexOf(".");
    return {
      column: x.column,
      dynamic: platform === "sentinel" && x.column.includes(".") && !json,
      encoding: x.encoding || null,
      head: json && dot > 0 ? x.column.slice(0, dot) : null,
      path: json && dot > 0 ? x.column.slice(dot + 1) : null,
    };
  };
  // The other direct bindings of the same concept on this container: a
  // filter on the concept matches the value in any of them.
  const alternatives = list.filter((x) => x !== b && !x.alias_of).map(shape);
  return { ...shape(b), key, alternatives };
}

export function plan(intent, { pack, platform, container, type } = {}) {
  if (intent && intent.scope === "type") return planType(intent, { pack, platform, container, type });
  const unresolved = [];
  const params = new Set();
  const resolve = (ref) => {
    const hit = columnFor(pack, ref, platform, container);
    if (!hit) unresolved.push(ref);
    return { concept: ref, column: hit ? hit.column : null, dynamic: hit ? hit.dynamic : false, encoding: hit ? hit.encoding : null, head: hit ? hit.head : null, path: hit ? hit.path : null, alternatives: hit ? hit.alternatives : [] };
  };
  const clause = (f) => {
    const r = resolve(f.concept);
    note(f.value);
    return { column: r.column, dynamic: r.dynamic, encoding: r.encoding, head: r.head, path: r.path, alternatives: r.alternatives, concept: f.concept, op: f.op, value: f.value, param: paramName(f.value) };
  };
  const note = (v) => {
    const p = paramName(v);
    if (p) params.add(p);
  };
  const filters = (intent.filter || []).map((f) => {
    for (const n of f.needs || []) params.add(n);
    if (f.any) return { any: f.any.map(clause), needs: f.needs || [] };
    return { ...clause(f), needs: f.needs || [] };
  });
  let recordTypes = null;
  if (intent.record_types && intent.record_types.length) {
    const feed = concepts.feed(pack.id);
    const disc = feed && feed.discriminator ? feed.discriminator.split("/").pop() : null;
    const r = disc ? resolve(disc) : { column: null, dynamic: false };
    if (!disc) unresolved.push("(feed has no discriminator)");
    recordTypes = { column: r.column, dynamic: r.dynamic, values: intent.record_types };
  }
  let window = null;
  if (intent.window) {
    note(intent.window.since);
    note(intent.window.until);
    window = { since: paramName(intent.window.since), until: paramName(intent.window.until) };
  }
  const s = intent.shape;
  const shape = { kind: s.kind, order: s.order ? { by: s.order.by, dir: s.order.dir || (s.kind === "list" ? "desc" : "desc") } : null, take: s.take || null };
  if (s.kind === "list") shape.project = s.project.map(resolve);
  else {
    shape.by = s.by.map(resolve);
    shape.measures = s.measures.map((m) => {
      const r = m.concept ? resolve(m.concept) : { column: null, dynamic: false, encoding: null, head: null, path: null };
      return { fn: m.fn, concept: m.concept || null, column: r.column, dynamic: r.dynamic, encoding: r.encoding, head: r.head, path: r.path, as: m.as, limit: m.limit || null };
    });
  }
  if (shape.order && shape.order.by !== "time") {
    const isAlias = s.kind === "summary" && s.measures.some((m) => m.as === shape.order.by);
    if (!isAlias) shape.order = { ...shape.order, ...resolve(shape.order.by) };
  }
  return {
    platform,
    lang: platform === "sentinel" ? "kql" : "spl",
    container,
    time: TIME_COLUMN[platform],
    filters,
    recordTypes,
    window,
    shape,
    scope: intent.scope || "container",
    unresolved: Array.from(new Set(unresolved)),
    params: Array.from(params),
  };
}

// ---------------------------------------------------------------------------
// Scope "type"

// Types whose meaning the feed defines (taxonomy.json: "an opaque id whose
// kind the feed defines", "free text", "one of a fixed set of values").
// One feed's text is not another's, so these never stand in across feeds:
// a concept of such a type resolves on its own bindings only.
const FEED_DEFINED_TYPES = new Set(["text", "enum", "identifier", "count", "flag", "version", "raw_object"]);

function typeOfRef(pack, ref) {
  const c = concepts.concept(concepts.keyOf(pack.id, ref));
  return c && c.type ? c.type : null;
}

function spansFeeds(typeId) {
  return Boolean(typeId) && !FEED_DEFINED_TYPES.has(typeId);
}

function columnShape(b, platform) {
  const json = b.encoding === "json_string";
  const dot = b.column.indexOf(".");
  return {
    column: b.column,
    dynamic: platform === "sentinel" && b.column.includes(".") && !json,
    encoding: b.encoding || null,
    head: json && dot > 0 ? b.column.slice(0, dot) : null,
    path: json && dot > 0 ? b.column.slice(dot + 1) : null,
  };
}

// The concept's own column on the container when it is bound there; else
// the column of the concept of the same type that is bound there. Among
// several: the concept bound on the most containers across both platforms
// (the feed's main carrier of the type, and the same pick on either SIEM),
// then a top-level column before a path into one, then the order the packs
// declare them. null when the type does not land on the container.
function columnByType(pack, ref, platform, container) {
  const own = columnFor(pack, ref, platform, container);
  if (own) return { ...own, via: own.key };
  const typeId = typeOfRef(pack, ref);
  if (!spansFeeds(typeId)) return null;
  const cost = (b) => (b.column.includes(".") ? 1 : 0);
  const candidates = [];
  for (const c of concepts.ofType(typeId, platform)) {
    const list = concepts.bindingsOf(c.key, platform).filter((b) => b.container === container && !b.alias_of);
    if (!list.length) continue;
    const sorted = [...list].sort((a, b) => cost(a) - cost(b));
    const b = sorted[0];
    const breadth = new Set(concepts.bindingsOf(c.key).filter((x) => !x.alias_of).map((x) => `${x.platform}\u0000${x.container}`)).size;
    candidates.push({ ...columnShape(b, platform), key: c.key, via: c.key, alternatives: sorted.slice(1).map((x) => columnShape(x, platform)), rank: [-breadth, cost(b)] });
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => a.rank[0] - b.rank[0] || a.rank[1] - b.rank[1]); // sort is stable: declaration order holds among equals
  const { rank: _rank, ...best } = candidates[0];
  return best;
}

function planType(intent, { pack, platform, container, type }) {
  const filters = Array.isArray(intent.filter) ? intent.filter : [];
  const clauses = filters.flatMap((f) => (f.any ? f.any : [f]));
  const typeId = type || (clauses.length ? typeOfRef(pack, clauses[0].concept) : null);
  if (!typeId) throw new PlanError("no_type", "scope type: the first filter concept has no taxonomy type and none was given");
  if (!spansFeeds(typeId)) throw new PlanError("no_type", `scope type: ${typeId} is a type the feed defines; it does not span feeds`);
  const params = new Set();
  const note = (v) => {
    const p = paramName(v);
    if (p) params.add(p);
  };
  for (const c of clauses) note(c.value);
  let window = null;
  if (intent.window) {
    note(intent.window.since);
    note(intent.window.until);
    window = { since: paramName(intent.window.since), until: paramName(intent.window.until) };
  }

  // The shared shape: one alias per projected concept, its type id.
  const s = intent.shape;
  const aliasOf = (ref, what) => {
    const t = typeOfRef(pack, ref);
    if (!t) throw new PlanError("no_type", `${what}: ${ref} has no taxonomy type, so it cannot be named across feeds`);
    return t;
  };
  const named = (refs, what) => {
    const out = [];
    const seen = new Map();
    for (const ref of refs) {
      const alias = aliasOf(ref, what);
      if (seen.has(alias) && seen.get(alias) !== ref) throw new PlanError("alias_clash", `${what}: ${ref} and ${seen.get(alias)} are both ${alias}; scope type projects one concept per type`);
      seen.set(alias, ref);
      out.push({ concept: ref, type: alias, alias });
    }
    return out;
  };
  const shape = { kind: s.kind, order: s.order ? { by: s.order.by, dir: s.order.dir || "desc" } : null, take: s.take || null };
  const refs = new Set();
  if (s.kind === "list") {
    shape.project = named(s.project, "shape.project");
    for (const p of shape.project) refs.add(p.concept);
  } else {
    shape.by = named(s.by, "shape.by");
    for (const b of shape.by) refs.add(b.concept);
    shape.measures = s.measures.map((m) => {
      const t = m.concept ? aliasOf(m.concept, `measure ${m.as}`) : null;
      if (m.concept) refs.add(m.concept);
      return { fn: m.fn, concept: m.concept || null, type: t, alias: t, as: m.as, limit: m.limit || null };
    });
  }
  if (shape.order && shape.order.by !== "time") {
    const isAlias = s.kind === "summary" && s.measures.some((m) => m.as === shape.order.by);
    if (!isAlias) {
      // An order concept the shape does not carry is resolved per container like a projection.
      const hit = (s.kind === "list" ? shape.project : shape.by).find((x) => x.concept === shape.order.by);
      shape.order = { ...shape.order, alias: hit ? hit.alias : aliasOf(shape.order.by, "shape.order") };
      refs.add(shape.order.by);
    }
  }

  // Every container the type lands on, the one in hand first.
  const all = concepts.containersOfType(platform, typeId);
  const ordered = container && all.includes(container) ? [container, ...all.filter((c) => c !== container)] : all;
  const union = [];
  const dropped = [];
  for (const c of ordered) {
    let missing = null;
    const clause = (f) => {
      const r = columnByType(pack, f.concept, platform, c);
      if (!r && !missing) missing = f.concept;
      return { column: r ? r.column : null, dynamic: r ? r.dynamic : false, encoding: r ? r.encoding : null, head: r ? r.head : null, path: r ? r.path : null, alternatives: r ? r.alternatives : [], via: r ? r.via : null, concept: f.concept, op: f.op, value: f.value, param: paramName(f.value) };
    };
    const fs = filters.map((f) => (f.any ? { any: f.any.map(clause), needs: [] } : { ...clause(f), needs: [] }));
    if (missing) {
      dropped.push({ container: c, reason: `no column for ${missing} (${typeOfRef(pack, missing) || "untyped"})` });
      continue;
    }
    const columns = {};
    for (const ref of refs) {
      const r = columnByType(pack, ref, platform, c);
      columns[ref] = r ? { column: r.column, dynamic: r.dynamic, encoding: r.encoding, head: r.head, path: r.path, via: r.via } : null;
    }
    union.push({ container: c, filters: fs, columns });
  }
  if (!union.length) throw new PlanError("no_containers", `scope type: no container on ${platform} carries ${typeId} with every filter concept${dropped.length ? ` (${dropped.map((d) => `${d.container}: ${d.reason}`).join("; ")})` : ""}`);
  const unresolved = Array.from(refs).filter((ref) => union.every((u) => !u.columns[ref]));
  return {
    platform,
    lang: platform === "sentinel" ? "kql" : "spl",
    container,
    time: TIME_COLUMN[platform],
    filters: [],
    recordTypes: null,
    window,
    shape,
    scope: "type",
    type: typeId,
    union,
    dropped,
    unresolved,
    params: Array.from(params),
  };
}

export default { validate, plan, PlanError, OPS, MEASURES };
