// The FDR bundle's searches, rendered from the CrowdStrike Falcon pack's
// queries (app/packs/crowdstrike-falcon.json) by pivot.generate. The views
// and the Splunk popup describe a search as a pivot spec: a kind the FDR
// workflows and pages construct, or an edge of the pack's join graph (pack-fields.js).
// This module maps a spec onto the pack query that renders it, composes the
// bundle's own notes on an edge, and answers in the shape spl.generate has
// always returned.
//
//   generate(spec, params, { form }) → { spl, hazards, asserted, missing, form, kind, sourcetype }
//     spec: { kind: "trace" | "process_events" | "process_table" | "pid_lookup" | "tpid_to_pid"
//                    | "host_lookup" | "event_sample" }
//           { kind: "edge", edge: <bundle edge> }
//     form "macro" renders the query's macro call when it can carry every
//     bound parameter, else the inline form (form says which)
//   macrosFor(spec, params, { form }) → [macro name, …] the pack's own
//     macros (its allowlist) that this rendered form calls on Splunk, for
//     a caller to check against what the instance actually has defined;
//     never throws, [] when the spec has no macro form to speak of
//   throws SplError: bad_pivot, unknown_kind, unscoped_pid, bad_identifier, lint
//
// No DOM.

import * as packs from "./packs.js";
import * as pivot from "./pivot.js";
import { edgeHazards } from "./reachability.js";
import { SplError } from "./spl.js";

export const PACK_ID = "crowdstrike-falcon";
const EXTERNAL = "crowdstrike:events:external";

// Kind → query.
const KIND_QUERY = Object.freeze({
  trace: "cs_trace",
  process_events: "cs_process_events",
  process_table: "cs_process_table",
  pid_lookup: "cs_pid_lookup",
  tpid_to_pid: "cs_tpid_to_pid",
  host_lookup: "cs_host_lookup",
  event_sample: "cs_event_sample",
});

// Bundle edge → query, with the parameters the edge fixes. The value held
// is always $value$; a detection's hash traces on the sensor side's name.
const EDGE_QUERY = Object.freeze({
  e_parent_to_target: { query: "cs_process_anchor" },
  e_context_to_target: { query: "cs_process_anchor" },
  e_tree_grouping: { query: "cs_tree" },
  e_raw_pid: { query: "cs_os_pid" },
  e_aid_to_aidmaster: { query: "cs_host_record" },
  e_sha256_to_appinfo: { query: "cs_file_record" },
  e_usersid_to_userinfo: { query: "cs_user_record" },
  e_sha256string_to_sha256hashdata: { query: "cs_trace", params: { field: "SHA256HashData" } },
  e_agentidstring_to_aid: { query: "cs_detection_host" },
});

// The kinds whose search leans on ContextProcessId attribution.
const ASSERTED_KINDS = new Set(["trace", "process_events"]);

const PLACEHOLDER_RE = /^\$[A-Za-z_][A-Za-z0-9_]*\$$/;

function isBound(v) {
  if (v === undefined || v === null) return false;
  const s = String(v).trim();
  return s !== "" && !PLACEHOLDER_RE.test(s);
}

// Which of the query's containers the search runs on: the one the caller
// names, else the external sourcetype for a detection summary event
// sample, else the query's first.
function containerFor(kind, spec, params, q) {
  if (isBound(params.sourcetype)) return String(params.sourcetype).trim();
  if (spec.sourcetype) return String(spec.sourcetype);
  if (kind === "event_sample" && /^Event_/.test(String(params.event || ""))) return EXTERNAL;
  return q.containers[0];
}

export function targetFor(spec) {
  if (!spec || typeof spec !== "object" || !spec.kind) throw new SplError("bad_pivot", "pivot must be an object with a kind");
  if (spec.kind === "edge") {
    if (!spec.edge || typeof spec.edge !== "object") throw new SplError("bad_pivot", "edge pivot needs pivot.edge");
    const entry = EDGE_QUERY[spec.edge.id];
    if (!entry) throw new SplError("bad_pivot", `no query for edge ${spec.edge.id || spec.edge.src}`);
    return entry;
  }
  const query = KIND_QUERY[spec.kind];
  if (!query) throw new SplError("unknown_kind", `unknown pivot kind: ${spec.kind}`);
  return { query };
}

function asSplError(err, why) {
  if (!err || err.name !== "PivotError") throw err;
  const out = new SplError(err.code, err.code === "unscoped_pid" ? `${why}: ${err.message}` : err.message);
  if (err.violations) out.violations = err.violations;
  return out;
}

// The pack query a spec targets, on the container the params resolve to:
// shared by generate() and macrosFor() so both look up the same template.
function resolveTemplate(spec, params) {
  const target = targetFor(spec);
  const kind = spec.kind;
  const p = { ...(target.params || {}), ...(params || {}) };
  const pack = packs.pack(PACK_ID);
  const first = packs.query(PACK_ID, target.query);
  if (!pack || !first) throw new SplError("no_pack", `the ${PACK_ID} pack is not loaded`);
  const container = containerFor(kind, spec, p, first);
  const q = packs.query(PACK_ID, target.query, { container });
  if (!q) throw new SplError("bad_pivot", `${target.query} does not run on ${container}`);
  return { kind, pack, q, params: p };
}

export function generate(spec, params = {}, opts = {}) {
  const { kind, pack, q, params: p } = resolveTemplate(spec, params);
  const why = kind === "edge" ? `edge ${spec.edge.id || spec.edge.src}` : kind;
  let out;
  try {
    out = opts && opts.form === "macro" ? macroOrInline(q, p, pack) : pivot.generate(q, p, { pack });
  } catch (err) {
    throw asSplError(err, why);
  }
  const hazards = kind === "edge" ? [...edgeHazards(spec.edge, out.sourcetype), ...out.hazards] : out.hazards;
  return {
    spl: out.spl,
    hazards,
    asserted: kind === "edge" ? spec.edge.basis === "asserted" : ASSERTED_KINDS.has(kind),
    missing: out.missing,
    form: out.form,
    kind,
    sourcetype: out.sourcetype,
  };
}

// The macro call, or the inline search when the query has no macro or the
// macro cannot carry a bound parameter.
function macroOrInline(q, p, pack) {
  try {
    return pivot.generate(q, p, { pack, form: "macro" });
  } catch (err) {
    if (err && err.name === "PivotError" && err.code === "no_macro") return pivot.generate(q, p, { pack });
    throw err;
  }
}

// Backtick macro calls in a template's lines, base names only ("cs_index",
// not "cs_index(3)").
const MACRO_CALL_RE = /`([A-Za-z_][A-Za-z0-9_]*)/g;
function macroCallsIn(lines) {
  const out = new Set();
  for (const line of lines || []) for (const m of String(line).matchAll(MACRO_CALL_RE)) out.add(m[1]);
  return out;
}

// Which of the pack's macros a rendered form calls on Splunk, so a caller
// can check them against what conf-macros says exists there:
//   inline  the index macro, only when nothing bound params.index (the
//           only place an inline search ever names a macro: pivot.js's
//           renderLine substitutes `\`cs_index\`` there and nowhere else)
//   macro   whatever name the macro call itself carries, plus the index
//           macro unconditionally: the macro form never takes an inline
//           index, so it always leans on the vendor macro's own index
// Answers [] when the spec has no macro form, the pack is not loaded, or
// the spec cannot be resolved (a param an inline search would still need
// is not this function's business; it never throws).
export function macrosFor(spec, params = {}, { form = "inline" } = {}) {
  let resolved;
  try {
    resolved = resolveTemplate(spec, params);
  } catch {
    return [];
  }
  const { pack, q, params: p } = resolved;
  const template = q && q.spl;
  if (!template) return [];
  const allow = new Set(pack.macros || []);
  const names = new Set();
  if (form === "macro") {
    const lines = (template.macro && template.macro.lines) || [];
    if (!lines.length) return [];
    for (const n of macroCallsIn(lines)) names.add(n);
    if (template.index_macro) names.add(template.index_macro);
  } else if (!isBound(p.index) && template.index_macro) {
    names.add(template.index_macro);
  }
  return [...names].filter((n) => allow.has(n)).sort();
}

export default { generate, targetFor, macrosFor, PACK_ID };
