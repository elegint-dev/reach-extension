// Pure reachability logic, shared by the field view (app/views/field.js) and
// the Splunk-extension popup injectors (extension/). No DOM, no rendering.
// see app/views/field.js for how these get presented in the standalone app.

export const EDGE_ORDER = [
  "causal_attribution",
  "process_lineage",
  "tree_grouping",
  "detection_handle",
  "host_enrichment",
  "file_enrichment",
  "user_enrichment",
  "os_pid",
];

// A search-time lookup is free only where the TA's stanza fires (edge.automatic_on).
export function isAutomaticOn(edge, eventRec) {
  return Boolean(eventRec) && edge.mechanism === "search_time_lookup"
    && (edge.automatic_on || []).includes(eventRec.sourcetype);
}

export function edgeRowsFor(edges, eventRec, fieldName) {
  if (!eventRec) return [];
  const present = new Set(eventRec.fields || []);
  // Offered only if the key rides on this event and, for process-side edges
  // (dst TargetProcessId), is a real handle there, never re-derived from name
  // presence (detection events carry *ProcessId names in an unestablished space).
  const handles = new Set(eventRec.handles || []);
  const usable = (e) => present.has(e.src) && (e.dst !== "TargetProcessId" || handles.has(e.src));
  const rows = edges.filter(usable).map((e) => ({ edge: e, viaSelf: e.src === fieldName }));
  rows.sort((a, b) => {
    if (a.viaSelf !== b.viaSelf) return a.viaSelf ? -1 : 1;
    const ai = EDGE_ORDER.indexOf(a.edge.kind);
    const bi = EDGE_ORDER.indexOf(b.edge.kind);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || String(a.edge.id).localeCompare(String(b.edge.id));
  });
  return rows;
}

// Pivot for a ONE JOIN row: the edge itself, except a co-field hop to the
// process uses `trace` so the held field stays in the search.
export function pivotForEdgeRow(row, fieldName) {
  const e = row.edge;
  if (row.viaSelf) return { kind: "edge", edge: e };
  if (e.dst === "TargetProcessId") return { kind: "trace" };
  return { kind: "edge", edge: e };
}

export function baseParamsForRow(row, fieldName, eventName) {
  const pivot = pivotForEdgeRow(row, fieldName);
  if (pivot.kind === "trace") return { field: fieldName, event: eventName };
  return {};
}

// What the bundle says about a hop, as the drawer's hazard list: the
// validation measure, the asserted chip, the edge's own hazard, the
// search-time lookup the TA already applies, and the sourcetype boundary
// the search crosses to reach `sourcetype`. Rendered ahead of the query's
// own hazards.
export function edgeHazards(edge, sourcetype) {
  const out = [];
  if (edge.basis === "validated" && edge.validation) {
    const v = edge.validation;
    out.push({ level: "note", text: `Measured in run ${v.run}: ${v.resolved} of ${v.total} source events resolved (${(v.rate * 100).toFixed(1)}%).` });
  }
  if (edge.basis === "asserted") out.push({ level: "asserted", text: `${(edge.note || "").trim()} Not corpus-validated.` });
  if (edge.hazard && edge.hazard.text) out.push({ level: edge.hazard.level || "danger", text: edge.hazard.text });
  if (edge.mechanism === "search_time_lookup" && (edge.automatic_on || []).length) {
    const yields = (edge.yields || []).slice(0, 4).join(", ") + ((edge.yields || []).length > 4 ? ", …" : "");
    out.push({
      level: "note",
      text: `The TA applies this lookup automatically at search time on ${edge.automatic_on.join(" and ")}: ${yields} are already on those records. Run this only if that LOOKUP stanza is disabled or you are on another sourcetype.`,
    });
  }
  const srcSt = edge.src_sourcetype;
  const dstSt = edge.dst_sourcetype || sourcetype;
  if (srcSt && dstSt && srcSt !== dstSt) {
    out.push({ level: "note", text: `Sourcetype change: ${edge.src} lives on ${srcSt}; this search runs on ${dstSt}. Field names and CIM coverage differ across the boundary.` });
  }
  return out;
}

// A field's route.summary (the pack's fields sidecar) in one analyst-facing
// phrase: how directly a value on this field ties back to the process that
// produced it. Shared by both extension popups so the wording never drifts.
export const ROUTE_TEXT = Object.freeze({
  direct_anchor: "on an anchor event",
  one_hop: "one join to the process",
  host_only: "host and time only",
  mixed: "depends on the event",
  unobserved: "never observed",
  derived: "computed field",
});

// The order the route classes are named in, in a mixed field's histogram.
export const ROUTE_ORDER = Object.freeze(["direct_anchor", "one_hop", "mixed", "host_only", "unobserved", "derived"]);

const EXTERNAL = "crowdstrike:events:external";

const ROUTE_EXPLAIN = Object.freeze({
  direct_anchor: "This field appears on a process-creation event, so the process context is already present on the same record. No pivot needed.",
  one_hop: "This field appears on events carrying a process handle (usually ContextProcessId). One pivot to ProcessRollup2 recovers the full process context.",
  host_only: "The events carrying this field have NO process handle. You can attribute this to a HOST (aid) and a time, but not to a specific process. Do not fabricate a process link.",
  host_only_external: "This field rides only on detection summary events (crowdstrike:events:external). Their ProcessId / ParentProcessId are renames whose PID space is not established, so no process join is offered from here. The detection workflow leads with the hash and host pivots instead.",
  unobserved: "Never observed on any event in the public corpus, so no route can be computed; run queries/discovery/01 against your tenant to find which events carry it.",
  constant: "This field is a constant the TA sets by EVAL, so there is no raw source and no process route.",
});

// The paragraph under a field's route verdict, composed from the route
// class and the record's own data (its by_event histogram, the fields it
// derives from, the sourcetype its events are on). A record that carries
// an explain of its own (a derived field whose source is a TA intermediate
// no catalogue names) keeps it. sourcetypeOf(eventName) answers the
// sourcetype an event record is on.
export function routeExplain(route, sourcetypeOf = () => null) {
  if (!route) return "";
  if (typeof route.explain === "string") return route.explain;
  const s = route.summary;
  if (s === "mixed") {
    const counts = {};
    for (const info of Object.values(route.by_event || {})) counts[info.route] = (counts[info.route] || 0) + 1;
    const hist = ROUTE_ORDER.filter((r) => counts[r]).map((r) => `${counts[r]} ${r}`).join(", ");
    return `The route depends on which event you are looking at (${hist}); check by_event for the event in hand.`;
  }
  if (s === "derived") {
    const from = route.derived_from || [];
    if (!from.length) return ROUTE_EXPLAIN.constant;
    return `This field is computed by the TA from ${from.join(", ")}, so see ${from[0]}'s route; a process route belongs to the raw source, not to the derived field.`;
  }
  if (s === "host_only") {
    const events = Object.keys(route.by_event || {});
    if (events.length && events.every((e) => sourcetypeOf(e) === EXTERNAL)) return ROUTE_EXPLAIN.host_only_external;
    return ROUTE_EXPLAIN.host_only;
  }
  return ROUTE_EXPLAIN[s] || "";
}

export default { EDGE_ORDER, ROUTE_ORDER, isAutomaticOn, edgeRowsFor, pivotForEdgeRow, baseParamsForRow, edgeHazards, ROUTE_TEXT, routeExplain };
