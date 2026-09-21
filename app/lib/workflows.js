// Guided workflows from every pack, behind one lookup. A pack declares them
// as JSON (packs.js documents the shape); they come out as the definition
// views/workflow.js walks, so the walker never knows which pack a workflow
// came from.
//
//   list()                        → [{ id, title, kicker, packId, entries, containers, hunt }]
//                                   containers: the sourcetypes a pack workflow's results run on here
//   get(id, ctx)                  → definition | null
//                                   a definition carries containers (where its results run on this
//                                   platform), hunt (the scheduled-search wording, or null), meta (per
//                                   input: label, placeholder, hint, required), a gate when the pack asks
//                                   one, and, per result, shape (how a run's rows read, or null), caution
//                                   and gate (true when the result waits on the gate's answer)
//   forField(sourcetype, field)   → [{ id, title, kicker, packId, param }]  workflows a popup offers here
//   forSourcetype(sourcetype)     → [{ id, title, kicker, packId, hunt }]   entered from a value there,
//                                   or a hunt whose searches run on it
//   href(id, params)              → "#/w/<id>?…"  with empty params dropped
//
// A definition:
//   { packId, title, kicker, when, lead, hunt, containers, meta: { param: { label, placeholder, hint, required } },
//     steps: [{ title, why, help, required, names: [param], optional: [param], gate? }],
//     gate?: { param, ask, blocked, choices: [{ value, label, callout: { kind, label, body, link?: { text, href(p) } } }], emits(which) },
//     expect, disambiguate: [], troubleshooting: [{ symptom, causes: [] }],
//     results(p) → [{ id, label, note, pivot: { kind: "pack", edge, packId } | { kind: "edge", edge } | null, params, shape, caution, gate }],
//     chain?(p) → { href, text, inputNames, why },
//     valueLink?: true }
//
// A result's pivot is a pack edge or query resolved onto a container this
// platform can query (kind "pack", rendered by pivot.js), or an edge of the
// pack's fields sidecar (kind "edge", rendered by fdr-queries.js). A query
// written in the other platform's language only does not resolve here.
//
// No DOM. Safe from a content script.

import * as packs from "./packs.js";
import * as packFields from "./pack-fields.js";
import { isSentinel } from "./platform.js";

const LANG = isSentinel() ? "kql" : "spl";

export function href(id, params = {}) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString();
  return `#/w/${encodeURIComponent(id)}${q ? "?" + q : ""}`;
}

// What a result (or a gated result's choice) runs, resolved for this
// platform: null when nothing here can render it.
function resolved(w, r, container) {
  if (r.query) {
    const q = packs.query(w.packId, r.query, { container });
    return q && q[LANG] ? q : null;
  }
  if (r.join) return packFields.edge(r.join);
  return packs.edge(w.packId, r.edge, { container });
}

function pivotOf(w, r, container) {
  const target = resolved(w, r, container);
  if (!target) return null;
  return r.join ? { kind: "edge", edge: target } : { kind: "pack", edge: target, packId: w.packId };
}

function targets(r) {
  return r.gate === true && r.choices ? Object.values(r.choices) : [r];
}

// A pack workflow is listed where at least one of its results renders.
function renderable(w) {
  return (w.results || []).some((r) => targets(r).some((t) => resolved(w, t) !== null));
}

function containersOf(w, container) {
  const out = [];
  for (const r of w.results || []) {
    for (const t of targets(r)) {
      const e = resolved(w, t, container);
      const st = e && (t.join ? e.dst_sourcetype || e.src_sourcetype : e.dst.sourcetype);
      if (st && !out.includes(st)) out.push(st);
    }
  }
  return out;
}

export function list() {
  return packs.workflows().filter(renderable).map((w) => ({ id: w.id, title: w.title, kicker: w.kicker || "", packId: w.packId, entries: w.entries || [], containers: containersOf(w), hunt: Boolean(w.hunt) }));
}

// "$name" → params[name]; "@name" → the pack's list of that name (its
// values); anything else is a literal.
function bind(template, p, lists = {}) {
  const out = {};
  for (const [k, v] of Object.entries(template || {})) {
    if (typeof v === "string" && v.startsWith("$")) {
      const val = p[v.slice(1)];
      if (val !== undefined && val !== null && val !== "") out[k] = val;
    } else if (typeof v === "string" && v.startsWith("@")) {
      const l = lists[v.slice(1)];
      if (l && Array.isArray(l.values)) out[k] = l.values.slice();
    } else out[k] = v;
  }
  return out;
}

function gateOf(w) {
  const g = w.gate;
  if (!g || typeof g !== "object") return null;
  const choices = (g.choices || []).map((c) => {
    const link = c.callout && c.callout.link;
    return {
      value: c.value,
      label: c.label,
      callout: {
        kind: c.callout.kind,
        label: c.callout.label,
        body: c.callout.body,
        ...(link ? { link: { text: link.text, href: (p) => href(link.workflow, bind(link.carry, p)) } } : {}),
      },
    };
  });
  return {
    param: g.param,
    ask: g.ask,
    blocked: g.blocked,
    choices,
    emits: (which) => Boolean((g.choices || []).find((c) => c.value === which && c.emits === true)),
  };
}

function fromPack(w, ctx) {
  // A v2 edge comes back resolved onto a container this platform can query;
  // the one the workflow was opened from (?st=) when the app says so.
  const container = ctx && ctx.params && ctx.params.st ? String(ctx.params.st) : undefined;
  const lists = (packs.pack(w.packId) || {}).lists || {};
  const meta = {};
  for (const [name, m] of Object.entries(packs.params(w.packId))) meta[name] = { label: m.label, placeholder: m.placeholder, hint: m.hint, required: true };
  const gate = gateOf(w);
  // A gated result takes its search from the gate's answer: the choice
  // for it, else no pivot and the result's own params (a placeholder the
  // drawer can still show).
  const targetOf = (r, p) => {
    if (r.gate !== true) return r;
    const choice = gate && p[gate.param] !== undefined ? r.choices[p[gate.param]] : null;
    return choice || null;
  };
  return {
    packId: w.packId,
    title: w.title,
    kicker: w.kicker || "",
    when: w.when || "",
    lead: w.lead || "",
    hunt: w.hunt && typeof w.hunt === "object" ? { schedule: w.hunt.schedule || "" } : null,
    containers: containersOf(w, container),
    meta,
    steps: (w.steps || []).map((s) => ({ title: s.title, why: s.why || "", help: s.help || null, required: s.required !== false, names: s.names || [], optional: s.optional || [], ...(s.gate === true ? { gate: true } : {}) })),
    ...(gate ? { gate } : {}),
    expect: w.expect || "",
    disambiguate: w.disambiguate || [],
    troubleshooting: w.troubleshooting || [],
    ...(w.value_link === true ? { valueLink: true } : {}),
    results: (p) =>
      (w.results || []).map((r) => {
        const t = targetOf(r, p);
        return {
          id: r.id,
          label: r.label,
          note: r.note || "",
          pivot: t ? pivotOf(w, t, container) : null,
          params: bind((t || r).params, p, lists),
          shape: r.shape && Array.isArray(r.shape.columns) ? { columns: r.shape.columns.map((c) => ({ key: c.key, label: c.label || c.key, role: c.role || "value", field: c.field })) } : null,
          caution: r.caution || null,
          ...(r.gate === true ? { gate: true } : {}),
        };
      }),
    chain: w.chain
      ? (p) => ({
          href: href(w.chain.workflow, bind(w.chain.carry, p)),
          text: w.chain.text || `Continue in ${w.chain.workflow}`,
          inputNames: Object.values(w.chain.carry || {}).filter((v) => typeof v === "string" && v.startsWith("$")).map((v) => v.slice(1)),
          why: w.chain.why || "",
        })
      : null,
  };
}

export function get(id, ctx) {
  const w = packs.workflow(id);
  return w && renderable(w) ? fromPack(w, ctx) : null;
}

// A workflow a loaded pack declares but nothing on this platform renders:
// its title, for a page that says so instead of "no such workflow".
export function elsewhere(id) {
  const w = packs.workflow(id);
  return w && !renderable(w) ? { id: w.id, title: w.title, packId: w.packId } : null;
}

export function forField(sourcetype, field) {
  if (!sourcetype || !field) return [];
  const out = [];
  for (const w of list()) {
    for (const e of w.entries) if (e.sourcetype === sourcetype && e.field === field) out.push({ id: w.id, title: w.title, kicker: w.kicker, packId: w.packId, param: e.param });
  }
  return out;
}

// A workflow entered from a value on this sourcetype, or a hunt (no entry
// to start from) whose searches run on it.
export function forSourcetype(sourcetype) {
  if (!sourcetype) return [];
  const seen = new Set();
  const out = [];
  for (const w of list()) {
    if (seen.has(w.id)) continue;
    const entered = w.entries.some((e) => e.sourcetype === sourcetype);
    const runsOn = w.hunt && !w.entries.length && (w.containers || []).includes(sourcetype);
    if (!entered && !runsOn) continue;
    seen.add(w.id);
    out.push({ id: w.id, title: w.title, kicker: w.kicker, packId: w.packId, hunt: Boolean(w.hunt) });
  }
  return out;
}

export default { list, get, elsewhere, forField, forSourcetype, href };
