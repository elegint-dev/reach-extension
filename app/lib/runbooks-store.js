// Runbooks store: the runbook the analyst keeps per rule, seeded from the
// bundle on the first open (app/lib/runbooks.js seedFor) and edited on the
// runbook page. One document under store key "runbooks" (reach.runbooks in
// chrome.storage.local; localStorage, then memory, when served as a plain
// page), keyed by the rule key string parseKey accepts:
//
//   { v: 1, runbooks: { "<rule key>": runbook } }
//   runbook  { format: "reach-runbook", version: 1, id, title,
//              rule: { platform, name, keys: [{ source, by, value }] },
//              seeded_from: { source, id, url, label, ref } | null,
//              description, techniques: [],
//              steps: [{ id, kind, question, why, pivot? }],
//              benign_when: [{ text }], escalate_when: [{ text }],
//              notes, origin: "seed" | "edited", created, updated, edited_at?,
//              learned_from?: { investigations, at } }
//   pivot    { packId, edge, container, type, binds: { "<param>": "<row field>" } }
//
// A stored step never carries a row's values: a pivot names the pack edge
// and the row field each parameter binds from, and bind() fills them from
// the row in hand, so the same runbook fits the next alert for that rule.
//
//   await load()                         → the document; the readers below are sync after it
//   list(), get(id), has(id), bytes()
//   fromSeed(seed)                       → the stored shape of a seedFor() runbook   (pure)
//   bind(runbook, row, { platform })     → { steps: [{ ...step, pivot: { edgeId, edge | null, packId, params, bound, missing, meta } | null }], entities, bound }
//   await seed(seedRunbook)              → the stored runbook: the one already there, else this seed written
//   await reset(id, seedRunbook)         → the seed written over whatever was there, origin "seed"
//   await update(id, patch)              → title, notes, benign_when, escalate_when; marks it edited
//   await addStep(id, step, { at })      → the step added (kind "check" unless it binds a pivot)
//   await updateStep(id, stepId, patch)  → question, why, pivot (null clears it)
//   await moveStep(id, stepId, delta)    → the step moved by delta places
//   await removeStep(id, stepId)
//   await remove(id)
//   await draftFrom(ruleKey, { row, platform, investigations? })
//                                        → { ruleKey, investigations: n, needed, ready, label, steps, outcome,
//                                            benign_when, escalate_when } | null
//                                          the notebook's closed investigations that started from this rule
//                                          (the last MAX_LEARN of them): a pivot run in at least a third of
//                                          them is a step, bound to the pack edge whose label it carries
//                                          when the packs know one; the most common close outcome and the
//                                          reasons given with it. ready is false under MIN_LEARN. Never
//                                          written: Adopt is the analyst's call
//   await adoptDraft(id, draft)          → the runbook with the draft's steps and conditions it lacked,
//                                          learned_from stamped, marked edited
//   check(raw)                           → a sanitised runbook, or throws with why   (import check, pure)
//   exportDoc(ids?)                      → { format: "reach-runbooks", version: 1, exported_at, runbooks: [] }
//   await importDoc(doc, { mode })       → { added, updated, kept, rejected: [{ id, why }] }
//                                          merge (default): newer updated wins; replace: theirs only
//   subscribe(fn)                        → fn({ type: "change" | "pruned", ... }); returns unsubscribe
//   await prune()                        → { pruned: [{ id, title }], warning }
//
// Writes go through app/lib/document.js, one serialised chain that rereads
// the document first, so two contexts never overwrite each other's
// runbook. Past the size bound the oldest unedited seeds go first, then the
// oldest edited runbooks. No DOM.

import { versionedDocument, newId as makeId } from "./document.js";
import * as packs from "./packs.js";
import { parseKey, keyString, entitiesOf, pivotOptions, ENTITY_FIELDS } from "./runbooks.js";
import { PLATFORM } from "./platform.js";
import { OUTCOMES } from "./notebook-md.js";

export const KEY = "runbooks";
export const VERSION = 1;
export const FORMAT = "reach-runbook";
export const LIST_FORMAT = "reach-runbooks";
export const MAX_BYTES = 500_000;
export const MAX_STEPS = 60;
export const MAX_CONDITIONS = 40;
export const MAX_TEXT = 4000;
export const KINDS = Object.freeze(["confirm", "false_positive", "pivot", "close", "check"]);
export const MIN_LEARN = 3;
export const MAX_LEARN = 20;

function now() {
  return Date.now();
}

function newId(prefix) {
  return makeId(prefix);
}

function str(v, max = MAX_TEXT) {
  if (v === undefined || v === null) return "";
  return String(v).slice(0, max);
}

function text(v, max = MAX_TEXT) {
  return str(v, max).trim();
}

function empty() {
  return { v: VERSION, runbooks: {} };
}

// ---- shape -------------------------------------------------------------

function sanitizeKeys(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  const seen = new Set();
  for (const k of list) {
    if (!k || typeof k !== "object") continue;
    const p = parseKey(keyString({ source: text(k.source, 40), by: text(k.by, 8), value: text(k.value, 500) }));
    if (!p) continue;
    const s = keyString(p);
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(p);
  }
  return out;
}

function sanitizePivot(p) {
  if (!p || typeof p !== "object") return null;
  const packId = text(p.packId, 100);
  const edge = text(p.edge, 100);
  if (!packId || !edge) return null;
  const binds = {};
  for (const [param, field] of Object.entries(p.binds && typeof p.binds === "object" ? p.binds : {})) {
    const pn = text(param, 60);
    const fn = text(field, 100);
    if (pn && fn && !/^(__proto__|constructor|prototype)$/.test(pn)) binds[pn] = fn;
  }
  return { packId, edge, container: text(p.container, 200) || null, type: text(p.type, 60) || null, binds };
}

function sanitizeStep(s, i) {
  if (!s || typeof s !== "object") return null;
  const question = text(s.question, 500);
  if (!question) return null;
  const pivot = sanitizePivot(s.pivot);
  let kind = KINDS.includes(s.kind) ? s.kind : pivot ? "pivot" : "check";
  if (kind === "pivot" && !pivot) kind = "check";
  return { id: text(s.id, 120) || `step-${i + 1}`, kind, question, why: text(s.why) || null, pivot };
}

function sanitizeConditions(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const c of list) {
    const t = text(typeof c === "string" ? c : c && c.text, 1000);
    if (t) out.push({ text: t });
    if (out.length >= MAX_CONDITIONS) break;
  }
  return out;
}

// A foreign document becomes a runbook or a reason it is not.
export function check(raw) {
  if (!raw || typeof raw !== "object") throw new Error("Not a runbook: expected an object.");
  if (raw.format !== FORMAT) throw new Error(`Not a runbook: expected format ${FORMAT}, got ${raw.format === undefined ? "none" : JSON.stringify(raw.format)}.`);
  if (raw.version !== VERSION) throw new Error(`Runbook version ${raw.version} is not ${VERSION}.`);
  const id = text(raw.id, 600);
  if (!parseKey(id)) throw new Error(`Runbook id ${JSON.stringify(id)} is not a rule key (source:by:value).`);
  if (!Array.isArray(raw.steps)) throw new Error(`Runbook ${id} has no steps list.`);
  const steps = [];
  const ids = new Set();
  raw.steps.slice(0, MAX_STEPS).forEach((s, i) => {
    const st = sanitizeStep(s, i);
    if (!st) return;
    while (ids.has(st.id)) st.id = `${st.id}-${i + 1}`;
    ids.add(st.id);
    steps.push(st);
  });
  if (!steps.length) throw new Error(`Runbook ${id} has no step with a question.`);
  const rule = raw.rule && typeof raw.rule === "object" ? raw.rule : {};
  const keys = sanitizeKeys(rule.keys);
  const own = parseKey(id);
  if (!keys.some((k) => keyString(k) === id)) keys.unshift(own);
  const sf = raw.seeded_from && typeof raw.seeded_from === "object" ? raw.seeded_from : null;
  const created = Number.isFinite(raw.created) ? raw.created : now();
  const updated = Number.isFinite(raw.updated) ? raw.updated : created;
  return {
    format: FORMAT,
    version: VERSION,
    id,
    title: text(raw.title, 300) || text(rule.name, 300) || own.value,
    rule: { platform: rule.platform === "sentinel" ? "sentinel" : "splunk", name: text(rule.name, 300) || null, keys },
    seeded_from: sf ? { source: text(sf.source, 40) || null, id: text(sf.id, 120) || null, url: /^https?:\/\//.test(str(sf.url, 500)) ? text(sf.url, 500) : null, label: text(sf.label, 100) || null, ref: text(sf.ref, 100) || null } : null,
    description: text(raw.description),
    techniques: Array.isArray(raw.techniques) ? raw.techniques.map((t) => text(t, 20)).filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)).slice(0, 20) : [],
    steps,
    benign_when: sanitizeConditions(raw.benign_when),
    escalate_when: sanitizeConditions(raw.escalate_when),
    notes: text(raw.notes),
    origin: raw.origin === "edited" ? "edited" : "seed",
    created,
    updated,
    ...(raw.origin === "edited" && Number.isFinite(raw.edited_at) ? { edited_at: raw.edited_at } : {}),
    ...(raw.learned_from && typeof raw.learned_from === "object" && Number.isFinite(raw.learned_from.investigations) && raw.learned_from.investigations > 0 ? { learned_from: { investigations: Math.floor(raw.learned_from.investigations), at: Number.isFinite(raw.learned_from.at) ? raw.learned_from.at : updated } } : {}),
  };
}

// seedFor()'s runbook, with the row taken out of it: a pivot step keeps
// the pack edge and the row field each parameter came from, not the value.
export function fromSeed(seed) {
  const t = now();
  const steps = (seed.steps || []).map((s, i) => {
    if (!s.pivot || !s.pivot.edge) return { id: s.id || `step-${i + 1}`, kind: s.kind || "check", question: s.question, why: s.why || null, pivot: null };
    const meta = s.pivot.meta || {};
    const binds = { value: s.entity ? s.entity.field : "value" };
    for (const p of s.pivot.bound || []) if (p !== "value" && meta[p] && meta[p].from_field) binds[p] = meta[p].from_field;
    return {
      id: s.id,
      kind: "pivot",
      question: s.entity ? `${s.pivot.edge.label} for ${s.entity.field}` : s.pivot.edge.label,
      why: s.why || null,
      pivot: { packId: s.pivot.packId, edge: s.pivot.edge.id, container: s.pivot.edge.src.sourcetype, type: s.entity ? s.entity.type : null, binds },
    };
  });
  return check({
    format: FORMAT,
    version: VERSION,
    id: seed.id,
    title: seed.title,
    rule: seed.rule,
    seeded_from: seed.seeded_from ? { source: seed.seeded_from.source, id: seed.seeded_from.id, url: seed.seeded_from.url, label: seed.seeded_from.label, ref: seed.seeded_from.ref } : null,
    description: seed.description,
    techniques: seed.techniques,
    steps,
    benign_when: seed.benign_when,
    escalate_when: seed.escalate_when,
    notes: "",
    origin: "seed",
    created: t,
    updated: t,
  });
}

// The row's value for a bind: the named field, else any field the row
// carries of the pivot's entity type (dest on one row, dest_host on the next).
function rowValue(row, field, type) {
  const v = row[field];
  if (v !== undefined && v !== null && String(v).trim() !== "") return String(v).trim();
  if (!type) return "";
  for (const [f, t] of Object.entries(ENTITY_FIELDS)) {
    if (t !== type) continue;
    const w = row[f];
    if (w !== undefined && w !== null && String(w).trim() !== "") return String(w).trim();
  }
  for (const e of entitiesOf(row)) if (e.type === type) return e.value;
  return "";
}

export function bind(runbook, row = {}, { platform = PLATFORM } = {}) {
  const entities = entitiesOf(row);
  let bound = 0;
  const steps = (runbook.steps || []).map((s) => {
    if (!s.pivot) return { ...s, pivot: null };
    const edge = packs.edge(s.pivot.packId, s.pivot.edge, { container: s.pivot.container || undefined });
    if (!edge) return { ...s, pivot: { ...s.pivot, edgeId: s.pivot.edge, edge: null, params: {}, bound: [], missing: [], meta: {} } };
    const meta = packs.params(s.pivot.packId, edge.src.sourcetype);
    const params = {};
    const filled = [];
    const missing = [];
    for (const [p, field] of Object.entries(s.pivot.binds || {})) {
      const v = rowValue(row, field, p === "value" ? s.pivot.type : null);
      if (v) {
        params[p] = v;
        filled.push(p);
      } else missing.push({ param: p, field });
    }
    if (filled.length) bound++;
    return { ...s, pivot: { ...s.pivot, edgeId: s.pivot.edge, edge, packId: s.pivot.packId, params, bound: filled, missing, meta, platform } };
  });
  return { steps, entities, bound };
}

// ---- document ------------------------------------------------------------

function adopt(raw) {
  const out = empty();
  if (!raw || typeof raw !== "object" || !raw.runbooks || typeof raw.runbooks !== "object") return out;
  for (const [id, rb] of Object.entries(raw.runbooks)) {
    try {
      const s = check(rb);
      if (s.id === id) out.runbooks[id] = s;
    } catch {
      /* dropped */
    }
  }
  return out;
}

// Unedited seeds go first, oldest first; then the oldest edited runbooks.
function pruneInPlace(d, { bytes: size, budget }) {
  const pruned = [];
  const candidates = () =>
    Object.values(d.runbooks).sort((a, b) => ((a.origin === "edited") === (b.origin === "edited") ? (a.updated || 0) - (b.updated || 0) : a.origin === "edited" ? 1 : -1));
  while (size(d) > budget) {
    const victim = candidates()[0];
    if (!victim) break;
    delete d.runbooks[victim.id];
    pruned.push({ id: victim.id, title: victim.title, origin: victim.origin });
  }
  const edited = pruned.filter((p) => p.origin === "edited");
  let warning = "";
  if (pruned.length) warning = `The runbooks were over their ${Math.round(budget / 1000)} KB bound: ${pruned.length === 1 ? "the oldest" : `the ${pruned.length} oldest`} (${pruned.map((p) => p.title).join(", ")}) ${pruned.length === 1 ? "was" : "were"} removed${edited.length ? `, ${edited.length} of them edited by you` : ""}. Export what you want to keep.`;
  return { pruned, warning };
}

const D = versionedDocument({ key: KEY, version: VERSION, empty, adopt, prune: pruneInPlace, budget: MAX_BYTES });

export function load(opts) {
  return D.load(opts);
}

export function bytes(d) {
  return D.bytes(d);
}

export function prune() {
  return D.prune();
}

export function subscribe(fn) {
  return D.subscribe(fn);
}

// ---- readers -------------------------------------------------------------

export function list() {
  return Object.values(D.get().runbooks).sort((a, b) => (b.updated || 0) - (a.updated || 0));
}

export function get(id) {
  const d = D.get();
  return Object.prototype.hasOwnProperty.call(d.runbooks, id) ? d.runbooks[id] : null;
}

export function has(id) {
  return get(id) !== null;
}

function need(d, id) {
  const rb = Object.prototype.hasOwnProperty.call(d.runbooks, id) ? d.runbooks[id] : null;
  if (!rb) throw new Error(`No runbook ${id}.`);
  return rb;
}

function edited(rb) {
  const t = now();
  rb.updated = t;
  rb.edited_at = t;
  rb.origin = "edited";
}

// ---- writers -------------------------------------------------------------

export function seed(seedRunbook) {
  const rb = fromSeed(seedRunbook);
  return D.update((d) => {
    const cur = Object.prototype.hasOwnProperty.call(d.runbooks, rb.id) ? d.runbooks[rb.id] : null;
    if (cur) return cur;
    d.runbooks[rb.id] = rb;
    return rb;
  });
}

export function reset(id, seedRunbook) {
  const rb = fromSeed(seedRunbook);
  if (rb.id !== id) throw new Error(`The seed is for ${rb.id}, not ${id}.`);
  return D.update((d) => {
    const cur = Object.prototype.hasOwnProperty.call(d.runbooks, id) ? d.runbooks[id] : null;
    if (cur) rb.created = cur.created;
    d.runbooks[id] = rb;
    return rb;
  });
}

const PATCHABLE = ["title", "notes", "benign_when", "escalate_when"];

export function update(id, patch) {
  return D.update((d) => {
    const rb = need(d, id);
    for (const k of PATCHABLE) {
      if (!patch || patch[k] === undefined) continue;
      if (k === "title") rb.title = text(patch.title, 300) || rb.title;
      else if (k === "notes") rb.notes = text(patch.notes);
      else rb[k] = sanitizeConditions(patch[k]);
    }
    edited(rb);
    return rb;
  });
}

function findStep(rb, stepId) {
  const i = rb.steps.findIndex((s) => s.id === stepId);
  if (i < 0) throw new Error(`No step ${stepId} on ${rb.title}.`);
  return i;
}

export function addStep(id, step = {}, { at = null } = {}) {
  return D.update((d) => {
    const rb = need(d, id);
    if (rb.steps.length >= MAX_STEPS) throw new Error(`A runbook keeps at most ${MAX_STEPS} steps.`);
    const s = sanitizeStep({ ...step, id: newId("step"), question: step.question || "New step" }, rb.steps.length);
    const i = at === null || at === undefined ? rb.steps.length : Math.max(0, Math.min(rb.steps.length, Number(at)));
    rb.steps.splice(i, 0, s);
    edited(rb);
    return s;
  });
}

export function updateStep(id, stepId, patch = {}) {
  return D.update((d) => {
    const rb = need(d, id);
    const s = rb.steps[findStep(rb, stepId)];
    if (patch.question !== undefined) s.question = text(patch.question, 500) || s.question;
    if (patch.why !== undefined) s.why = text(patch.why) || null;
    if (patch.pivot !== undefined) {
      s.pivot = sanitizePivot(patch.pivot);
      if (s.pivot) s.kind = "pivot";
      else if (s.kind === "pivot") s.kind = "check";
    }
    edited(rb);
    return s;
  });
}

export function moveStep(id, stepId, delta) {
  return D.update((d) => {
    const rb = need(d, id);
    const i = findStep(rb, stepId);
    const j = Math.max(0, Math.min(rb.steps.length - 1, i + Number(delta || 0)));
    if (j === i) return rb.steps[i];
    const [s] = rb.steps.splice(i, 1);
    rb.steps.splice(j, 0, s);
    edited(rb);
    return s;
  });
}

export function removeStep(id, stepId) {
  return D.update((d) => {
    const rb = need(d, id);
    if (rb.steps.length <= 1) throw new Error("A runbook keeps at least one step.");
    const [s] = rb.steps.splice(findStep(rb, stepId), 1);
    edited(rb);
    return s;
  });
}

export function remove(id) {
  return D.update((d) => {
    const rb = need(d, id);
    delete d.runbooks[id];
    return rb;
  });
}

// ---- learning from the notebook ----------------------------------------------

// What one pivot entry is counted as across investigations: its name (the
// pack edge's label, as recordPivot writes it), else its query text with
// the origin pin's value replaced by the pin's field name, so the same
// pivot on another host is the same key.
function pivotKeyOf(e, inv) {
  const name = text(e.name, 300);
  if (name) return { key: `name:${name.toLowerCase()}`, name };
  const q = e.query && text(e.query.text, 4000);
  if (!q) return null;
  const origin = e.origin ? (inv.entries || []).find((x) => x.id === e.origin) : null;
  let t = q;
  if (origin && origin.value) t = t.split(String(origin.value)).join(`$${origin.field || (origin.from && origin.from.column) || "value"}`);
  t = t.replace(/\s+/g, " ").trim();
  return { key: `query:${t}`, name: null, query: { text: t, language: (e.query && e.query.language) || null } };
}

function median(list) {
  const a = list.slice().sort((x, y) => x - y);
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

function shortText(t, max = 80) {
  const o = String(t || "").replace(/\s+/g, " ").trim();
  return o.length > max ? `${o.slice(0, max - 1)}…` : o;
}

export async function draftFrom(ruleKey, { row = {}, platform = PLATFORM, investigations = null, notebook = null } = {}) {
  const rk = typeof ruleKey === "string" ? { key: ruleKey } : ruleKey;
  const key = rk && (rk.key || rk.id || (rk.keys && rk.keys[0] && keyString(rk.keys[0])));
  if (!key) return null;
  let invs = investigations;
  if (!invs) {
    const nb = notebook || (await import("./notebook.js"));
    await nb.load();
    invs = nb.list({ status: "closed", rule: key });
  }
  invs = invs
    .filter((inv) => inv && inv.status === "closed" && inv.origin && inv.origin.ruleKey === key)
    .sort((a, b) => (b.closed || b.updated || 0) - (a.closed || a.updated || 0))
    .slice(0, MAX_LEARN);
  const n = invs.length;
  const out = { ruleKey: key, investigations: n, needed: MIN_LEARN, ready: n >= MIN_LEARN, label: `from your last ${n} investigation${n === 1 ? "" : "s"}`, steps: [], outcome: null, benign_when: [], escalate_when: [] };
  if (!n) return out;

  const seen = new Map();
  for (const inv of invs) {
    const pivots = (inv.entries || []).filter((e) => e.kind === "pivot");
    const inThis = new Set();
    pivots.forEach((e, i) => {
      const k = pivotKeyOf(e, inv);
      if (!k || inThis.has(k.key)) return;
      inThis.add(k.key);
      const origin = e.origin ? (inv.entries || []).find((x) => x.id === e.origin) : null;
      if (!seen.has(k.key)) seen.set(k.key, { ...k, count: 0, positions: [], field: origin ? origin.field || (origin.from && origin.from.column) || null : null });
      const rec = seen.get(k.key);
      rec.count++;
      rec.positions.push(i);
    });
  }
  const kept = Array.from(seen.values())
    .filter((r) => r.count * 3 >= n)
    .sort((a, b) => median(a.positions) - median(b.positions) || b.count - a.count || a.key.localeCompare(b.key));
  const options = kept.length ? pivotOptions(row, platform) : [];
  const stored = get(key);
  out.steps = kept.map((r, i) => {
    const option = r.name ? options.find((o) => o.label.toLowerCase() === r.name.toLowerCase()) || null : null;
    const present = Boolean(stored && stored.steps.some((s) => (option && s.pivot && s.pivot.packId === option.pivot.packId && s.pivot.edge === option.pivot.edge) || (!option && s.question.toLowerCase() === (r.name || `Run ${shortText(r.query.text)}`).toLowerCase())));
    return {
      id: `learned-${i + 1}`,
      kind: option ? "pivot" : "check",
      question: r.name || `Run ${shortText(r.query.text)}`,
      why: `Run in ${r.count} of ${n} investigation${n === 1 ? "" : "s"}${r.field ? `, from ${r.field}` : ""}.`,
      count: r.count,
      of: n,
      pivot: option ? { ...option.pivot } : null,
      query: r.query || null,
      present,
    };
  });

  const counts = new Map(OUTCOMES.map((o) => [o, 0]));
  const reasons = { benign: new Map(), escalated: new Map() };
  for (const inv of invs) {
    const o = inv.outcome;
    if (!o || !counts.has(o.result)) continue;
    counts.set(o.result, counts.get(o.result) + 1);
    const r = text(o.reason, 1000);
    if (r && reasons[o.result]) reasons[o.result].set(r, (reasons[o.result].get(r) || 0) + 1);
  }
  let best = null;
  for (const o of OUTCOMES) if (counts.get(o) > 0 && (!best || counts.get(o) > counts.get(best))) best = o;
  if (best) out.outcome = { result: best, count: counts.get(best), of: n };
  // The reasons given most often first, then as first seen (newest first).
  const byCount = (m) => Array.from(m.entries()).sort((a, b) => b[1] - a[1]).map(([t, count]) => ({ text: t, count }));
  out.benign_when = byCount(reasons.benign);
  out.escalate_when = byCount(reasons.escalated);
  return out;
}

// The draft's steps the runbook lacks go in before its close step, the
// conditions it lacks onto its lists; learned_from says how many
// investigations they came from.
export function adoptDraft(id, draft) {
  return D.update((d) => {
    const rb = need(d, id);
    const steps = Array.isArray(draft && draft.steps) ? draft.steps : [];
    const closeAt = () => rb.steps.findIndex((s) => s.kind === "close");
    for (const st of steps) {
      if (st.present) continue;
      const dup = rb.steps.some((s) => (st.pivot && s.pivot && s.pivot.packId === st.pivot.packId && s.pivot.edge === st.pivot.edge) || (!st.pivot && s.question.toLowerCase() === String(st.question || "").toLowerCase()));
      if (dup || rb.steps.length >= MAX_STEPS) continue;
      const s = sanitizeStep({ question: st.question, why: st.pivot || !st.query ? st.why : `${st.why || ""} ${st.query.text}`.trim(), pivot: st.pivot, id: newId("step") }, rb.steps.length);
      if (!s) continue;
      const at = closeAt();
      rb.steps.splice(at < 0 ? rb.steps.length : at, 0, s);
    }
    for (const k of ["benign_when", "escalate_when"]) {
      const have = new Set(rb[k].map((c) => c.text.toLowerCase()));
      const add = sanitizeConditions(draft && draft[k]).filter((c) => !have.has(c.text.toLowerCase()));
      rb[k] = rb[k].concat(add).slice(0, MAX_CONDITIONS);
    }
    rb.learned_from = { investigations: Number(draft && draft.investigations) || 0, at: now() };
    edited(rb);
    return rb;
  });
}

// ---- share -----------------------------------------------------------------

export function exportDoc(ids = null) {
  const all = list().filter((rb) => !ids || ids.includes(rb.id));
  return { format: LIST_FORMAT, version: VERSION, exported_at: new Date().toISOString(), runbooks: JSON.parse(JSON.stringify(all)) };
}

// The runbooks in a file: one runbook, a runbooks list, or any envelope
// carrying a runbooks array (the share page's export).
export function runbooksIn(raw) {
  if (!raw || typeof raw !== "object") return null;
  if (raw.format === FORMAT) return [raw];
  if (Array.isArray(raw.runbooks)) return raw.runbooks;
  return null;
}

export async function importDoc(input, { mode = "merge" } = {}) {
  const raw = typeof input === "string" ? JSON.parse(input) : input;
  const theirs = runbooksIn(raw);
  if (!theirs) throw new Error(`Not a runbook export (expected format ${FORMAT} or ${LIST_FORMAT}).`);
  const result = { added: 0, updated: 0, kept: 0, rejected: [] };
  const ok = [];
  theirs.forEach((r, i) => {
    try {
      ok.push(check(r));
    } catch (err) {
      result.rejected.push({ id: r && typeof r === "object" && r.id ? String(r.id).slice(0, 200) : `#${i + 1}`, why: String((err && err.message) || err) });
    }
  });
  await D.update((d) => {
    if (mode === "replace") {
      d.runbooks = {};
      for (const rb of ok) {
        d.runbooks[rb.id] = rb;
        result.added++;
      }
      return;
    }
    for (const rb of ok) {
      const cur = Object.prototype.hasOwnProperty.call(d.runbooks, rb.id) ? d.runbooks[rb.id] : null;
      if (!cur) {
        d.runbooks[rb.id] = rb;
        result.added++;
      } else if ((rb.updated || 0) > (cur.updated || 0)) {
        d.runbooks[rb.id] = rb;
        result.updated++;
      } else result.kept++;
    }
  });
  return result;
}

export function _reset() {
  D._reset();
}

export default { KEY, VERSION, FORMAT, LIST_FORMAT, MAX_BYTES, MAX_STEPS, KINDS, MIN_LEARN, MAX_LEARN, load, list, get, has, bytes, fromSeed, bind, seed, reset, update, addStep, updateStep, moveStep, removeStep, remove, draftFrom, adoptDraft, check, exportDoc, runbooksIn, importDoc, subscribe, prune, _reset };
