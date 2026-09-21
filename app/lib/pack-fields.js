// Fields: a pack's field catalogue, as a sidecar. A pack describes a feed
// by concept (packs.js, a few dozen per feed); the catalogue a vendor's
// add-on lands is a record per field name (every field the feed carries,
// its layer, role, meaning, decode table, the events it rides on, its
// route to the process), the record types those fields ride on, and the
// join graph among them, far too much to sit in the pack. It lives beside
// the pack, one file per pack, listed in app/packs/index.json under
// "fields" with the containers it describes, and is fetched only when a
// page or a popup needs one of those containers (loadFor), the way the
// values sidecars are (values.js).
//
//   { "format": "reach-pack-fields", "version": 1, "pack": "<pack id>",
//     "source": { "ta_version", "built_at" },     what the records were read from
//     "counts": { ... },                           the build's counts (docs/SPEC.md 10.1)
//     "fields": { "<name>": FieldRecord },
//     "records": { "<event name>": EventRecord },  the record types, each on one container
//     "edges": [ Edge ] }                          the join graph, in ledger order
//
// FieldRecord (docs/SPEC.md 10.1): name, layer, role, role_basis, role_disagreement, type, observed,
//   event_count, events, in_catalogue, legacy, meaning, decode, conversions, sources, cim_targets,
//   edges, same_role_fields, suggested_joins, route { summary, by_event, derived_from, explain? },
//   collision?. The route's explain is composed on registration
//   (reachability.js routeExplain) unless the record carries its own.
// EventRecord: name, sourcetype, fields, field_count, fields_by_role, is_anchor, handles, pid_spaces,
//   pid_fields_unestablished, cim, tenant.
// Edge: id, kind, src, src_sourcetype, dst, dst_sourcetype, dst_table, target_label, basis, basis_ref,
//   cardinality, scope, hazard, note, mechanism, automatic_on, yields, lookup_keys, validation,
//   enrichment_concurs (reachability.js reads this shape).
//
//   validateDocument(doc)                → [errors]
//   register(packId, doc)                → doc   validate and hold a sidecar (tests, and loadPack)
//   ready(packId)                        → true once the pack's sidecar was fetched (or there is none)
//   loaded()                             → true once any sidecar is held
//   await loadPack(packId)               one pack's sidecar, if the index lists one
//   await loadFor(container)             the sidecars listing this container; idempotent
//   await loadBound(platform)            the sidecars listing a container this platform knows
//                                        (declared by a pack or bound by the user); the app's
//                                        boot reads these, a popup reads loadFor
//   packsFor(container)                  → [packId] the sidecars listing the container (index read)
//   field(name) / packOf(name)           → FieldRecord | null / the pack it came from
//   fields()                             → { name: FieldRecord } over every held sidecar
//   names()                              → [name] sorted
//   decode(name)                         → { lookup, meaning_field, values } | null
//   fieldsWithRole(role)                 → [name]
//   fieldOn(sourcetype, name)            → { rec, scope: "sourcetype" | "unscoped", sourcetype } | null
//   sourcetypesFor(name)                 → [sourcetype] the field is known to ride on
//   sourcetypes()                        → [sourcetype] every container the records describe
//   event(name) / eventName(name)        → EventRecord | null / the held key for a record type, through its aliases
//   eventsOn(sourcetype)                 → [event name]
//   coFields(field, event)               → [{ role, fields, fills }]
//   edge(id) / edges() / edgesFor(name)  → Edge | null / [Edge] / [Edge] the name is src or dst of
//   searchIndex()                        → { fields, events, sourcetypes }, each sorted
//   counts()                             → the build's counts, every number a view reads present
//
// No DOM, no store. The only network is fetch() of the bundled sidecars.

import { routeExplain, ROUTE_ORDER } from "./reachability.js";
import * as concepts from "./concepts.js";
import { PLATFORM } from "./platform.js";

export const FORMAT = "reach-pack-fields";
export const VERSION = 1;
export const BUDGET_BYTES = 3 * 1024 * 1024;

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
const DOC_KEYS = new Set(["format", "version", "pack", "source", "counts", "fields", "records", "edges"]);
const EVENT_KEYS = new Set(["name", "sourcetype", "fields", "field_count", "fields_by_role", "is_anchor", "handles", "pid_spaces", "pid_fields_unestablished", "cim", "tenant"]);
const EDGE_KEYS = new Set([
  "id", "kind", "src", "src_sourcetype", "dst", "dst_sourcetype", "dst_table", "target_label", "basis", "basis_ref", "cardinality", "scope",
  "hazard", "note", "mechanism", "automatic_on", "yields", "lookup_keys", "validation", "enrichment_concurs", "label",
]);
const FIELD_KEYS = new Set([
  "name", "layer", "role", "role_basis", "role_disagreement", "type", "observed", "event_count", "events", "in_catalogue", "legacy",
  "meaning", "decode", "conversions", "sources", "cim_targets", "edges", "same_role_fields", "suggested_joins", "route", "collision",
]);
const ROUTE_KEYS = new Set(["summary", "by_event", "derived_from", "explain"]);
const LAYERS = new Set(["raw_fdr", "ta_derived", "cim"]);

const docs = new Map(); // packId → registered sidecar, explain composed
const fetched = new Set(); // packIds whose sidecar was looked for (present or not)
const pending = new Map(); // packId → promise, so two pages asking at once share one fetch
let indexPromise = null;
let table = null; // the merged reads over every held sidecar, rebuilt after register

function isObj(v) {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

function fileUrl(name) {
  return new URL(`../packs/${name}`, import.meta.url).href;
}

async function getJson(name) {
  const res = await fetch(fileUrl(name));
  if (!res.ok) throw new Error(`app/packs/${name}: HTTP ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Validation

function onlyKeys(obj, allowed, where, errors) {
  for (const k of Object.keys(obj)) {
    if (UNSAFE.has(k)) errors.push(`${where}: unsafe key "${k}"`);
    else if (!allowed.has(k)) errors.push(`${where}: unknown key "${k}"`);
  }
}

function checkField(name, rec, errors) {
  const where = `fields.${name}`;
  if (UNSAFE.has(name)) { errors.push(`${where}: unsafe key`); return; }
  if (!isObj(rec)) { errors.push(`${where}: must be an object`); return; }
  onlyKeys(rec, FIELD_KEYS, where, errors);
  if (rec.name !== name) errors.push(`${where}: name must be "${name}"`);
  if (!LAYERS.has(rec.layer)) errors.push(`${where}: layer must be raw_fdr, ta_derived or cim`);
  if (typeof rec.role !== "string" || !rec.role) errors.push(`${where}: role is required`);
  if (!Array.isArray(rec.events) || rec.events.some((e) => typeof e !== "string" || !e)) errors.push(`${where}: events must be an array of names`);
  if (rec.decode !== null && rec.decode !== undefined && !(isObj(rec.decode) && isObj(rec.decode.values))) errors.push(`${where}: decode must be null or { lookup, meaning_field, values }`);
  if (!isObj(rec.route)) { errors.push(`${where}: route is required`); return; }
  onlyKeys(rec.route, ROUTE_KEYS, `${where}.route`, errors);
  if (!ROUTE_ORDER.includes(rec.route.summary)) errors.push(`${where}.route: summary must be one of ${ROUTE_ORDER.join(", ")}`);
  if (!isObj(rec.route.by_event)) errors.push(`${where}.route: by_event must be an object`);
  if (!Array.isArray(rec.route.derived_from)) errors.push(`${where}.route: derived_from must be an array`);
  if (rec.route.explain !== undefined && (typeof rec.route.explain !== "string" || !rec.route.explain)) errors.push(`${where}.route: explain, when carried, is a non-empty string`);
}

function checkEvent(name, rec, errors) {
  const where = `records.${name}`;
  if (UNSAFE.has(name)) { errors.push(`${where}: unsafe key`); return; }
  if (!isObj(rec)) { errors.push(`${where}: must be an object`); return; }
  onlyKeys(rec, EVENT_KEYS, where, errors);
  if (rec.name !== name) errors.push(`${where}: name must be "${name}"`);
  if (typeof rec.sourcetype !== "string" || !rec.sourcetype) errors.push(`${where}: sourcetype is required`);
  if (!Array.isArray(rec.fields) || rec.fields.some((f) => typeof f !== "string" || !f)) errors.push(`${where}: fields must be an array of names`);
  if (rec.handles !== undefined && !Array.isArray(rec.handles)) errors.push(`${where}: handles must be an array`);
}

function checkEdge(e, i, ids, errors) {
  const where = `edges[${i}]`;
  if (!isObj(e)) { errors.push(`${where}: must be an object`); return; }
  onlyKeys(e, EDGE_KEYS, where, errors);
  if (typeof e.id !== "string" || !e.id) errors.push(`${where}: id is required`);
  else if (ids.has(e.id)) errors.push(`${where}: duplicate id ${e.id}`);
  ids.add(e.id);
  if (typeof e.kind !== "string" || !e.kind) errors.push(`${where}: kind is required`);
  if (typeof e.src !== "string" || !e.src) errors.push(`${where}: src is required`);
  if (e.dst !== null && typeof e.dst !== "string") errors.push(`${where}: dst must be a field name or null`);
  if (typeof e.basis !== "string" || !e.basis) errors.push(`${where}: basis is required`);
  if (typeof e.target_label !== "string" || !e.target_label) errors.push(`${where}: target_label is required`);
}

export function validateDocument(doc) {
  const errors = [];
  if (!isObj(doc)) return ["document must be an object"];
  onlyKeys(doc, DOC_KEYS, "document", errors);
  if (doc.format !== FORMAT) errors.push(`format must be ${FORMAT}`);
  if (doc.version !== VERSION) errors.push(`version must be ${VERSION}`);
  if (typeof doc.pack !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(doc.pack)) errors.push("pack must name a pack id");
  if (doc.source !== undefined && !isObj(doc.source)) errors.push("source must be an object");
  if (doc.counts !== undefined && !isObj(doc.counts)) errors.push("counts must be an object");
  if (!isObj(doc.fields)) { errors.push("fields must be an object keyed by field name"); return errors; }
  for (const [name, rec] of Object.entries(doc.fields)) {
    checkField(name, rec, errors);
    if (errors.length > 50) { errors.push("..."); return errors; }
  }
  if (doc.records !== undefined) {
    if (!isObj(doc.records)) errors.push("records must be an object keyed by event name");
    else for (const [name, rec] of Object.entries(doc.records)) {
      checkEvent(name, rec, errors);
      if (errors.length > 50) { errors.push("..."); return errors; }
    }
  }
  if (doc.edges !== undefined) {
    if (!Array.isArray(doc.edges)) errors.push("edges must be an array");
    else {
      const ids = new Set();
      doc.edges.forEach((e, i) => checkEdge(e, i, ids, errors));
    }
  }
  return errors;
}

// ---------------------------------------------------------------------------
// The table of loaded sidecars

// The merged reads over every held sidecar. A field's sourcetypes are the
// sourcetypes of the events it rides on, so a lookup can be scoped to the
// event in hand instead of matching any field of that name anywhere; a
// CIM-layer or TA-derived field rides on whatever the TA's stanza targets
// (cim_targets); an inventory sourcetype (aidmaster, appinfo, userinfo)
// has no event records and is known as an edge destination, whose yields
// are the fields that ride on it.
function rebuild() {
  const fields = {};
  const events = {};
  const edges = [];
  const packOfName = new Map();
  for (const [id, doc] of docs) {
    for (const [name, rec] of Object.entries(doc.fields)) if (!fields[name]) { fields[name] = rec; packOfName.set(name, id); }
    for (const [name, rec] of Object.entries(doc.records || {})) if (!events[name]) events[name] = rec;
    for (const e of doc.edges || []) edges.push(e);
  }
  const sourcetypeOfEvent = new Map();
  const sourcetypeSet = new Set();
  for (const ev of Object.values(events)) {
    if (!ev.sourcetype) continue;
    sourcetypeOfEvent.set(ev.name, ev.sourcetype);
    sourcetypeSet.add(ev.sourcetype);
  }
  const sourcetypesOfField = new Map();
  for (const rec of Object.values(fields)) {
    const sts = new Set();
    for (const evName of rec.events || []) {
      const st = sourcetypeOfEvent.get(evName);
      if (st) sts.add(st);
    }
    for (const t of rec.cim_targets || []) if (t && t.sourcetype) sts.add(t.sourcetype);
    sourcetypesOfField.set(rec.name, sts);
  }
  const edgeById = new Map();
  const edgesBySrc = new Map();
  const edgesByDst = new Map();
  for (const e of edges) {
    if (e.dst_sourcetype) {
      sourcetypeSet.add(e.dst_sourcetype);
      const onDst = [e.dst && e.dst.includes(".") ? e.dst.split(".").slice(1).join(".") : e.dst, ...(e.yields || [])];
      for (const name of onDst) if (name && fields[name]) sourcetypesOfField.get(name).add(e.dst_sourcetype);
    }
    edgeById.set(e.id, e);
    if (!edgesBySrc.has(e.src)) edgesBySrc.set(e.src, []);
    edgesBySrc.get(e.src).push(e);
    if (e.dst) {
      if (!edgesByDst.has(e.dst)) edgesByDst.set(e.dst, []);
      edgesByDst.get(e.dst).push(e);
    }
  }
  table = {
    fields,
    events,
    edges,
    packOfName,
    sourcetypeOfEvent,
    sourcetypesOfField,
    edgeById,
    edgesBySrc,
    edgesByDst,
    index: Object.freeze({
      fields: Object.keys(fields).sort(),
      events: Object.keys(events).sort(),
      sourcetypes: Array.from(sourcetypeSet).sort(),
    }),
  };
}

function tab() {
  if (!table) rebuild();
  return table;
}

// The route paragraph is composed once here, from the sidecar's own
// record types, so every reader sees a record with route.explain set, as
// the build wrote it.
export function register(packId, doc) {
  const errors = validateDocument(doc);
  if (errors.length) throw new Error(`fields for ${packId} rejected: ${errors.join("; ")}`);
  if (doc.pack !== packId) throw new Error(`fields for ${packId} rejected: document names pack ${doc.pack}`);
  const records = doc.records || {};
  const sourcetypeOf = (ev) => (records[ev] && records[ev].sourcetype) || null;
  const fields = {};
  for (const [name, rec] of Object.entries(doc.fields)) {
    const route = { ...rec.route, explain: routeExplain(rec.route, sourcetypeOf) };
    fields[name] = { ...rec, route };
  }
  const held = { ...doc, fields, records, edges: doc.edges || [] };
  docs.set(packId, held);
  fetched.add(packId);
  table = null;
  return held;
}

export function ready(packId) {
  return fetched.has(packId);
}

export function loaded() {
  return docs.size > 0;
}

async function indexDoc() {
  if (!indexPromise) indexPromise = getJson("index.json").catch(() => ({ packs: [], fields: [] }));
  return indexPromise;
}

function entriesOf(index) {
  return Array.isArray(index.fields) ? index.fields.filter((e) => e && typeof e.pack === "string" && typeof e.file === "string") : [];
}

// One pack's sidecar, if the index lists one. A pack with none is marked
// fetched too, so the next page does not ask again. A sidecar that fails
// validation is reported once and left out.
export async function loadPack(packId) {
  if (fetched.has(packId)) return docs.get(packId) || null;
  if (pending.has(packId)) return pending.get(packId);
  const p = (async () => {
    try {
      const entry = entriesOf(await indexDoc()).find((e) => e.pack === packId);
      if (!entry) return null;
      return register(packId, await getJson(entry.file));
    } catch (err) {
      console.warn("[Reach] fields:", String(err && err.message ? err.message : err));
      return null;
    } finally {
      fetched.add(packId);
      pending.delete(packId);
    }
  })();
  pending.set(packId, p);
  return p;
}

export async function packsFor(container) {
  if (!container) return [];
  return entriesOf(await indexDoc()).filter((e) => Array.isArray(e.containers) && e.containers.includes(container)).map((e) => e.pack);
}

export async function loadFor(container) {
  await Promise.all((await packsFor(container)).map((id) => loadPack(id)));
}

// The sidecars describing a container this platform knows: one a pack
// declares or the user bound columns on. On a platform where no such
// container exists nothing is fetched.
export async function loadBound(platform = PLATFORM) {
  const ids = entriesOf(await indexDoc())
    .filter((e) => Array.isArray(e.containers) && e.containers.some((c) => concepts.container(platform, c)))
    .map((e) => e.pack);
  await Promise.all(ids.map((id) => loadPack(id)));
}

// ---------------------------------------------------------------------------
// Reads

export function fields() {
  return tab().fields;
}

export function field(name) {
  if (!name || UNSAFE.has(name)) return null;
  return tab().fields[name] || null;
}

export function packOf(name) {
  if (!name || UNSAFE.has(name)) return null;
  return tab().packOfName.get(name) || null;
}

export function names() {
  return tab().index.fields;
}

export function searchIndex() {
  return tab().index;
}

export function sourcetypes() {
  return tab().index.sourcetypes;
}

// Every sourcetype this field is known to ride on. Empty for a field that
// is in the catalogue but was never observed on an event.
export function sourcetypesFor(name) {
  const set = tab().sourcetypesOfField.get(name);
  return set ? Array.from(set).sort() : [];
}

// The field as it exists ON this sourcetype, or null when the catalogue
// does not place it there. The result says how sure that placement is:
//   scope: "sourcetype"  the field is observed on this sourcetype
//          "unscoped"    the field is known but never observed on any
//                        sourcetype; cannot confirm or deny this one
//   null                 known, and known NOT to be on this sourcetype
//                        (or the sourcetype is unknown here)
export function fieldOn(sourcetype, name) {
  const rec = field(name);
  if (!rec) return null;
  const sts = tab().sourcetypesOfField.get(name) || new Set();
  if (sts.has(sourcetype)) return { rec, scope: "sourcetype", sourcetype };
  if (!sts.size) return { rec, scope: "unscoped", sourcetype };
  return null;
}

// The held key for a record type by the name a record carries: the key
// itself, or its older Falcon-prefixed name for a sensor event the sensor
// now writes bare (FalconProcessHandleOpDetectInfo for a
// ProcessHandleOpDetectInfo row). Null when neither is held.
export function eventName(name) {
  if (!name || UNSAFE.has(name)) return null;
  const events = tab().events;
  if (events[name]) return name;
  if (events[`Falcon${name}`]) return `Falcon${name}`;
  return null;
}

export function event(name) {
  const key = eventName(name);
  return key ? tab().events[key] : null;
}

// Record-type names on a sourcetype, for the discriminator value list.
export function eventsOn(sourcetype) {
  const out = [];
  for (const [ev, st] of tab().sourcetypeOfEvent) if (st === sourcetype) out.push(ev);
  return out.sort();
}

export function edge(id) {
  if (!id) return null;
  return tab().edgeById.get(id) || null;
}

export function edges() {
  return tab().edges;
}

// Every edge this name takes part in, as source or as target.
export function edgesFor(name) {
  if (!name) return [];
  const t = tab();
  const out = [];
  for (const e of t.edgesBySrc.get(name) || []) out.push(e);
  for (const e of t.edgesByDst.get(name) || []) if (!out.includes(e)) out.push(e);
  return out;
}

// Other fields on `eventName`, grouped by role. Within a role: by fill
// rate, descending, when the run measured this event's fields (a field
// with no row on a measured event was never populated: 0); alphabetical
// otherwise. `fills` is null when the event is unmeasured.
export function coFields(fieldName, evName) {
  const rec = event(evName);
  if (!rec) return [];
  return coFieldGroups(rec, tab().fields, fieldName);
}

export function coFieldGroups(eventRec, fieldTable, fieldName) {
  const byRole = eventRec.fields_by_role || {};
  const measured = Boolean(eventRec.tenant && eventRec.tenant.measured);
  const fillOf = (n) => {
    const t = fieldTable[n] && fieldTable[n].tenant && fieldTable[n].tenant.events[eventRec.name];
    return t ? t.fill : 0;
  };
  const out = [];
  for (const role of Object.keys(byRole).sort()) {
    const names = (byRole[role] || []).filter((n) => n !== fieldName);
    if (!names.length) continue;
    const entries = names.map((n) => ({ name: n, fill: measured ? fillOf(n) : null }));
    entries.sort((a, b) => (measured ? b.fill - a.fill : 0) || a.name.localeCompare(b.name));
    out.push({ role, fields: entries.map((e) => e.name), fills: measured ? entries.map((e) => e.fill) : null });
  }
  return out;
}

// The build's counts, with every number a view reads present: a platform
// with no sidecar reads them as zero.
const ROUTE_COUNTS = Object.freeze({ derived: 0, direct_anchor: 0, host_only: 0, mixed: 0, one_hop: 0, unobserved: 0 });
const COUNTS = Object.freeze({
  fields: 0, raw_fdr: 0, ta_derived: 0, cim: 0, events: 0, events_cim_normalized: 0, events_cim_gap: 0,
  edges_confirmed: 0, edges_asserted: 0, edges_validated: 0, enriched: 0, enrichment_batches: 0, decode_tables: 0, decode_values: 0,
});

export function counts() {
  let c = {};
  for (const doc of docs.values()) if (doc.counts) c = { ...c, ...doc.counts };
  return { ...COUNTS, ...c, routes: { ...ROUTE_COUNTS, ...(c.routes || {}) } };
}

export function decode(name) {
  const rec = field(name);
  return rec && rec.decode ? rec.decode : null;
}

export function fieldsWithRole(role) {
  const out = [];
  for (const name of names()) if (fields()[name].role === role) out.push(name);
  return out;
}

export function _reset() {
  docs.clear();
  fetched.clear();
  pending.clear();
  indexPromise = null;
  table = null;
}

export default {
  validateDocument, register, ready, loaded, loadPack, loadFor, loadBound, packsFor,
  field, packOf, fields, names, decode, fieldsWithRole, fieldOn, sourcetypesFor, sourcetypes, searchIndex,
  event, eventName, eventsOn, coFields, coFieldGroups, edge, edges, edgesFor, counts,
  FORMAT, VERSION, BUDGET_BYTES,
};
