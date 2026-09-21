// The concept model: what a field means, written once per feed, and the
// bindings that say where that meaning lands on each platform.
//
// A pack v2 (see packs.js) describes a feed with canonical concept ids
// (`principal_arn`: meaning, role, tags, sensitivity, decode, hazards) and
// lists bindings (platform, container, column) → concept, where container
// is a Splunk sourcetype or a Sentinel table and column a field name or a
// dynamic path there. Several bindings per concept and platform are
// normal: a vendor table and a custom table for one feed, or a raw field
// and the TA's CIM alias of it. Above feeds sits the taxonomy
// (taxonomy.js): a concept's `type` makes CloudTrail's source address and
// an Entra sign-in's the same kind of thing.
//
// This module is the resolver. packs.js registers every v2 pack here and
// answers its (sourcetype, field) reads through resolve(); catalogue.js
// keys the user layer by concept when a binding exists. Concept keys are
// "<pack id>/<concept id>"; a binding in one pack may point at another
// pack's concept by that qualified form (the dev sample tables bind to the
// CloudTrail feed's concepts without repeating a word of its prose).
//
//   register(pack)                        index a validated v2 pack (packs.js calls this)
//   keyOf(packId, ref)                    → "pack/concept" for a bare or qualified ref
//   concept(key)                          → Concept | null
//   resolve(platform, container, column)  → { key, concept, binding } | null
//   bindingsOf(key, platform?)            → [binding], the pack's own first
//   allBindings(platform?)                → [binding], every concept's, as bindingsOf lists them
//   columnsOn(platform, container)        → [column]
//   containers(platform)                  → [{ name, platform, packIds, feedKeys, kind, description, tags, note, hazards: [{ id, level, text }] }]
//   container(platform, name)             → the same record | null
//   feed(packId)                          → { key, packId, id, label, description, tags, discriminator } | null
//   conceptsOf(packId)                    → [Concept]
//   ofType(typeId, platform?)             → [Concept] whose type is typeId (or a child of it)
//   containersOfType(platform, typeId)    → [container], every container a concept of the type binds on directly
//
// Concept: { key, packId, id, label, type, typeLabel, typeDescription, shape, description, notes,
//            role, tags, sensitivity, cim, decode, hazards: [{ id, level, text }], feed }
// binding: { platform, container, column, key, packId, note, alias_of, basis, basis_ref, cim, encoding }
//   encoding "json_string": the column's first segment is a JSON string, the rest of the dotted
//   name a path into it (AWSCloudTrail's RequestParameters.userName); a compiler parses before reaching in
//
// When two packs bind the same (platform, container, column), the pack
// that owns the concept wins over one that only refers to it; among equals,
// the first registered. No DOM. Safe from a content script.

import * as taxonomy from "./taxonomy.js";
import { PLATFORM } from "./platform.js";

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

const concepts = new Map(); // key → raw { packId, id, rec, pack }
const bindings = new Map(); // platform → Map(container → Map(column → [binding]))
const byConcept = new Map(); // key → [binding]
const containerMeta = new Map(); // platform → Map(name → record)
const feeds = new Map(); // packId → feed record

export function keyOf(packId, ref) {
  if (!ref || typeof ref !== "string") return null;
  return ref.includes("/") ? ref : `${packId}/${ref}`;
}

function safe(k) {
  return typeof k === "string" && k !== "" && !UNSAFE.has(k);
}

function ensure(map, key, make) {
  if (!map.has(key)) map.set(key, make());
  return map.get(key);
}

export function register(pack) {
  const packId = pack.id;
  const feed = pack.feed || {};
  feeds.set(packId, {
    key: `${packId}/${feed.id || packId}`,
    packId,
    id: feed.id || packId,
    label: feed.label || pack.name,
    description: feed.description || pack.description || null,
    tags: feed.tags || [],
    discriminator: feed.discriminator ? keyOf(packId, feed.discriminator) : null,
  });
  for (const [id, rec] of Object.entries(pack.concepts || {})) {
    if (!safe(id)) continue;
    concepts.set(`${packId}/${id}`, { packId, id, rec, pack });
  }
  for (const [name, rec] of Object.entries(pack.containers || {})) {
    if (!safe(name) || !rec || !rec.platform) continue;
    const perPlatform = ensure(containerMeta, rec.platform, () => new Map());
    const cur = perPlatform.get(name) || { name, platform: rec.platform, packIds: [], feedKeys: [], kind: null, description: null, tags: [], note: null, hazards: [] };
    cur.packIds.push(packId);
    if (rec.kind && !cur.kind) cur.kind = rec.kind;
    if (rec.description && !cur.description) cur.description = rec.description;
    if (rec.note && !cur.note) cur.note = rec.note;
    for (const t of rec.tags || []) if (!cur.tags.includes(t)) cur.tags.push(t);
    for (const h of resolveHazardRefs(pack, rec.hazards)) if (!cur.hazards.some((x) => (x.id || x.text) === (h.id || h.text))) cur.hazards.push(h);
    perPlatform.set(name, cur);
  }
  for (const b of pack.bindings || []) {
    if (!b || !safe(b.container) || !safe(b.column) || !b.platform) continue;
    const key = keyOf(packId, b.concept);
    if (!key) continue;
    const rec = {
      platform: b.platform,
      container: b.container,
      column: b.column,
      key,
      packId,
      note: b.note || null,
      alias_of: b.alias_of || null,
      basis: b.basis || null,
      basis_ref: b.basis_ref || null,
      cim: b.cim || null,
      encoding: b.encoding || null,
    };
    ensure(ensure(ensure(bindings, b.platform, () => new Map()), b.container, () => new Map()), b.column, () => []).push(rec);
    ensure(byConcept, key, () => []).push(rec);
    // A container a binding names is a container, described or not.
    const perPlatform = ensure(containerMeta, b.platform, () => new Map());
    const cur = perPlatform.get(b.container) || { name: b.container, platform: b.platform, packIds: [], feedKeys: [], kind: null, description: null, tags: [], note: null, hazards: [] };
    if (!cur.packIds.includes(packId)) cur.packIds.push(packId);
    const feedPack = key.split("/")[0];
    if (!cur.feedKeys.includes(feedPack)) cur.feedKeys.push(feedPack);
    perPlatform.set(b.container, cur);
  }
}

// A pack's own hazard refs, resolved to { id, level, text } worded for this
// platform (pack.hazards[ref].platform[PLATFORM] overrides), falling back to
// the taxonomy when the pack does not own the id. Shared by concepts and
// containers: either can name a hazard the owning pack defines once.
function resolveHazardRefs(pack, refs) {
  const out = [];
  const seen = new Set();
  const add = (h) => {
    if (h && h.text && !seen.has(h.id || h.text)) {
      seen.add(h.id || h.text);
      out.push({ id: h.id || null, level: h.level || "note", text: h.text });
    }
  };
  for (const ref of refs || []) {
    const own = pack && pack.hazards && Object.prototype.hasOwnProperty.call(pack.hazards, ref) ? pack.hazards[ref] : null;
    const over = (own && own.platform && own.platform[PLATFORM]) || {};
    add(own ? { id: ref, level: over.level || own.level, text: over.text || own.text } : taxonomy.hazard(ref));
  }
  return out;
}

function hazardsFor(raw, typeRec) {
  const out = resolveHazardRefs(raw.pack, (raw.rec && raw.rec.hazards) || []);
  const seen = new Set(out.map((h) => h.id || h.text));
  for (const h of (typeRec && typeRec.hazards) || []) {
    if (h && h.text && !seen.has(h.id || h.text)) {
      seen.add(h.id || h.text);
      out.push({ id: h.id || null, level: h.level || "note", text: h.text });
    }
  }
  return out;
}

export function concept(key) {
  if (!key || typeof key !== "string") return null;
  const raw = concepts.get(key);
  if (!raw) return null;
  const rec = raw.rec || {};
  const typeRec = rec.type ? taxonomy.type(rec.type) : null;
  return {
    key,
    packId: raw.packId,
    id: raw.id,
    label: rec.label || raw.id.replace(/_/g, " "),
    type: rec.type || null,
    typeLabel: typeRec ? typeRec.label : null,
    typeDescription: typeRec ? typeRec.description : null,
    shape: (typeRec && typeRec.shape) || null,
    description: rec.description || null,
    notes: rec.notes || null,
    role: rec.role || (typeRec && typeRec.role) || null,
    roleSource: rec.role ? "concept" : typeRec && typeRec.role ? "type" : null,
    tags: rec.tags || [],
    sensitivity: rec.sensitivity || null,
    cim: rec.cim || null,
    decode: rec.decode || null,
    hazards: hazardsFor(raw, typeRec),
    feed: feeds.get(raw.packId) || null,
  };
}

// The binding whose pack owns the concept beats one that only refers to it.
function best(list) {
  if (!list || !list.length) return null;
  return list.find((b) => b.key.startsWith(b.packId + "/")) || list[0];
}

export function resolve(platform, container, column) {
  if (!safe(container) || !safe(column)) return null;
  const perPlatform = bindings.get(platform);
  const perContainer = perPlatform && perPlatform.get(container);
  const list = perContainer && perContainer.get(column);
  const b = best(list);
  if (!b) return null;
  const c = concept(b.key);
  return c ? { key: b.key, concept: c, binding: b } : null;
}

// One entry per (platform, container, column): when two packs bind the
// same column to this concept, the one resolve() would pick.
export function bindingsOf(key, platform) {
  const list = (byConcept.get(key) || []).filter((b) => !platform || b.platform === platform);
  const own = key.split("/")[0];
  const ordered = [...list.filter((b) => b.packId === own), ...list.filter((b) => b.packId !== own)];
  const seen = new Set();
  return ordered.filter((b) => {
    const k = `${b.platform}\u0000${b.container}\u0000${b.column}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function allBindings(platform) {
  const out = [];
  for (const key of byConcept.keys()) out.push(...bindingsOf(key, platform));
  return out;
}

// Every container on a platform that binds a column of this name, with the
// concept it lands on there: the reverse lookup for a click whose table is
// unknown (the Logs blade in Simple mode without Type projected). One hit
// names the table; several hits on one concept still name the meaning.
export function containersWithColumn(platform, column) {
  if (!safe(column)) return [];
  const out = [];
  const perPlatform = bindings.get(platform);
  if (!perPlatform) return out;
  for (const [container, cols] of perPlatform) {
    const b = best(cols.get(column));
    if (b) out.push({ container, key: b.key, alias_of: b.alias_of });
  }
  return out.sort((a, b) => a.container.localeCompare(b.container));
}

export function columnsOn(platform, container) {
  const perPlatform = bindings.get(platform);
  const perContainer = perPlatform && perPlatform.get(container);
  return perContainer ? Array.from(perContainer.keys()).sort() : [];
}

export function containers(platform) {
  const perPlatform = containerMeta.get(platform);
  return perPlatform ? Array.from(perPlatform.values()).sort((a, b) => a.name.localeCompare(b.name)) : [];
}

export function container(platform, name) {
  const perPlatform = containerMeta.get(platform);
  return (perPlatform && safe(name) && perPlatform.get(name)) || null;
}

export function feed(packId) {
  return feeds.get(packId) || null;
}

export function conceptsOf(packId) {
  const out = [];
  for (const [key, raw] of concepts) if (raw.packId === packId) out.push(concept(key));
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

// Concepts of a type, or of a type whose parent it is. With a platform,
// only concepts bound somewhere on that platform.
export function ofType(typeId, platform) {
  const out = [];
  for (const key of concepts.keys()) {
    const c = concept(key);
    if (!c || !c.type) continue;
    const t = taxonomy.type(c.type);
    if (c.type !== typeId && !(t && t.parent === typeId)) continue;
    if (platform && !bindingsOf(key, platform).length) continue;
    out.push(c);
  }
  return out;
}

// Every container on a platform that carries a concept of the type through
// a direct binding (an alias alone does not count: the column it aliases
// is bound too). Sorted by name. This is the reach of a scope "type" edge:
// "this address in every feed I have" is a union over these.
export function containersOfType(platform, typeId) {
  const out = new Set();
  for (const c of ofType(typeId, platform)) {
    for (const b of bindingsOf(c.key, platform)) if (!b.alias_of) out.add(b.container);
  }
  return Array.from(out).sort((a, b) => a.localeCompare(b));
}

export function _reset() {
  concepts.clear();
  bindings.clear();
  byConcept.clear();
  containerMeta.clear();
  feeds.clear();
}

export default { register, keyOf, concept, resolve, bindingsOf, containersWithColumn, columnsOn, containers, container, feed, conceptsOf, ofType, containersOfType };
