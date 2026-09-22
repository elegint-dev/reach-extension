// The catalogue: one answer to "what is this field, on this sourcetype",
// merged from three layers in fixed precedence:
//
//   user        what this user (or their team, via import) wrote. Always wins.
//   pack        bundled knowledge for a feed: the packs (app/packs, via
//               packs.js) and their fields sidecars (pack-fields.js: the
//               per-field records, record types and join graph a vendor's
//               add-on lands, fetched per container).
//   discovered  what the user's own Splunk reported: inventory, profiles,
//               provenance. Facts, not meanings; never overrides either above.
//
// A fourth, narrower layer: falcon-dictionary.js, the analyst's own FDR
// schema pull imported as a local file. It only ever answers for a Falcon
// container (falconDictionary.isFalconContainer): a field's type, its
// value decode (below pack, never above a bundled decode table, decodeOn),
// and, only where the pull carried one, a field's description (below the
// user's note and the pack's, above nothing, since the real pull's field
// descriptions are almost always empty).
//
// Keys are (sourcetype, field). The pack layer is read through packs.js
// and pack-fields.js; the user layer lives in store.js under the keys
// below and the discovered layer in layer.js, one key per environment.
// This module is the only writer of the user layer.
//
// Where a v2 pack binds the (sourcetype, field) to a concept (concepts.js),
// the user's note is keyed by that concept instead: a description written
// on Sentinel's PrincipalArn is the description of Splunk's
// userIdentity.arn, labelled with where it was written. Unbound fields keep
// the (sourcetype, field) key. A version-1 user layer is read as version 2
// on load, and any unbound note that a later pack binds is adopted the
// next time the layer loads.
//
// The user's own bindings (user.bindings, learned.js) say which concept a
// column on an unbound table carries. On load and after every write they
// are projected into the resolver as the "learned" pack, so a confirmed
// column resolves, takes notes by concept and compiles pivots like a
// pack-bound one. A pack that binds the same triple wins: bindField
// refuses to write such a record, and one that arrives anyway (import,
// another context) is kept in the layer but left out of the projection.
//
//   await load({ fields })           packs, the user and discovered layers, and (fields "bound", the default) the
//                                       fields sidecars describing a container this platform knows; a popup passes
//                                       fields "lazy" and loads per click instead. Throws BundleError needs_server on file://
//   await loadFields(sourcetype?)    → fetches the fields sidecars describing the container (pack-fields.loadFor),
//                                       or, with no container, those describing any container this platform knows
//                                       (pack-fields.loadBound: nothing on a platform with no such container)
//   sourcetypes()                    → [{ name, sources: ["pack"|"user"|"discovered"…], …meta }]
//                                       discovered meta: indexes, eventCount, firstSeen, lastSeen (epoch s),
//                                       missingSince (ISO, when the last inventory covering it did not return it),
//                                       profiledAt, profileDelta { added, gone, fill[] }
//   sourcetype(name)                 → { name, description, tags, discriminator, sources, fields: [names] } | null
//   orgCorpora()                     → [{ envKey, platform, doc }]  every environment's organisation corpus (known.js), newest first
//   fieldOn(sourcetype, name)        → FieldView | null   (see below)
//   await loadValues(sourcetype)     → fetches the values sidecars of the packs bound on it (values.loadFor); a
//                                       page renders once without them and fills its table when this resolves
//   valuesReady(sourcetype)          → true when nothing more would arrive for it
//   valueOn(sourcetype, name, value) → ValueRecord | null   what one value means there: the pack's values table,
//                                       else the decode table discovery read from your own lookup (values.js)
//   fieldsOn(sourcetype)             → [names], every layer
//   fieldEverywhere(name)            → [{ sourcetype, sources, fill, … }] best-filled first
//   inferSourcetype(name, among?)    → { sourcetype, concept, basis: "column" } | { sourcetypes, concept } | null
//                                       the container(s) a pack binds this column on, for a click whose
//                                       container is unknown; `among` narrows to candidates the page gave
//   leadingContainer(name, hints)    → the first hint that names a container this field is bound on, else null
//   searchIndex()                    → { fields, events, sourcetypes } across every layer
//   annotate(sourcetype, name, patch)          → saves user layer; null values clear a key
//                                                 (by concept when bound, else by (sourcetype, field))
//   noteCount()                      → { notes, sourcetypes, concepts } across the user layer
//   annotateSourcetype(sourcetype, patch)
//   bindField(sourcetype, name, conceptKey, { alias_of, evidence, via })   → the record; throws when a pack
//                                                 binds the pair on this platform or the concept is unknown
//   bindFields([{ sourcetype, name, concept, alias_of, evidence, via }])   → { records, errors }; the same checks
//                                                 per pair, a refused pair reported not fatal, one sync and one save
//   dismissBinding(sourcetype, name, conceptKey | null)   → the record; "not this one" | "leave this column alone"
//   unbindField(sourcetype, name)    → drops the record; a concept note written on this pair is copied back to it
//   learnedBindings()                → [record] copy of user.bindings, both platforms
//   bindingFor(sourcetype, name)     → the record for this platform's pair | null
//   syncLearned()                    → projects the confirmed records into the resolver (load and every write do this)
//   userLayer() / exportUser()       → the raw user layer (JSON-safe)
//   importUser(doc, { mode })        → "merge" (theirs fills gaps, newer wins on conflict) | "replace"
//   subscribe(fn)                    → fn() after any layer changes
//
// FieldView:
//   { sourcetype, name,
//     meaning: { description, notes, source: "user"|"pack"|null, notesSource?, confidence?, writtenOn?, ... },
//                                    notesSource "user": the description is the pack's, the notes are yours
//                                    writtenOn: { platform, container, column } when a user note was made elsewhere
//     taxonomy: { role, tags, sensitivity, owner, source, type, typeLabel },
//     concept: { key, id, label, packId, type, typeLabel, typeDescription, hazards, bindings } | null,
//     binding: { platform, container, column, note, alias_of, basis, packId, provenance } | null,   how the concept lands here
//                                    packId "learned" is a binding you confirmed (learned.js);
//                                    provenance { kind, statement, cite } when the pack says how the column is made
//     dictionary: { format, shape, examples, values, provenance, cite, source, count } | null,   values.js, once the pack's
//                                    sidecar is loaded (loadValues); a concept with a decode table has one from the start
//     pack: FieldRecord | null,      the fields sidecar's record, when there is one
//     packField: {...} | null,       a generic pack's record; packId names the pack
//     user: annotation | null,       the untouched user annotation (concept-keyed when bound)
//     profile: {...} | null,         discovered layer, when measured
//     provenance: {...} | null,      discovered layer
//     declared: { type, raw } | null, discovered layer, Sentinel's schema type for the column
//     props: { indexed_extractions, kv_mode } | null,   discovered layer, the sourcetype's own
//                                    props stanza; efficiency.js's classOf() fallback
//     cim: { data_models, from } | { targets } | null,   a generic pack's CIM mapping
//     falcon: { type, description?, values?, events: [name] } | null,   falcon-dictionary.js, a Falcon container only
//     scope: "sourcetype" | "unscoped" | "user" | "discovered" | "falcon" }
//
// No DOM. Safe to import from a content script.

import * as packs from "./packs.js";
import * as packFields from "./pack-fields.js";
import * as store from "./store.js";
import * as layer from "./layer.js";
import * as concepts from "./concepts.js";
import * as learned from "./learned.js";
import * as values from "./values.js";
import * as falconDictionary from "./falcon-dictionary.js";
import { PLATFORM } from "./platform.js";

export const USER_KEY = "catalogue.user";
export const USER_VERSION = 2;
const USER_VERSIONS = [1, 2];
const PLATFORMS = [PLATFORM, PLATFORM === "splunk" ? "sentinel" : "splunk"];

// { version, updated_at,
//   sourcetypes: { [st]: { description, tags, discriminator, updated_at, fields: { [f]: annotation } } },
//   concepts: { [pack/concept]: annotation + { written_on: { platform, container, column } } },
//   bindings: [ { platform, container, column, concept, basis, alias_of, confirmed_at, via, imported_at, evidence } ] }
//   (bindings: learned.js has the record; optional, absent in a layer written before 0.4.53)
let user = null;
let learnedMemo = null; // JSON of the confirmed records last projected; a no-op change does not rebuild
let learnedGen = -1; // packs.generation() when that projection landed; a pack change from outside invalidates it
let discovered = null; // { [origin]: { sourcetypes: { [st]: { index[], count, fields: { [f]: { profile, provenance } } } } } } (Phase 3)
const listeners = new Set();
let indexMemo = null; // searchIndex(), rebuilt after any layer change

function emptyUser() {
  return { version: USER_VERSION, updated_at: null, sourcetypes: {}, concepts: {}, bindings: [] };
}

// The concept a (container, column) is bound to on any platform: the
// stored layer is shared by both, so a note made on the other platform's
// column must find its concept too.
function boundKeyAnywhere(container, column) {
  for (const platform of PLATFORMS) {
    const r = concepts.resolve(platform, container, column);
    if (r) return { key: r.key, platform, packId: r.binding.packId };
  }
  return null;
}

function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// Move every (sourcetype, field) note whose field is bound onto its
// concept. When the concept already has a note the two merge key by key
// (description, notes, tags, ...): the newer note's value wins where both
// have one, and each keeps what the other lacks, so a note typed on the
// pack's own column loses nothing when a custom column is confirmed with
// a note of its own, and the other way round. Where the pair note is the
// older and one of its values loses, the pair record stays in place under
// a learned binding (invisible while bound, since the concept slot answers
// first; unbindField gives the column back as the user wrote it); under a
// pack binding the concept is the note's final home and the pair record
// goes. Returns how many records changed. Idempotent: a second pass over
// the same layer changes nothing.
function adoptBoundNotes(u) {
  let changed = 0;
  u.concepts = u.concepts || {};
  for (const [st, rec] of Object.entries(u.sourcetypes || {})) {
    if (isUnsafeKey(st) || !rec || !rec.fields) continue;
    for (const [f, ann] of Object.entries(rec.fields)) {
      if (isUnsafeKey(f) || !ann || typeof ann !== "object") continue;
      const hit = boundKeyAnywhere(st, f);
      if (!hit) continue;
      const here = { platform: hit.platform, container: st, column: f };
      const cur = u.concepts[hit.key];
      if (!cur) {
        u.concepts[hit.key] = { ...ann, written_on: ann.written_on || here };
        delete rec.fields[f];
        changed++;
        continue;
      }
      const pairNewer = String(ann.updated_at || "") > String(cur.updated_at || "");
      let lost = false;
      let merged = false;
      for (const k of FIELD_KEYS) {
        if (!(k in ann)) continue;
        if (!(k in cur) || pairNewer) {
          if (!sameValue(cur[k], ann[k])) merged = true;
          cur[k] = ann[k];
        } else if (!sameValue(cur[k], ann[k])) {
          lost = true;
        }
      }
      if (pairNewer) {
        cur.updated_at = ann.updated_at;
        cur.written_on = ann.written_on || here;
        merged = true;
      }
      if (merged) changed++;
      if (!lost || hit.packId !== learned.LEARNED_ID) {
        delete rec.fields[f];
        changed++;
      }
    }
    if (!Object.keys(rec.fields).length && !ST_KEYS.some((k) => k in rec)) delete u.sourcetypes[st];
  }
  return changed;
}

function normaliseUser(doc) {
  if (!doc || typeof doc !== "object" || !USER_VERSIONS.includes(doc.version) || typeof doc.sourcetypes !== "object") return emptyUser();
  // A copy: adoption edits the layer in place, and the document handed in
  // (a store read, an import) must stay as it was.
  const copy = JSON.parse(JSON.stringify(doc));
  const u = { version: USER_VERSION, updated_at: copy.updated_at || null, sourcetypes: copy.sourcetypes || {}, concepts: copy.version === USER_VERSION && copy.concepts && typeof copy.concepts === "object" ? copy.concepts : {} };
  for (const k of Object.keys(u.concepts)) if (isUnsafeKey(k)) delete u.concepts[k];
  u.bindings = copy.version === USER_VERSION ? learned.normaliseBindings(copy.bindings) : [];
  return u;
}

// The pack that binds a record's triple ahead of the learned pack, or
// null: the one check bindField (refuse) and syncLearned (leave out) share,
// so what the guard refuses the projection never carries either.
function shadowedBy(rec) {
  return learned.shadowingPack(rec, concepts.resolve);
}

// The confirmed bindings whose concept a loaded pack defines and whose
// triple no pack binds, as the learned pack in the resolver. The rest
// stay in the layer: inert while their pack is absent, shadowed while a
// pack binds the triple (a colleague's export, a write from another
// context or a newer pack version can put such a record here; resolve()
// would ignore it, but bindingsOf() would not, and a phantom pivot from
// it would query the wrong feed). Runs on load, on every store change and
// after every write; the resolver is rebuilt only when that set changed
// or a pack was registered, replaced or removed from outside since
// (packs.generation()), so a runtime pack that shadows a learned triple,
// or a learned pack dropped by another caller, is put right on the next
// sync rather than the next changed write.
export function syncLearned() {
  if (!user) return;
  const live = (user.bindings || []).filter((b) => b.basis === "confirmed" && b.concept && concepts.concept(b.concept) && !shadowedBy(b));
  const sig = JSON.stringify(live);
  if (sig === learnedMemo && packs.generation() === learnedGen) return;
  try {
    if (!live.length) packs.remove(learned.LEARNED_ID);
    else packs.replace(learned.learnedPack(live, { conceptExists: (key) => Boolean(concepts.concept(key)) }));
    learnedMemo = sig; // only once the resolver holds it; a refused pack is tried again next time
    learnedGen = packs.generation(); // after the replace: it bumped the counter itself
  } catch (err) {
    // A bad record must not stop the catalogue loading; the layer keeps it and nothing resolves through it.
    console.warn("[Reach] learned bindings:", err && err.message ? err.message : err);
  }
}

export class BundleError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = "BundleError";
    this.code = code;
    this.detail = detail || "";
  }
}

// fetch() is blocked on file://.
export function isFileProtocol() {
  return typeof location !== "undefined" && location.protocol === "file:";
}

export async function loadFields(sourcetype) {
  if (sourcetype) await packFields.loadFor(sourcetype);
  else await packFields.loadBound(PLATFORM);
}

export async function load({ fields = "bound" } = {}) {
  if (isFileProtocol()) {
    throw new BundleError(
      "needs_server",
      "This page was opened straight from disk (file://), and browsers block a page on file:// from reading its own data files.",
      "Browsers block fetch() on file://, so the packs cannot be loaded without a server.",
    );
  }
  await packs.load();
  if (fields !== "lazy") await loadFields();
  const raw = await store.get(USER_KEY);
  learnedMemo = null;
  user = normaliseUser(raw);
  syncLearned(); // before adoption: a note on a learned column belongs to its concept
  const dirty = Boolean(raw && raw.version === 1 && typeof raw.sourcetypes === "object"); // a version-1 layer is saved back as version 2
  if (adoptBoundNotes(user) || dirty) await save();
  await layer.load();
  discovered = await layer.readAll();
  await falconDictionary.load();
  falconDictionary.subscribe(() => notify());
  store.subscribe((key, value) => {
    if (key === USER_KEY) {
      user = normaliseUser(value);
      syncLearned(); // a confirm made in another context (the popup) reaches this resolver
      adoptBoundNotes(user); // in memory only; the writer saves
      notify();
    }
  });
  // One environment per change; the map is patched, not replaced.
  layer.subscribe((envKey, env) => {
    if (env) discovered[envKey] = env;
    else delete discovered[envKey];
    discoveredMemo = null;
    notify();
  });
}

function must() {
  if (!user) throw new Error("catalogue.load() has not finished yet.");
  return user;
}

function notify() {
  indexMemo = null;
  for (const fn of listeners) fn();
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// ---------------------------------------------------------------------------
// Discovered layer readers (populated by discovery.js in Phase 3; read-only here).

// Merged across environments once per change of the discovered layer.
// fieldOn() runs once per field per page, and this must not rebuild then.
let discoveredMemo = null;
function discoveredSourcetypes() {
  if (discoveredMemo) return discoveredMemo;
  const out = new Map(); // st → merged { indexes, count, fields }
  for (const env of Object.values(discovered || {})) {
    for (const [st, rec] of Object.entries((env && env.sourcetypes) || {})) {
      const cur = out.get(st) || { indexes: new Set(), count: 0, fields: {} };
      for (const i of rec.indexes || []) cur.indexes.add(i);
      cur.count += rec.count || 0;
      if (rec.record_types && (!cur.recordTypes || rec.record_types.length > cur.recordTypes.length)) {
        cur.recordTypes = rec.record_types;
        cur.discriminator = rec.discriminator || null;
      }
      if (rec.mb) cur.volumeMb = (cur.volumeMb || 0) + rec.mb;
      const firstSeen = layer.epochOf(rec.first_seen);
      const lastSeen = layer.epochOf(rec.last_seen);
      if (firstSeen && (!cur.firstSeen || firstSeen < cur.firstSeen)) cur.firstSeen = firstSeen;
      if (lastSeen && (!cur.lastSeen || lastSeen > cur.lastSeen)) cur.lastSeen = lastSeen;
      // Health, across environments: missing only when no environment that
      // has inventoried it still sees it; the newest profile's delta wins.
      if (rec.inventoried_at) {
        cur.inventoried = true;
        if (rec.missing_since) cur.missingSince = cur.missingSince && cur.missingSince < rec.missing_since ? cur.missingSince : rec.missing_since;
        else cur.seenSomewhere = true;
      }
      if (rec.profiled_at && (!cur.profiledAt || rec.profiled_at > cur.profiledAt)) {
        cur.profiledAt = rec.profiled_at;
        cur.profileDelta = rec.profile_delta || null;
      }
      for (const [f, frec] of Object.entries(rec.fields || {})) cur.fields[f] = { ...(cur.fields[f] || {}), ...frec };
      if (rec.decodes) cur.decodes = { ...(cur.decodes || {}), ...rec.decodes };
      if (rec.lookups) cur.lookups = rec.lookups;
      if (rec.props) cur.props = { ...(cur.props || {}), ...rec.props };
      out.set(st, cur);
    }
  }
  discoveredMemo = out;
  return out;
}

// The organisation corpus (known.js) of every environment that measured
// one, newest first; the verdict row asks prevalenceOf() over them.
export function orgCorpora() {
  return Object.entries(discovered || {})
    .filter(([, env]) => env && env.org_corpus && Array.isArray(env.org_corpus.rows))
    .map(([envKey, env]) => ({ envKey, platform: layer.platformOf(envKey), doc: env.org_corpus }))
    .sort((a, b) => String(b.doc.at || "").localeCompare(String(a.doc.at || "")));
}

function discoveredField(sourcetype, name) {
  const st = discoveredSourcetypes().get(sourcetype);
  return st && st.fields[name] ? st.fields[name] : null;
}

function discoveredDecode(sourcetype, name) {
  const st = discoveredSourcetypes().get(sourcetype);
  return st && st.decodes && st.decodes[name] ? st.decodes[name] : null;
}

// The sourcetype's own props stanza (INDEXED_EXTRACTIONS, KV_MODE), read
// by discovery.js's provenance() run; efficiency.js falls back to it when
// a field carries no recorded provenance of its own.
function discoveredProps(sourcetype) {
  const st = discoveredSourcetypes().get(sourcetype);
  return st && st.props ? st.props : null;
}

// A Falcon container's field, from the imported FDR schema layer: type,
// events and, when the pull carried one, a description (falcon-dictionary.js).
function falconField(sourcetype, name) {
  if (!sourcetype || !falconDictionary.isFalconContainer(sourcetype)) return null;
  return falconDictionary.fieldOn(name);
}

// Decode table for a field on a sourcetype: the pack's, else the imported
// Falcon layer's values table on a Falcon container, else the one
// discovery read from the user's own lookup. The layer never overrides a
// bundled decode: this function is asked for one only once the caller's
// own bundled table (the FDR ledger's rec.decode, or a pack's) came up
// empty (field.js's Values section, decodeOn's own callers).
export function decodeOn(sourcetype, name) {
  const packHit = sourcetype ? packFields.fieldOn(sourcetype, name) : null;
  if (packHit) {
    const d = packFields.decode(name);
    if (d) return { ...d, source: "pack" };
  }
  const pd = sourcetype ? packs.decode(sourcetype, name) : null;
  if (pd) return { ...pd, source: "pack" };
  const fd = falconField(sourcetype, name);
  if (fd && fd.values) return { values: fd.values, lookup: "your imported Falcon dictionary", source: "falcon" };
  const d = discoveredDecode(sourcetype, name);
  return d ? { ...d, source: "discovered" } : null;
}

// sourcetype → record-type field, from every layer that declares one:
// packs, the user's own note, discovery's measurement.
export function discriminators() {
  must();
  const out = { ...packs.discriminators() };
  for (const [st, rec] of discoveredSourcetypes()) if (rec.discriminator && !out[st]) out[st] = rec.discriminator;
  for (const [st, rec] of Object.entries(user.sourcetypes)) if (rec.discriminator) out[st] = rec.discriminator;
  return out;
}

// Pack edges leaving a field on a sourcetype: the generic pivot graph.
// (The FDR bundle's edges are served by reachability.js / spl.js.)
export function edgesFrom(sourcetype, name) {
  return sourcetype ? packs.edgesFrom(sourcetype, name) : [];
}

// ---------------------------------------------------------------------------
// Reads

export function sourcetypes() {
  must();
  const out = new Map();
  // A sourcetype two packs describe is listed once: between packs the
  // first description and pack id stand and the rest fill gaps; the user's
  // own description, tags and discriminator always win.
  const add = (name, source, meta = {}) => {
    const cur = out.get(name) || { name, sources: [], description: null, tags: [], discriminator: null };
    if (!cur.sources.includes(source)) cur.sources.push(source);
    for (const [k, v] of Object.entries(meta)) {
      if (v === undefined || v === null) continue;
      if (source === "user" || cur[k] === undefined || cur[k] === null || (Array.isArray(cur[k]) && !cur[k].length)) cur[k] = v;
    }
    out.set(name, cur);
  };
  for (const p of packs.list()) {
    for (const st of p.sourcetypes) {
      const rec = packs.sourcetype(st) || {};
      add(st, "pack", { description: rec.description, tags: rec.tags, discriminator: rec.discriminator, packId: rec.packId || p.id });
    }
  }
  for (const [st, rec] of discoveredSourcetypes()) {
    add(st, "discovered", {
      indexes: Array.from(rec.indexes).sort(),
      eventCount: rec.count,
      volumeMb: rec.volumeMb,
      recordTypes: rec.recordTypes,
      firstSeen: rec.firstSeen,
      lastSeen: rec.lastSeen,
      missingSince: rec.missingSince && !rec.seenSomewhere ? rec.missingSince : null,
      profiledAt: rec.profiledAt || null,
      profileDelta: rec.profileDelta && (rec.profileDelta.added.length || rec.profileDelta.gone.length || rec.profileDelta.fill.length) ? rec.profileDelta : null,
    });
    if (rec.discriminator && !out.get(st).discriminator) out.get(st).discriminator = rec.discriminator;
  }
  for (const [st, rec] of Object.entries(user.sourcetypes)) {
    add(st, "user", { description: rec.description, tags: rec.tags, discriminator: rec.discriminator });
  }
  return Array.from(out.values()).sort((a, b) => a.name.localeCompare(b.name));
}

export function sourcetype(name) {
  return sourcetypes().find((s) => s.name === name) || null;
}

export function fieldsOn(sourcetype) {
  must();
  const names = new Set();
  for (const f of packFields.names()) if (packFields.fieldOn(sourcetype, f)?.scope === "sourcetype") names.add(f);
  for (const f of packs.fieldsOn(sourcetype)) names.add(f);
  const d = discoveredSourcetypes().get(sourcetype);
  if (d) {
    for (const f of Object.keys(d.fields)) names.add(f);
    for (const f of Object.keys(d.decodes || {})) names.add(f);
  }
  const u = user.sourcetypes[sourcetype];
  if (u) for (const f of Object.keys(u.fields || {})) names.add(f);
  return Array.from(names).sort();
}

// Where a note for (sourcetype, name) lives: on its concept when a pack
// binds the pair on this platform, else under the pair itself.
function noteSlot(sourcetype, name) {
  const r = sourcetype && name ? concepts.resolve(PLATFORM, sourcetype, name) : null;
  return r ? { key: r.key, binding: r.binding, concept: r.concept } : null;
}

export function userAnnotation(sourcetype, name) {
  const u = must();
  if (isUnsafeKey(sourcetype) || isUnsafeKey(name)) return null;
  const slot = noteSlot(sourcetype, name);
  if (slot && Object.prototype.hasOwnProperty.call(u.concepts, slot.key)) return u.concepts[slot.key];
  const st = u.sourcetypes[sourcetype];
  return (st && st.fields && Object.prototype.hasOwnProperty.call(st.fields, name) && st.fields[name]) || null;
}

// Every sourcetype that carries this field name, with what each layer says
// about it there. This is the answer to "why is my search empty on this
// field": it is 94% filled on one sourcetype, 3% on another, only known to
// a pack on a third, and called something else entirely on a fourth.
// Ordered best-filled first; sourcetypes with no measurement sort last.
//
//   → [{ sourcetype, sources: ["pack"|"user"|"discovered"], packId,
//        described, fill, count, sample, measured_at, provenance }]
export function fieldEverywhere(name) {
  must();
  const out = [];
  for (const st of sourcetypes()) {
    const v = fieldOn(st.name, name);
    if (!v) continue;
    const sources = [];
    if (v.pack || v.packField) sources.push("pack");
    if (v.user) sources.push("user");
    if (v.profile || v.provenance || (v.decode && v.decode.source === "discovered")) sources.push("discovered");
    const p = v.profile;
    out.push({
      sourcetype: st.name,
      sources,
      packId: v.packId,
      described: Boolean(v.meaning && v.meaning.description),
      fill: p && p.fill !== null && p.fill !== undefined ? p.fill : null,
      count: p ? p.count : null,
      sample: p ? p.sample : null,
      measured_at: p ? p.measured_at : null,
      provenance: v.provenance && v.provenance.length ? v.provenance[0].kind : null,
    });
  }
  return out.sort((a, b) => {
    if (a.fill === null && b.fill !== null) return 1;
    if (b.fill === null && a.fill !== null) return -1;
    return (b.fill || 0) - (a.fill || 0) || a.sourcetype.localeCompare(b.sourcetype);
  });
}

// A click whose container is unknown (the Logs blade in Simple mode with
// Type not projected) still names a column. If exactly one bound container
// carries a column of that name, that is the container; if several do and
// they all land on one concept, the meaning is known even though the
// pivots (which need a table to query) still wait for a choice.
export function inferSourcetype(name, among) {
  must();
  let hits = concepts.containersWithColumn(PLATFORM, name);
  if (Array.isArray(among) && among.length) hits = hits.filter((h) => among.includes(h.container));
  if (!hits.length) return null;
  if (hits.length === 1) return { sourcetype: hits[0].container, concept: hits[0].key, basis: "column" };
  const keys = new Set(hits.map((h) => h.key));
  return { sourcetypes: hits.map((h) => h.container), concept: keys.size === 1 ? hits[0].key : null };
}

// The first of several candidate values (a page's ?st=, ?on=, a click's
// discriminator…) that actually names a container this field is bound on.
// A field page reached by a link built elsewhere may carry the container's
// name under a key that also doubles as something else (?on= is an FDR
// event on the FDR ledger, but a container on a generic pack's field with
// no separate sourcetype in the link): try each in order and let the
// caller's own default stand when none of them resolves.
export function leadingContainer(name, hints) {
  must();
  for (const h of Array.isArray(hints) ? hints : [hints]) {
    if (h && fieldOn(h, name)) return h;
  }
  return null;
}

// Names from every layer, in the shape search.matchNames() takes: the
// fields sidecars' fields and events, plus every field a pack, discovery
// or the user has placed on a sourcetype. Rebuilt when a layer changes.
export function searchIndex() {
  must();
  if (indexMemo) return indexMemo;
  const base = packFields.searchIndex();
  const fields = new Set(base.fields);
  for (const st of sourcetypes()) for (const f of fieldsOn(st.name)) fields.add(f);
  indexMemo = { fields: Array.from(fields).sort(), events: base.events, sourcetypes: sourcetypes().map((s) => s.name) };
  return indexMemo;
}

export function fieldOn(sourcetype, name) {
  must();
  const packHit = sourcetype ? packFields.fieldOn(sourcetype, name) : null;
  const pack = packHit ? packHit.rec : null; // the fields sidecar's record, when there is one
  const pf = sourcetype ? packs.field(sourcetype, name) : null; // a generic pack's record
  const ann = sourcetype ? userAnnotation(sourcetype, name) : null;
  const disc = sourcetype ? discoveredField(sourcetype, name) : null;
  const decode = sourcetype ? decodeOn(sourcetype, name) : null;
  const falcon = falconField(sourcetype, name);
  if (!pack && !pf && !ann && !disc && !decode && !falcon) return null;

  // A concept's prose (a v2 pack, written once for every platform) beats
  // the sidecar's enriched meaning for the same field; the sidecar's
  // record stays attached for everything else it knows.
  const packMeaning = pack && pack.meaning;
  const conceptMeaning = pf && pf.concept && pf.description ? { description: pf.description, notes: pf.notes || null, source: "pack", basis: "curated", packId: pf.packId, concept: pf.concept.key } : null;
  const meaning = ann && ann.description
    ? { description: ann.description, notes: ann.notes || null, source: "user", updated_at: ann.updated_at || null }
    : conceptMeaning
      ? conceptMeaning
      : packMeaning && packMeaning.description
        ? { description: packMeaning.description, notes: packMeaning.hunting_notes || null, source: "pack", confidence: packMeaning.confidence || null, basis: packMeaning.source || null, packId: packFields.packOf(name) }
        : pf && pf.description
          ? { description: pf.description, notes: pf.notes || null, source: "pack", basis: "curated", packId: pf.packId }
          : falcon && falcon.description
            ? { description: falcon.description, notes: null, source: "falcon" }
            : { description: null, notes: (ann && ann.notes) || null, source: null };
  // A note alone (Notes filled, Description left to the pack): the pack's
  // description stands and the note rides under it as yours, on the pack's
  // own column too, the way a description of yours does.
  if (ann && ann.notes && meaning.source !== "user") {
    meaning.notes = ann.notes;
    meaning.notesSource = "user";
    meaning.updated_at = ann.updated_at || null;
  }
  const wo = ann && ann.written_on;
  if ((meaning.source === "user" || meaning.notesSource === "user") && wo && (wo.platform !== PLATFORM || wo.container !== sourcetype || wo.column !== name)) meaning.writtenOn = { ...wo };

  const packRole = (pf && pf.concept && pf.role) || (pack && pack.role) || (pf && pf.role) || null;
  const taxonomy = {
    role: (ann && ann.role) || packRole,
    roleSource: ann && ann.role ? "user" : packRole ? "pack" : null,
    tags: (ann && ann.tags && ann.tags.length ? ann.tags : (pf && pf.tags) || []),
    sensitivity: (ann && ann.sensitivity) || (pf && pf.sensitivity) || null,
    owner: (ann && ann.owner) || null,
    type: (pf && pf.type) || null,
    typeLabel: (pf && pf.typeLabel) || null,
  };

  const c = pf && pf.concept;
  const concept = c
    ? { key: c.key, id: c.id, label: c.label, packId: c.packId, type: c.type, typeLabel: c.typeLabel, typeDescription: c.typeDescription, hazards: c.hazards, feed: c.feed, bindings: concepts.bindingsOf(c.key).map((b) => ({ platform: b.platform, container: b.container, column: b.column, alias_of: b.alias_of })) }
    : null;
  const binding = pf && pf.binding ? { platform: pf.binding.platform, container: pf.binding.container, column: pf.binding.column, note: pf.binding.note, alias_of: pf.binding.alias_of, basis: pf.binding.basis, packId: pf.binding.packId || null, provenance: pf.bindingProvenance || null } : null;

  const scope = packHit ? packHit.scope : pf ? "sourcetype" : ann ? "user" : disc ? "discovered" : falcon ? "falcon" : "discovered";
  return {
    sourcetype,
    name,
    meaning,
    taxonomy,
    concept,
    binding,
    pack,
    packField: pf,
    packId: pf ? pf.packId : pack ? packFields.packOf(name) : null,
    user: ann,
    falcon,
    profile: (disc && disc.profile) || null,
    provenance: (disc && disc.provenance) || null,
    declared: (disc && disc.declared) || null,
    props: sourcetype ? discoveredProps(sourcetype) : null,
    decode,
    dictionary: (pf && pf.dictionary) || null,
    cim: (pf && pf.cim) || null,
    scope,
  };
}

export async function loadValues(sourcetype) {
  if (!sourcetype || isUnsafeKey(sourcetype)) return;
  await values.loadFor(sourcetype);
}

export function valuesReady(sourcetype) {
  if (!sourcetype || isUnsafeKey(sourcetype)) return true;
  return values.packsOn(sourcetype).every((id) => values.ready(id));
}

// One value on a field: the pack's dictionary first, then the decode
// table discovery read from the user's own lookup.
export function valueOn(sourcetype, name, value) {
  if (!sourcetype || !name || isUnsafeKey(sourcetype) || isUnsafeKey(name)) return null;
  const d = discoveredDecode(sourcetype, name);
  return values.valueOn(sourcetype, name, value, { decode: d });
}

// ---------------------------------------------------------------------------
// Writes: user layer only

const FIELD_KEYS = ["description", "notes", "role", "tags", "sensitivity", "owner"];
const ST_KEYS = ["description", "tags", "discriminator"];

// sourcetype and field names land here straight off Splunk page content
// (json-tree-fields.js tags a clicked JSON leaf with its raw, attacker-data
// dotted path) and off imported catalogue export files, never a fixed set.
// `obj[k] = obj[k] || {}` for k === "__proto__" doesn't create an own
// property: bracket assignment to "__proto__" on a plain object reassigns
// its [[Prototype]], so `obj["__proto__"]` back on the right-hand side reads
// as the (truthy) Object.prototype itself, and every later `mine.fields[f] =
// …` on that "record" writes onto the real, shared Object.prototype.
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function isUnsafeKey(k) {
  return UNSAFE_KEYS.has(k);
}

function applyPatch(target, patch, allowed) {
  for (const k of allowed) {
    if (!(k in patch)) continue;
    const v = patch[k];
    if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) delete target[k];
    else target[k] = v;
  }
}

async function save() {
  user.updated_at = new Date().toISOString();
  await store.set(USER_KEY, user);
  if (store.backend() !== "chrome") notify(); // chrome path notifies via onChanged
}

export async function annotate(sourcetype, name, patch) {
  must();
  if (!sourcetype || !name) throw new Error("annotate needs a sourcetype and a field name");
  if (isUnsafeKey(sourcetype) || isUnsafeKey(name)) throw new Error(`"${isUnsafeKey(sourcetype) ? sourcetype : name}" cannot be annotated`);
  const slot = noteSlot(sourcetype, name);
  if (slot) {
    user.concepts = user.concepts || {};
    const rec = (user.concepts[slot.key] = user.concepts[slot.key] || {});
    applyPatch(rec, patch, FIELD_KEYS);
    if (FIELD_KEYS.some((k) => k in rec)) {
      rec.updated_at = new Date().toISOString();
      rec.written_on = { platform: PLATFORM, container: sourcetype, column: name };
    } else {
      delete user.concepts[slot.key];
    }
    // A note left under the pair from before the pack bound it would shadow nothing, but keep one copy.
    const stale = user.sourcetypes[sourcetype];
    if (stale && stale.fields && stale.fields[name]) {
      delete stale.fields[name];
      if (!Object.keys(stale.fields).length && !ST_KEYS.some((k) => k in stale)) delete user.sourcetypes[sourcetype];
    }
    await save();
    return userAnnotation(sourcetype, name);
  }
  const st = (user.sourcetypes[sourcetype] = user.sourcetypes[sourcetype] || { fields: {} });
  st.fields = st.fields || {};
  const rec = (st.fields[name] = st.fields[name] || {});
  applyPatch(rec, patch, FIELD_KEYS);
  if (FIELD_KEYS.some((k) => k in rec)) rec.updated_at = new Date().toISOString();
  else delete st.fields[name];
  if (!Object.keys(st.fields).length && !ST_KEYS.some((k) => k in st)) delete user.sourcetypes[sourcetype];
  await save();
  return userAnnotation(sourcetype, name);
}

export async function annotateSourcetype(sourcetype, patch) {
  must();
  if (!sourcetype) throw new Error("annotateSourcetype needs a sourcetype");
  if (isUnsafeKey(sourcetype)) throw new Error(`"${sourcetype}" cannot be annotated`);
  const st = (user.sourcetypes[sourcetype] = user.sourcetypes[sourcetype] || { fields: {} });
  applyPatch(st, patch, ST_KEYS);
  st.updated_at = new Date().toISOString();
  if (!Object.keys(st.fields || {}).length && !ST_KEYS.some((k) => k in st)) delete user.sourcetypes[sourcetype];
  await save();
}

// ---------------------------------------------------------------------------
// Learned bindings: the user's own (platform, container, column) → concept
// records. One per triple on this platform; each write replaces the record,
// projects the layer into the resolver and saves.

const BINDING_KEYS = ["platform", "container", "column", "concept", "basis", "alias_of", "confirmed_at", "via", "imported_at", "evidence", "dismissed"];

function bindingIndex(sourcetype, name) {
  const u = must();
  u.bindings = u.bindings || [];
  return u.bindings.findIndex((b) => b.platform === PLATFORM && b.container === sourcetype && b.column === name);
}

function copyBinding(b) {
  const out = {};
  for (const k of BINDING_KEYS) out[k] = k === "evidence" && b[k] ? JSON.parse(JSON.stringify(b[k])) : k === "dismissed" ? Array.from(b[k] || []) : b[k] === undefined ? null : b[k];
  return out;
}

function checkPair(sourcetype, name, what) {
  if (!sourcetype || !name) throw new Error(`${what} needs a sourcetype and a field name`);
  if (isUnsafeKey(sourcetype) || isUnsafeKey(name)) throw new Error(`"${isUnsafeKey(sourcetype) ? sourcetype : name}" cannot be bound`);
}

function putBinding(rec) {
  const u = must();
  const i = bindingIndex(rec.container, rec.column);
  if (i >= 0) u.bindings[i] = rec;
  else u.bindings.push(rec);
  return rec;
}

// The concept note the user wrote on this very pair, when there is one:
// unbinding would leave it keyed by a concept the pair no longer carries.
function noteWrittenOn(sourcetype, name) {
  const u = must();
  for (const [key, ann] of Object.entries(u.concepts || {})) {
    const wo = ann && ann.written_on;
    if (wo && wo.platform === PLATFORM && wo.container === sourcetype && wo.column === name) return { key, ann };
  }
  return null;
}

// The record a confirm would write, checked but not yet stored: a pair a
// pack binds on this platform, an unknown concept or a bad key throws.
function confirmedRecord(sourcetype, name, conceptKey, { alias_of = null, evidence = null, via = null } = {}) {
  checkPair(sourcetype, name, "bindField");
  if (!concepts.concept(conceptKey)) throw new Error(`Unknown concept ${conceptKey}: no loaded pack defines it.`);
  const rec = learned.normaliseBindings([{ platform: PLATFORM, container: sourcetype, column: name, concept: conceptKey, basis: "confirmed", alias_of, confirmed_at: new Date().toISOString(), via, imported_at: null, evidence }])[0];
  if (!rec) throw new Error(`${name} cannot be bound.`);
  const owner = shadowedBy(rec);
  if (owner) {
    const p = packs.pack(owner);
    throw new Error(`${name} is already bound by the ${p ? p.name : owner} pack.`);
  }
  return rec;
}

export async function bindField(sourcetype, name, conceptKey, opts = {}) {
  must();
  const rec = confirmedRecord(sourcetype, name, conceptKey, opts);
  putBinding(rec);
  syncLearned();
  adoptBoundNotes(user); // a note left on the pair moves onto the concept it now carries
  await save();
  return copyBinding(rec);
}

// Several confirms as one write (Confirm all, the sibling offer): every
// pair is checked as bindField checks it, a refused pair is reported in
// `errors` and the rest still land, then one projection, one note
// adoption and one save. Nothing is written when every pair refuses.
export async function bindFields(list) {
  must();
  const records = [];
  const errors = [];
  for (const item of list || []) {
    try {
      records.push(confirmedRecord(item.sourcetype, item.name, item.concept, item));
    } catch (err) {
      errors.push(err && err.message ? err.message : String(err));
    }
  }
  for (const rec of records) putBinding(rec);
  if (records.length) {
    syncLearned();
    adoptBoundNotes(user);
    await save();
  }
  return { records: records.map(copyBinding), errors };
}

// A dismissal replaces whatever record the pair had: with a concept, "not
// this one" (the proposer offers the next); with null, "leave this column
// alone". A confirmation it replaces is simply gone from the resolver; the
// concept note, if any, stays where it is (see unbindField for the copy).
// "Not this" (a concept key) adds to the pair's list of refused concepts;
// "leave this column alone" (null) sets the pair aside outright. Either
// way one record per pair, and every earlier "not this" is kept.
export async function dismissBinding(sourcetype, name, conceptKey = null) {
  const u = must();
  checkPair(sourcetype, name, "dismissBinding");
  const i = bindingIndex(sourcetype, name);
  const prior = i >= 0 && u.bindings[i].basis === "dismissed" ? u.bindings[i].dismissed || [] : [];
  const rec = learned.normaliseBindings([{ platform: PLATFORM, container: sourcetype, column: name, concept: conceptKey, basis: "dismissed", alias_of: null, confirmed_at: new Date().toISOString(), via: null, imported_at: null, evidence: null, dismissed: conceptKey ? [...prior, conceptKey] : prior }])[0];
  if (!rec) throw new Error(`${conceptKey} is not a concept key.`);
  putBinding(rec);
  syncLearned();
  await save();
  return copyBinding(rec);
}

// Drops the pair's record, confirmed or dismissed. A concept note the user
// wrote on this pair is copied back under the pair (the concept keeps its
// copy: other columns still carry it), so nothing they wrote is lost.
export async function unbindField(sourcetype, name) {
  const u = must();
  checkPair(sourcetype, name, "unbindField");
  const i = bindingIndex(sourcetype, name);
  if (i < 0) return;
  const hit = noteWrittenOn(sourcetype, name);
  if (hit) {
    const st = (u.sourcetypes[sourcetype] = u.sourcetypes[sourcetype] || { fields: {} });
    st.fields = st.fields || {};
    const rec = (st.fields[name] = st.fields[name] || {});
    applyPatch(rec, hit.ann, FIELD_KEYS);
    rec.updated_at = hit.ann.updated_at || new Date().toISOString();
  }
  u.bindings.splice(i, 1);
  syncLearned();
  await save();
}

export function learnedBindings() {
  return (must().bindings || []).map(copyBinding);
}

// Every binding gone, the notes on them kept: what switching the coverage
// module off clears (app/lib/wipe.js clearModule), since the bindings are
// a field of the user layer rather than a key of their own.
export async function clearBindings() {
  const u = must();
  const n = (u.bindings || []).length;
  u.bindings = [];
  syncLearned();
  await save();
  return n;
}

export function bindingFor(sourcetype, name) {
  const u = must();
  if (isUnsafeKey(sourcetype) || isUnsafeKey(name)) return null;
  const i = bindingIndex(sourcetype, name);
  return i >= 0 ? copyBinding(u.bindings[i]) : null;
}

export function userLayer() {
  return must();
}

export function noteCount() {
  const u = must();
  let notes = 0;
  for (const st of Object.values(u.sourcetypes)) notes += Object.keys(st.fields || {}).length;
  const conceptNotes = Object.keys(u.concepts || {}).length;
  const bindings = (u.bindings || []).filter((b) => b.basis === "confirmed").length;
  const setAside = (u.bindings || []).filter((b) => b.basis === "dismissed").length;
  return { notes: notes + conceptNotes, sourcetypes: Object.keys(u.sourcetypes).length, concepts: conceptNotes, bindings, setAside };
}

// A copy: the document handed out must not follow later writes.
export function exportUser() {
  const u = must();
  const copy = JSON.parse(JSON.stringify({ sourcetypes: u.sourcetypes, concepts: u.concepts || {}, bindings: u.bindings || [] }));
  return { format: "reach-catalogue", version: USER_VERSION, exported_at: new Date().toISOString(), ...copy };
}

// mode "replace": theirs becomes the user layer.
// mode "merge" (default): per field, keep whichever annotation is newer by
// updated_at; a field only one side has is kept. Bindings merge per
// (platform, container, column) the same way, newer confirmed_at wins,
// and count under added / updated / kept. Returns what changed, in total
// and per kind ({ bindings, notes }: { added, updated, kept }); a merge
// that changes nothing writes nothing, so "last change" stays put.
export async function importUser(doc, { mode = "merge" } = {}) {
  must();
  if (!doc || doc.format !== "reach-catalogue" || !USER_VERSIONS.includes(doc.version) || typeof doc.sourcetypes !== "object") {
    throw new Error("Not a Reach catalogue export (expected format reach-catalogue, version 1 or 2).");
  }
  // Theirs, in this layer's shape: a version-1 export's bound notes move
  // onto their concepts first, so they meet ours on the same key.
  const theirsAll = normaliseUser(JSON.parse(JSON.stringify(doc)));
  adoptBoundNotes(theirsAll);
  const result = { added: 0, updated: 0, kept: 0, sourcetypes: 0, concepts: 0, bindings: { added: 0, updated: 0, kept: 0 }, notes: { added: 0, updated: 0, kept: 0 } };
  if (mode === "replace") {
    user = theirsAll;
    result.sourcetypes = Object.keys(user.sourcetypes).length;
    result.concepts = Object.keys(user.concepts).length;
    result.bindings.added = (user.bindings || []).length;
    let n = 0;
    for (const st of Object.values(user.sourcetypes)) n += Object.keys(st.fields || {}).length;
    result.notes.added = n + result.concepts;
    syncLearned();
    adoptBoundNotes(user); // their notes onto their bindings, in one pass
    await save();
    return result;
  }
  const merged = learned.mergeBindings(user.bindings || [], theirsAll.bindings || []);
  user.bindings = merged.list;
  result.added += merged.added;
  result.updated += merged.updated;
  result.kept += merged.kept;
  result.bindings = { added: merged.added, updated: merged.updated, kept: merged.kept };
  syncLearned(); // before the notes merge: an imported note on an imported binding lands by concept
  user.concepts = user.concepts || {};
  for (const [key, ann] of Object.entries(theirsAll.concepts)) {
    if (isUnsafeKey(key)) continue;
    result.concepts++;
    const cur = user.concepts[key];
    if (!cur) {
      user.concepts[key] = { ...ann };
      result.added++;
      result.notes.added++;
    } else if (String(ann.updated_at || "") > String(cur.updated_at || "")) {
      user.concepts[key] = { ...ann };
      result.updated++;
      result.notes.updated++;
    } else {
      result.kept++;
      result.notes.kept++;
    }
  }
  for (const [st, theirs] of Object.entries(theirsAll.sourcetypes)) {
    if (isUnsafeKey(st)) continue; // a crafted export naming a sourcetype "__proto__" etc. is dropped, not merged
    const mine = (user.sourcetypes[st] = user.sourcetypes[st] || { fields: {} });
    result.sourcetypes++;
    for (const k of ST_KEYS) {
      if (theirs[k] !== undefined && (mine[k] === undefined || String(theirs.updated_at || "") > String(mine.updated_at || ""))) mine[k] = theirs[k];
    }
    mine.fields = mine.fields || {};
    for (const [f, ann] of Object.entries(theirs.fields || {})) {
      if (isUnsafeKey(f)) continue;
      const cur = mine.fields[f];
      if (!cur) {
        mine.fields[f] = { ...ann };
        result.added++;
        result.notes.added++;
      } else if (String(ann.updated_at || "") > String(cur.updated_at || "")) {
        mine.fields[f] = { ...ann };
        result.updated++;
        result.notes.updated++;
      } else {
        result.kept++;
        result.notes.kept++;
      }
    }
    if (!Object.keys(mine.fields).length && !ST_KEYS.some((k) => k in mine)) delete user.sourcetypes[st]; // nothing landed: no empty record
  }
  adoptBoundNotes(user);
  if (result.added || result.updated) await save();
  return result;
}

export default {
  load,
  subscribe,
  sourcetypes,
  sourcetype,
  orgCorpora,
  fieldsOn,
  fieldOn,
  loadFields,
  loadValues,
  valuesReady,
  valueOn,
  decodeOn,
  discriminators,
  edgesFrom,
  userAnnotation,
  fieldEverywhere,
  inferSourcetype,
  leadingContainer,
  searchIndex,
  annotate,
  annotateSourcetype,
  bindField,
  bindFields,
  dismissBinding,
  unbindField,
  learnedBindings,
  bindingFor,
  syncLearned,
  userLayer,
  noteCount,
  exportUser,
  importUser,
  USER_KEY,
  USER_VERSION,
};
