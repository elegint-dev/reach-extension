// Falcon dictionary: a local layer built from the analyst's own FDR schema
// pull (board it_9951cfe3), imported from Settings' Data group. One
// document under store key "catalogue.falcon" (chrome.storage.local
// reach.catalogue.falcon; localStorage when the app is served as a plain
// page). catalogue.js reads it for a Falcon container's field when the
// bundle and the packs have nothing better; it is the team's own file and
// never leaves through exportUser().
//
// The loader's file: { version: 1, source: "falcon-fdr-schema", cloud,
// pulled_at, events: { name: { variants: [{ platform, version, base_id,
// description, fields }] } }, fields: { name: { description, type,
// universal, values, events: [{ name, platforms }] } } }. Stored here is
// only what a page reads: a field's type, its values (an enumerated
// field's literal → meaning table), the event names it rides on, its own
// description where the pull carried one (the real pull's are almost
// always empty, so this is usually absent; catalogue.js's fieldOn() only
// reads it below the user's note and the pack's), and an event's own
// description where at least one of its variants carries one. The
// per-variant field lists (the bulk of the real file) are dropped
// entirely, since fieldOn()'s events array is membership already.
//
//   check(raw)             → the stored shape, or throws naming the problem
//   await importDoc(raw)   → { fields, events, pulled_at }   the counts moduleList.js shows
//   await forget()
//   await load()             the document; the readers below are sync after it
//   present()               → true once a dictionary is imported
//   counts()                → { fields, events, pulled_at } | null
//   fieldOn(name)           → { type, description?, values?, events: [name, ...] } | null
//   eventOn(name)           → { description } | null
//   bytes()
//   isFalconContainer(name) → true for a Splunk crowdstrike:* sourcetype or
//                             a Sentinel table whose name carries CrowdStrike
//   subscribe(fn)           → fn() after any write from any context; returns unsubscribe
//   _reset()                (tests)
//
// Plain ES module. No DOM.

import { versionedDocument } from "./document.js";

export const KEY = "catalogue.falcon";
export const VERSION = 1;
export const SOURCE = "falcon-fdr-schema";
export const MAX_BYTES = 6_000_000; // chrome.storage.local's own cap is 10 MB with no unlimitedStorage permission

const UNSAFE_KEY = new Set(["__proto__", "constructor", "prototype"]);
const MAX_TYPE = 60;
const MAX_NAME = 200;
const MAX_VALUE = 500;
const MAX_DESCRIPTION = 1000;
const MAX_EVENTS_PER_FIELD = 300;

function text(v, max) {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

function stripField(rec) {
  if (!rec || typeof rec !== "object") return null;
  const type = text(rec.type, MAX_TYPE) || null;
  // The real pull's field descriptions are almost always empty (the
  // note on board it_9951cfe3), but the shape allows one, and a later
  // pull or a different tenant can carry one; kept only when non-empty.
  const description = text(rec.description, MAX_DESCRIPTION) || null;
  const values = {};
  if (rec.values && typeof rec.values === "object") {
    for (const [literal, v] of Object.entries(rec.values)) {
      if (UNSAFE_KEY.has(literal)) continue;
      const k = text(literal, MAX_VALUE);
      const meaning = text(typeof v === "string" ? v : v === null || v === undefined ? "" : String(v), MAX_VALUE);
      if (k && meaning) values[k] = meaning;
    }
  }
  const events = Array.isArray(rec.events)
    ? Array.from(new Set(rec.events.map((e) => text(e && e.name, MAX_NAME)).filter(Boolean))).slice(0, MAX_EVENTS_PER_FIELD)
    : [];
  if (!type && !description && !Object.keys(values).length && !events.length) return null;
  const out = { type, events };
  if (description) out.description = description;
  if (Object.keys(values).length) out.values = values;
  return out;
}

// The first non-empty description across an event's variants (they can
// differ by platform, "LZMA-compressed file write, macOS." vs "...,
// Windows."); one description per event name is what the field and
// sourcetype pages read, so the first one found stands for the name.
function stripEvent(rec) {
  if (!rec || typeof rec !== "object" || !Array.isArray(rec.variants)) return null;
  for (const v of rec.variants) {
    const description = text(v && v.description, MAX_DESCRIPTION);
    if (description) return { description };
  }
  return null;
}

function bytesOf(doc) {
  const s = JSON.stringify(doc === undefined ? null : doc);
  return typeof TextEncoder !== "undefined" ? new TextEncoder().encode(s).length : s.length;
}

// A foreign or malformed pull becomes a reason it was refused, not a
// half-imported document.
export function check(raw) {
  if (!raw || typeof raw !== "object") throw new Error("Not a Falcon dictionary: expected a JSON object.");
  if (raw.version !== VERSION) throw new Error(`Not a Falcon dictionary: expected version ${VERSION}, got ${raw.version === undefined ? "none" : JSON.stringify(raw.version)}.`);
  if (raw.source !== SOURCE) throw new Error(`Not a Falcon dictionary: expected source ${JSON.stringify(SOURCE)}, got ${raw.source === undefined ? "none" : JSON.stringify(raw.source)}.`);
  if (!raw.fields || typeof raw.fields !== "object" || Array.isArray(raw.fields)) throw new Error("Not a Falcon dictionary: no fields map.");
  if (!raw.events || typeof raw.events !== "object" || Array.isArray(raw.events)) throw new Error("Not a Falcon dictionary: no events map.");

  const fields = {};
  let fieldsWithValues = 0;
  for (const [name, rec] of Object.entries(raw.fields)) {
    if (UNSAFE_KEY.has(name)) continue;
    const stripped = stripField(rec);
    if (!stripped) continue;
    fields[text(name, MAX_NAME)] = stripped;
    if (stripped.values) fieldsWithValues++;
  }

  const events = {};
  for (const [name, rec] of Object.entries(raw.events)) {
    if (UNSAFE_KEY.has(name)) continue;
    const stripped = stripEvent(rec);
    if (!stripped) continue;
    events[text(name, MAX_NAME)] = stripped;
  }

  const doc = {
    v: VERSION,
    source: SOURCE,
    cloud: text(raw.cloud, 40) || null,
    pulled_at: text(raw.pulled_at, 60) || null,
    imported_at: new Date().toISOString(),
    counts: { fields: Object.keys(fields).length, fieldsWithValues, events: Object.keys(events).length },
    fields,
    events,
  };
  const size = bytesOf(doc);
  if (size > MAX_BYTES) throw new Error(`This Falcon dictionary is ${Math.round(size / 1e6)} MB stored, over the ${Math.round(MAX_BYTES / 1e6)} MB bound for one import. Split the pull, or ask CrowdStrike support for a narrower field or event filter.`);
  return doc;
}

function empty() {
  return { v: VERSION, source: SOURCE, cloud: null, pulled_at: null, imported_at: null, counts: null, fields: {}, events: {} };
}

// A stored value that is not this shape (nothing imported, or a version
// this build does not know) reads as empty rather than throwing: adopt()
// never rejects a read the way check() rejects an import.
function adopt(raw) {
  if (!raw || typeof raw !== "object" || raw.v !== VERSION || !raw.fields || !raw.events) return empty();
  return raw;
}

const D = versionedDocument({ key: KEY, version: VERSION, empty, adopt });

export async function load(opts) {
  return D.load(opts);
}

export function present() {
  return Boolean(D.get().counts);
}

export function counts() {
  const d = D.get();
  return d.counts ? { ...d.counts, cloud: d.cloud, pulled_at: d.pulled_at, imported_at: d.imported_at } : null;
}

export function fieldOn(name) {
  if (!name || UNSAFE_KEY.has(name)) return null;
  const d = D.get();
  return d.fields && Object.prototype.hasOwnProperty.call(d.fields, name) ? d.fields[name] : null;
}

export function eventOn(name) {
  if (!name || UNSAFE_KEY.has(name)) return null;
  const d = D.get();
  return d.events && Object.prototype.hasOwnProperty.call(d.events, name) ? d.events[name] : null;
}

export function bytes() {
  return D.bytes();
}

// A container carries Falcon FDR fields when its name says so: every
// Splunk crowdstrike:* sourcetype (crowdstrike-falcon.json's containers)
// and any Sentinel table whose name carries "CrowdStrike" (the shipped
// sample's ReachCrowdStrike_CL, and a customer's own ingestion table
// follows the same habit). Not the discovered-columns heuristic
// isFleetBaselineTable uses (app/views/sourcetype.js): that needs live
// discovery data for one specific table, where this only needs a name and
// runs on every field read.
export function isFalconContainer(name) {
  return typeof name === "string" && /crowdstrike/i.test(name);
}

export async function importDoc(raw) {
  const doc = check(typeof raw === "string" ? JSON.parse(raw) : raw);
  await D.update((d) => {
    d.v = doc.v;
    d.source = doc.source;
    d.cloud = doc.cloud;
    d.pulled_at = doc.pulled_at;
    d.imported_at = doc.imported_at;
    d.counts = doc.counts;
    d.fields = doc.fields;
    d.events = doc.events;
  });
  return counts();
}

export async function forget() {
  await D.update((d) => {
    Object.assign(d, empty());
  });
}

export function subscribe(fn) {
  return D.subscribe(fn);
}

export function _reset() {
  D._reset();
}

export default { KEY, VERSION, SOURCE, MAX_BYTES, check, load, present, counts, fieldOn, eventOn, bytes, isFalconContainer, importDoc, forget, subscribe, _reset };
