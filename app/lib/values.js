// Values: the data-dictionary layer of a feed pack. A concept says what a
// field means (packs.js); this layer says what its values look like and
// what each one means, where that came from, and how sure it is. The
// reference is the AWS CLI's operation page: a synopsis (format), the
// values with one line each, examples, and the document the entry was
// read from.
//
// Per concept (in a pack's concepts.<id>, or in the pack's values sidecar):
//   {
//     "format": "one of five fixed words, case-sensitive",     the synopsis, in words
//     "shape": "arn",                                           a shapes.js shape the values take; every example must show it
//     "examples": [ { "value": "AwsApiCall", "note": "most records" } ],
//     "values": { "<literal>": { "meaning", "cite"?, "provenance"?, "quote"?, "note"? } | "<meaning>" },
//     "provenance": "documented" | "observed" | "inferred",     the default for every value; documented needs a cite
//     "cite": { "url": "https://…", "title": "…", "read_on": "YYYY-MM-DD" },
//     "quote": "at most twenty words of the vendor's own text",  only beside a cite
//     "closed": true                                            the values table is the whole set, not a sample; default false
//   }
// A value's own line under Meaning reads a dictionary as closed (a value
// missed by the table is itself signal: "not one of N documented values")
// when the entry says `closed: true` or the concept's taxonomy type is
// `enum` (bitmask is not: an unmatched literal there is an unseen flag
// combination, not a rejected one). Anything else with only a format is
// open: no value line, the format stays on the field entry alone.
// Per binding (packs.js bindings[]): "provenance": { "kind": indexed | extracted | alias | calculated | lookup | connector, "statement"?, "cite"? }
//
// A pack's decode.values (a lookup's literal → meaning table) is the plain
// ancestor of values: when a concept has a decode and no values entry, the
// decode is normalised into one (source "decode", no provenance claimed),
// so the field page draws one table either way.
//
// A concept of type bitmask carries decode.flags too ({ "0x<8 hex>": name },
// one bit set per key) beside decode.values (whole values with a name of
// their own). The one bitmask rule (decodeBitmask): an exact values key
// reads `<name> (0x<hex>)`; else the set flags ascending by mask joined by
// ` | `, bits no flag covers appended as ` +0x<hex>`; no flag set reads
// nothing (the surfaces say no decode). Only a decimal integer decodes.
//
// The bundled dictionaries are sidecars, one per pack, listed in
// app/packs/index.json under "values" and fetched only when a page needs
// the container (loadFor), so the eager pack load does not grow with them:
//   { "format": "reach-pack-values", "version": 1, "pack": "<pack id>",
//     "licence": { "name", "url"?, "holder"?, "note"? },      the vendor documentation's licence, noted once per pack
//     "cite": { url, title, read_on },                        the feed's reference document (the sourcetype page shows it)
//     "cites": { "<key>": { url, title, read_on } },          a table the entries may cite by key
//     "concepts": { "<concept id>": <entry> },
//     "bindings": [ { "platform", "container", "column", "provenance": {...} } ] }
// Inside a sidecar, any cite (an entry's, a value's, a binding provenance's)
// may be a string naming a row of `cites`; the document is resolved on
// registration, so everything below the loader sees cite objects. Each
// sidecar stays under BUDGET_BYTES; the converter and a test hold that.
//
//   validateEntry(rec, where)              → [errors]   the per-concept keys above (packs.js calls it on inline entries)
//   validateBindingProvenance(p, where)    → [errors]
//   validateDocument(doc, conceptIds)      → [errors]   a sidecar; an entry naming no concept of the pack is an error
//   resolveCites(doc)                      → { doc, errors }   the sidecar with every cite key replaced by its row
//   normalise(rec, decode?)                → Dictionary | null   the canonical shape; a bare meaning string becomes { meaning }
//   register(packId, doc)                  → doc   validate and hold a sidecar, cite keys resolved (tests, and loadFor)
//   indexPack(pack) / dropPack(packId)     hold a pack's inline entries (packs.js calls these as packs come and go)
//   ready(packId)                          → true once the pack's sidecar was fetched (or there is none to fetch)
//   await loadFor(container)               fetch the sidecars of every pack bound on this platform's container; idempotent
//   await loadPack(packId)                 one pack's sidecar
//   dictionary(packId, conceptId)          → Dictionary | null   the sidecar's entry, else the concept's inline entry, else its decode normalised
//   licence(packId) / reference(packId)    → the sidecar's licence / cite | null
//   bindingProvenance(packId, binding)     → the provenance the sidecar gives that (platform, container, column) | null
//   valueOn(container, column, value, { decode }) → ValueRecord | null
//   decodeBitmask(decode, value)           → string | null   the bitmask rule above, pure
//   bitmaskParts(decode, value)            → { name, hex, flags, rest } | null   its parts, for a folded drawing
//   validateFlags(flags, where)            → [errors]   the decode.flags shape
//   oneLiner(description)                  → the first sentence, capped, for an index page
//   citeWords(cite) / provenanceWords(p)   words for a citation line and a provenance chip
//
// Dictionary: { format, closed, shape, examples: [{ value, note }], values: { literal: { meaning, cite, provenance, quote, note } },
//               flags: { "0x<8 hex>": name } | null, provenance, cite, quote, source: "values" | "decode", count }
//   count is the values table's size plus the flags table's
// ValueRecord: { value, meaning, source: "pack" | "discovered", provenance, cite, quote, note, examples, packId, concept }
//   Precedence: the pack's values entry, then a discovered decode table passed in by the caller
//   (catalogue.valueOn), then, later, a known-values corpus (source "known": not here yet).
//
// No DOM, no store. The only network is fetch() of the bundled sidecars
// (the same files packs.js reads its index from).

import * as concepts from "./concepts.js";
import { shapeOf } from "./shapes.js";
import { PLATFORM } from "./platform.js";

export const FORMAT = "reach-pack-values";
export const VERSION = 1;
export const PROVENANCE = ["documented", "observed", "inferred"];
export const BINDING_KINDS = ["indexed", "extracted", "alias", "calculated", "lookup", "connector"];
export const QUOTE_MAX_WORDS = 20;
export const BUDGET_BYTES = 40 * 1024;

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
const FLAG_KEY_RE = /^0x[0-9A-Fa-f]{8}$/;
const DECIMAL_RE = /^[0-9]+$/;

// ---------------------------------------------------------------------------
// The bitmask rule

// decode.flags: an object of `0x` + eight hex digits, exactly one bit set
// per key, to a name. Keys are unique by construction.
export function validateFlags(flags, where = "decode.flags") {
  const errors = [];
  if (!isObj(flags)) return [`${where}: must be an object of 0x<8 hex> mask to name`];
  for (const [k, v] of Object.entries(flags)) {
    if (!FLAG_KEY_RE.test(k)) { errors.push(`${where}.${k}: key must be 0x followed by eight hex digits`); continue; }
    const mask = Number.parseInt(k.slice(2), 16);
    if (mask === 0 || (mask & (mask - 1)) !== 0) errors.push(`${where}.${k}: exactly one bit set`);
    if (typeof v !== "string" || !v.trim()) errors.push(`${where}.${k}: name is required`);
  }
  return errors;
}

// The set flags of a decimal literal, ascending by mask, with what remains.
function flagsOf(flags, n) {
  const set = [];
  let rest = n;
  const entries = Object.entries(isObj(flags) ? flags : {})
    .filter(([k]) => FLAG_KEY_RE.test(k))
    .map(([k, name]) => [Number.parseInt(k.slice(2), 16), name])
    .sort((a, b) => a[0] - b[0]);
  for (const [mask, name] of entries) {
    if ((n & mask) === mask && mask !== 0) {
      set.push(name);
      rest &= ~mask;
    }
  }
  return { set, rest: rest >>> 0 };
}

// The parts of a bitmask value: its own name when decode.values has one,
// the flags it sets (ascending by mask), the bits no flag covers as hex.
// Null when the literal is not a decimal integer or nothing names it.
export function bitmaskParts(decode, value) {
  if (!isObj(decode) || value === undefined || value === null) return null;
  const literal = String(value).trim();
  if (!DECIMAL_RE.test(literal) || UNSAFE.has(literal)) return null;
  const n = Number(literal);
  if (!Number.isSafeInteger(n) || n > 0xffffffff) return null;
  const hex = n.toString(16).toUpperCase();
  let name = null;
  if (isObj(decode.values) && has(decode.values, literal)) {
    const v = decode.values[literal];
    name = typeof v === "string" ? v : isObj(v) && typeof v.meaning === "string" ? v.meaning : String(v);
  }
  const { set, rest } = flagsOf(decode.flags, n);
  if (name === null && !set.length) return null;
  return { name, hex, flags: set, rest: rest ? rest.toString(16).toUpperCase() : null };
}

// What a clicked value of a bitmask concept reads: `<name> (0x<hex>)` for a
// named value, else the set flags joined by ` | ` with the remainder.
export function decodeBitmask(decode, value) {
  const p = bitmaskParts(decode, value);
  if (!p) return null;
  if (p.name !== null) return `${p.name} (0x${p.hex})`;
  return p.rest ? `${p.flags.join(" | ")} +0x${p.rest}` : p.flags.join(" | ");
}
const ENTRY_KEYS = new Set(["format", "shape", "examples", "values", "provenance", "cite", "quote", "closed"]);
const VALUE_KEYS = new Set(["meaning", "cite", "provenance", "quote", "note"]);
const CITE_KEYS = new Set(["url", "title", "read_on"]);
const BINDING_PROVENANCE_KEYS = new Set(["kind", "statement", "cite"]);
const DOC_KEYS = new Set(["format", "version", "pack", "licence", "cite", "cites", "concepts", "bindings"]);
const LICENCE_KEYS = new Set(["name", "url", "holder", "note"]);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const docs = new Map(); // packId → validated sidecar document
const inline = new Map(); // packId → { conceptId → entry } written inside the pack's own concepts
const fetched = new Set(); // packIds whose sidecar was looked for (present or not)
const pending = new Map(); // packId → promise, so two pages asking at once share one fetch
let indexPromise = null;

function has(obj, k) {
  return Boolean(obj) && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, k) && obj[k] !== undefined;
}

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
// Validation. Every checker appends to errors and returns nothing; the
// exported ones return the list.

function onlyKeys(obj, allowed, where, errors) {
  for (const k of Object.keys(obj)) {
    if (UNSAFE.has(k)) errors.push(`${where}: unsafe key "${k}"`);
    else if (!allowed.has(k)) errors.push(`${where}: unknown key "${k}"`);
  }
}

export function wordCount(s) {
  return String(s || "").trim().split(/\s+/).filter(Boolean).length;
}

function checkCite(cite, where, errors) {
  if (!isObj(cite)) { errors.push(`${where}: cite must be an object { url, title, read_on }`); return; }
  onlyKeys(cite, CITE_KEYS, where, errors);
  if (typeof cite.url !== "string" || !/^https?:\/\/\S+$/.test(cite.url)) errors.push(`${where}: cite.url must be an http(s) URL`);
  if (typeof cite.title !== "string" || !cite.title.trim()) errors.push(`${where}: cite.title is required`);
  if (typeof cite.read_on !== "string" || !DATE_RE.test(cite.read_on)) errors.push(`${where}: cite.read_on must be YYYY-MM-DD`);
}

function checkQuote(quote, hasCite, where, errors) {
  if (typeof quote !== "string" || !quote.trim()) { errors.push(`${where}: quote must be a non-empty string`); return; }
  if (wordCount(quote) > QUOTE_MAX_WORDS) errors.push(`${where}: quote is ${wordCount(quote)} words; the cap is ${QUOTE_MAX_WORDS} (paraphrase the rest)`);
  if (!hasCite) errors.push(`${where}: a quote needs a cite`);
}

function checkProvenance(p, where, errors) {
  if (!PROVENANCE.includes(p)) errors.push(`${where}: provenance must be ${PROVENANCE.join(", ")}`);
}

// The per-concept dictionary keys. `where` names the concept for the
// messages. A value entry may be a bare meaning string.
export function validateEntry(rec, where = "entry") {
  const errors = [];
  if (!isObj(rec)) return [`${where}: must be an object`];
  onlyKeys(rec, ENTRY_KEYS, where, errors);
  if (has(rec, "format") && (typeof rec.format !== "string" || !rec.format.trim())) errors.push(`${where}: format must be a non-empty string`);
  if (has(rec, "closed") && typeof rec.closed !== "boolean") errors.push(`${where}: closed must be true or false`);
  if (has(rec, "provenance")) checkProvenance(rec.provenance, where, errors);
  if (has(rec, "cite")) checkCite(rec.cite, where, errors);
  const conceptCite = has(rec, "cite");
  if (has(rec, "quote")) checkQuote(rec.quote, conceptCite, where, errors);
  if (rec.provenance === "documented" && !conceptCite) errors.push(`${where}: provenance documented needs a cite`);

  let examples = [];
  if (has(rec, "examples")) {
    if (!Array.isArray(rec.examples)) errors.push(`${where}: examples must be an array`);
    else {
      examples = rec.examples;
      rec.examples.forEach((ex, i) => {
        const w = `${where}: examples[${i}]`;
        if (!isObj(ex)) { errors.push(`${w}: must be { value, note? }`); return; }
        onlyKeys(ex, new Set(["value", "note"]), w, errors);
        if (typeof ex.value !== "string" || !ex.value) errors.push(`${w}: value must be a non-empty string`);
        if (has(ex, "note") && typeof ex.note !== "string") errors.push(`${w}: note must be a string`);
      });
    }
  }
  if (has(rec, "shape")) {
    if (typeof rec.shape !== "string" || !rec.shape) errors.push(`${where}: shape must be a shape name`);
    else {
      // The vocabulary is shapes.js's detectors, not a list kept here: a
      // shape is accepted when an example shows it, and every example must.
      const good = examples.filter((ex) => isObj(ex) && typeof ex.value === "string");
      if (!good.length) errors.push(`${where}: shape "${rec.shape}" needs an example that shows it`);
      for (const ex of good) {
        const got = shapeOf(ex.value);
        if (!got || got.shape !== rec.shape) errors.push(`${where}: example "${ex.value}" is not shape ${rec.shape}${got ? ` (reads as ${got.shape})` : ""}`);
      }
    }
  }
  if (has(rec, "values")) {
    if (!isObj(rec.values)) errors.push(`${where}: values must be an object keyed by literal`);
    else {
      for (const [literal, v] of Object.entries(rec.values)) {
        const w = `${where}: values["${literal}"]`;
        if (UNSAFE.has(literal)) { errors.push(`${w}: unsafe key`); continue; }
        if (typeof v === "string") { if (!v.trim()) errors.push(`${w}: meaning is empty`); continue; }
        if (!isObj(v)) { errors.push(`${w}: must be a meaning string or { meaning, cite?, provenance?, quote?, note? }`); continue; }
        onlyKeys(v, VALUE_KEYS, w, errors);
        if (typeof v.meaning !== "string" || !v.meaning.trim()) errors.push(`${w}: meaning is required`);
        if (has(v, "note") && typeof v.note !== "string") errors.push(`${w}: note must be a string`);
        if (has(v, "cite")) checkCite(v.cite, w, errors);
        const cited = has(v, "cite") || conceptCite;
        if (has(v, "provenance")) checkProvenance(v.provenance, w, errors);
        const prov = has(v, "provenance") ? v.provenance : rec.provenance;
        if (prov === "documented" && !cited) errors.push(`${w}: provenance documented needs a cite (its own or the concept's)`);
        if (has(v, "quote")) checkQuote(v.quote, cited, w, errors);
      }
    }
  }
  return errors;
}

export function validateBindingProvenance(p, where = "binding") {
  const errors = [];
  if (!isObj(p)) return [`${where}: provenance must be an object { kind, statement?, cite? }`];
  onlyKeys(p, BINDING_PROVENANCE_KEYS, `${where}.provenance`, errors);
  if (!BINDING_KINDS.includes(p.kind)) errors.push(`${where}.provenance: kind must be ${BINDING_KINDS.join(", ")}`);
  if (has(p, "statement") && (typeof p.statement !== "string" || !p.statement.trim())) errors.push(`${where}.provenance: statement must be a non-empty string`);
  if (has(p, "cite")) checkCite(p.cite, `${where}.provenance`, errors);
  return errors;
}

// The sidecar with every cite given as a key replaced by the row of its
// `cites` table (a copy; the input is left alone). A key the table lacks,
// or a bad row, is an error; a cite object passes through as it is.
export function resolveCites(doc) {
  const errors = [];
  if (!isObj(doc)) return { doc, errors: ["not an object"] };
  const table = has(doc, "cites") ? doc.cites : null;
  if (table !== null) {
    if (!isObj(table)) errors.push("cites must be an object keyed by cite key");
    else for (const [k, c] of Object.entries(table)) {
      if (UNSAFE.has(k)) errors.push(`cites: unsafe key "${k}"`);
      else checkCite(c, `cites.${k}`, errors);
    }
  }
  const resolve = (c, where) => {
    if (typeof c !== "string") return c;
    if (!isObj(table) || UNSAFE.has(c) || !has(table, c)) { errors.push(`${where}: cite "${c}" names no row of cites`); return c; }
    return { ...table[c] };
  };
  const out = { ...doc };
  delete out.cites;
  if (isObj(doc.concepts)) {
    out.concepts = {};
    for (const [id, rec] of Object.entries(doc.concepts)) {
      if (!isObj(rec)) { out.concepts[id] = rec; continue; }
      const r = { ...rec };
      if (has(r, "cite")) r.cite = resolve(r.cite, `concepts.${id}`);
      if (isObj(r.values)) {
        r.values = {};
        for (const [literal, v] of Object.entries(rec.values)) {
          r.values[literal] = isObj(v) && has(v, "cite") ? { ...v, cite: resolve(v.cite, `concepts.${id}: values["${literal}"]`) } : v;
        }
      }
      out.concepts[id] = r;
    }
  }
  if (Array.isArray(doc.bindings)) {
    out.bindings = doc.bindings.map((b, i) => (isObj(b) && isObj(b.provenance) && has(b.provenance, "cite") ? { ...b, provenance: { ...b.provenance, cite: resolve(b.provenance.cite, `bindings[${i}].provenance`) } } : b));
  }
  return { doc: out, errors };
}

// A sidecar document. conceptIds: the pack's concept ids (an entry naming
// none of them is a typo, not a new concept). bindingKeys, when given:
// "platform\0container\0column" of the pack's bindings, likewise. Cite
// keys are resolved first, so the entry rules see cite objects.
export function validateDocument(raw, conceptIds, bindingKeys = null) {
  if (!isObj(raw)) return ["not an object"];
  const errors = [];
  onlyKeys(raw, DOC_KEYS, "document", errors);
  const resolved = resolveCites(raw);
  errors.push(...resolved.errors);
  const doc = resolved.doc;
  if (doc.format !== FORMAT) errors.push(`format must be ${FORMAT}`);
  if (doc.version !== VERSION) errors.push(`version must be ${VERSION}`);
  if (typeof doc.pack !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(doc.pack)) errors.push("pack must name a pack id");
  if (has(doc, "licence")) {
    if (!isObj(doc.licence)) errors.push("licence must be an object { name, url?, holder?, note? }");
    else {
      onlyKeys(doc.licence, LICENCE_KEYS, "licence", errors);
      if (typeof doc.licence.name !== "string" || !doc.licence.name.trim()) errors.push("licence.name is required");
    }
  }
  if (has(doc, "cite")) checkCite(doc.cite, "document", errors);
  if (!isObj(doc.concepts)) errors.push("concepts must be an object keyed by concept id");
  else {
    const ids = new Set(conceptIds || []);
    for (const [id, rec] of Object.entries(doc.concepts)) {
      if (UNSAFE.has(id)) { errors.push(`concepts: unsafe key "${id}"`); continue; }
      if (conceptIds && !ids.has(id)) errors.push(`concepts.${id}: names no concept of pack ${doc.pack}`);
      errors.push(...validateEntry(rec, `concepts.${id}`));
    }
  }
  if (has(doc, "bindings")) {
    if (!Array.isArray(doc.bindings)) errors.push("bindings must be an array");
    else doc.bindings.forEach((b, i) => {
      const where = `bindings[${i}]`;
      if (!isObj(b)) { errors.push(`${where}: must be an object`); return; }
      onlyKeys(b, new Set(["platform", "container", "column", "provenance"]), where, errors);
      for (const k of ["platform", "container", "column"]) if (typeof b[k] !== "string" || !b[k]) errors.push(`${where}: ${k} is required`);
      if (bindingKeys && !bindingKeys.has(`${b.platform}\0${b.container}\0${b.column}`)) errors.push(`${where}: ${b.platform}:${b.container}/${b.column} is not a binding of pack ${doc.pack}`);
      errors.push(...validateBindingProvenance(b.provenance, where));
    });
  }
  return errors;
}

// ---------------------------------------------------------------------------
// Normalisation

function normaliseCite(c) {
  return isObj(c) ? { url: c.url, title: c.title, read_on: c.read_on } : null;
}

// The canonical Dictionary for a concept entry. With no entry but a
// decode, the decode's values become the table (source "decode"); with
// neither, null. A value's provenance and cite fall back to the concept's.
export function normalise(rec, decode = null) {
  const entry = isObj(rec) ? rec : null;
  if (!entry && !(decode && (isObj(decode.values) || isObj(decode.flags)))) return null;
  const cite = entry ? normaliseCite(entry.cite) : null;
  const provenance = entry && PROVENANCE.includes(entry.provenance) ? entry.provenance : null;
  const values = {};
  const table = entry && isObj(entry.values) ? entry.values : decode && isObj(decode.values) ? decode.values : {};
  const fromDecode = !(entry && isObj(entry.values)); // the table, when there is one, came from the decode
  const source = fromDecode && decode && isObj(decode.values) ? "decode" : "values";
  for (const [literal, v] of Object.entries(table)) {
    if (UNSAFE.has(literal)) continue;
    const rec = typeof v === "string" ? { meaning: v } : isObj(v) ? v : { meaning: String(v) };
    values[literal] = {
      meaning: rec.meaning,
      cite: fromDecode ? null : normaliseCite(rec.cite) || cite,
      provenance: fromDecode ? null : PROVENANCE.includes(rec.provenance) ? rec.provenance : provenance,
      quote: fromDecode ? null : rec.quote || null,
      note: rec.note || null,
    };
  }
  const flags = decode && isObj(decode.flags) ? Object.fromEntries(Object.entries(decode.flags).filter(([k]) => FLAG_KEY_RE.test(k))) : null;
  return {
    format: (entry && entry.format) || null,
    closed: Boolean(entry && entry.closed),
    shape: (entry && entry.shape) || null,
    examples: entry && Array.isArray(entry.examples) ? entry.examples.map((e) => ({ value: e.value, note: e.note || null })) : [],
    values,
    flags: flags && Object.keys(flags).length ? flags : null,
    provenance,
    cite,
    quote: (entry && entry.quote) || null,
    source,
    lookup: source === "decode" ? decode.lookup || null : null,
    count: Object.keys(values).length + (flags ? Object.keys(flags).length : 0),
  };
}

// ---------------------------------------------------------------------------
// The table of loaded sidecars

export function register(packId, doc) {
  const ids = concepts.conceptsOf(packId).map((c) => c.id);
  const errors = validateDocument(doc, ids.length ? ids : null);
  if (errors.length) throw new Error(`values for ${packId} rejected: ${errors.join("; ")}`);
  if (doc.pack !== packId) throw new Error(`values for ${packId} rejected: document names pack ${doc.pack}`);
  const resolved = resolveCites(doc).doc;
  docs.set(packId, resolved);
  fetched.add(packId);
  return resolved;
}

export function ready(packId) {
  return fetched.has(packId);
}

async function indexDoc() {
  if (!indexPromise) {
    indexPromise = getJson("index.json").catch(() => ({ packs: [] }));
  }
  return indexPromise;
}

// One pack's sidecar, if the index lists one. A pack with no sidecar is
// marked fetched too, so the next page does not ask again. A sidecar that
// fails validation is reported once and left out: a bad dictionary hides
// its own table, never the field.
export async function loadPack(packId) {
  if (fetched.has(packId)) return docs.get(packId) || null;
  if (pending.has(packId)) return pending.get(packId);
  const p = (async () => {
    try {
      const index = await indexDoc();
      const entry = (index.values || []).find((e) => e && e.pack === packId);
      if (!entry || typeof entry.file !== "string") return null;
      return register(packId, await getJson(entry.file));
    } catch (err) {
      console.warn("[Reach] values:", String(err && err.message ? err.message : err));
      return null;
    } finally {
      fetched.add(packId);
      pending.delete(packId);
    }
  })();
  pending.set(packId, p);
  return p;
}

// The packs whose concepts land on a container on this platform: the
// packs binding columns there, and the packs owning the concepts those
// columns resolve to (a column you bound yourself resolves to a feed
// pack's concept through the learned pack).
export function packsOn(container, platform = PLATFORM) {
  const out = new Set();
  const meta = concepts.container(platform, container);
  for (const id of (meta && meta.packIds) || []) out.add(id);
  for (const key of (meta && meta.feedKeys) || []) out.add(String(key).split("/")[0]);
  for (const col of concepts.columnsOn(platform, container)) {
    const r = concepts.resolve(platform, container, col);
    if (r) out.add(r.concept.packId);
  }
  return Array.from(out);
}

export async function loadFor(container, platform = PLATFORM) {
  await Promise.all(packsOn(container, platform).map((id) => loadPack(id)));
}

export function dictionary(packId, conceptId) {
  if (typeof packId !== "string" || typeof conceptId !== "string" || UNSAFE.has(conceptId)) return null;
  const c = concepts.concept(`${packId}/${conceptId}`);
  if (!c) return null;
  const doc = docs.get(packId);
  const side = doc && has(doc.concepts, conceptId) ? doc.concepts[conceptId] : null;
  const own = inline.get(packId);
  const mine = own && has(own, conceptId) ? own[conceptId] : null;
  return normalise(side || mine, c.decode);
}

// The dictionary keys of a pack's concept record, when it carries any inline.
export function pickEntry(rec) {
  if (!isObj(rec)) return null;
  const out = {};
  for (const k of ENTRY_KEYS) if (has(rec, k)) out[k] = rec[k];
  return Object.keys(out).length ? out : null;
}

// A registered pack's inline entries, keyed by concept id. Called by
// packs.js after validation, so nothing here re-checks them.
export function indexPack(pack) {
  if (!isObj(pack) || typeof pack.id !== "string" || !isObj(pack.concepts)) return;
  const entries = {};
  for (const [id, rec] of Object.entries(pack.concepts)) {
    if (UNSAFE.has(id)) continue;
    const e = pickEntry(rec);
    if (e) entries[id] = e;
  }
  if (Object.keys(entries).length) inline.set(pack.id, entries);
  else inline.delete(pack.id);
}

export function dropPack(packId) {
  inline.delete(packId);
}

export function licence(packId) {
  const doc = docs.get(packId);
  return doc && isObj(doc.licence) ? { ...doc.licence } : null;
}

export function reference(packId) {
  const doc = docs.get(packId);
  return doc ? normaliseCite(doc.cite) : null;
}

export function bindingProvenance(packId, binding) {
  const doc = docs.get(packId);
  if (!doc || !Array.isArray(doc.bindings) || !binding) return null;
  const hit = doc.bindings.find((b) => b.platform === binding.platform && b.container === binding.container && b.column === binding.column);
  return hit ? { ...hit.provenance, cite: normaliseCite(hit.provenance.cite) } : null;
}

// ---------------------------------------------------------------------------
// One value

export function valueOn(container, column, value, { decode = null, platform = PLATFORM } = {}) {
  if (value === undefined || value === null) return null;
  const literal = String(value);
  if (UNSAFE.has(literal)) return null;
  const r = container && column ? concepts.resolve(platform, container, column) : null;
  if (r) {
    const d = dictionary(r.concept.packId, r.concept.id);
    if (r.concept.type === "bitmask" && d) {
      // The one bitmask rule: the flags read as a set, an exact value by its own name.
      const meaning = decodeBitmask({ values: d.values, flags: d.flags }, literal);
      if (meaning === null) return null;
      const v = has(d.values, literal) ? d.values[literal] : null;
      return { value: literal, meaning, source: "pack", provenance: (v && v.provenance) || d.provenance, cite: (v && v.cite) || d.cite, quote: v ? v.quote : null, note: v ? v.note : null, examples: d.examples, packId: r.concept.packId, concept: r.key };
    }
    if (d && has(d.values, literal)) {
      const v = d.values[literal];
      return { value: literal, meaning: v.meaning, source: "pack", provenance: v.provenance, cite: v.cite, quote: v.quote, note: v.note, examples: d.examples, packId: r.concept.packId, concept: r.key };
    }
  }
  if (decode && isObj(decode.values) && has(decode.values, literal)) {
    const m = decode.values[literal];
    return { value: literal, meaning: typeof m === "string" ? m : String(m), source: "discovered", provenance: "observed", cite: null, quote: null, note: decode.lookup ? `from your lookup ${decode.lookup}` : null, examples: [], packId: null, concept: r ? r.key : null };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Words

// The first sentence of a description, for an index page: cut at the first
// full stop followed by a space, or at a colon that introduces a list (the
// rest of the sentence has commas, or runs long) when the words before it
// can stand alone ("Kind of event", not "TA"), and capped. A cap cuts at
// a word boundary and marks the cut.
export function oneLiner(description, max = 120) {
  const s = String(description || "").replace(/\s+/g, " ").trim();
  if (!s) return "";
  let cut = s;
  const stop = s.search(/[.!?](\s|$)/);
  if (stop > 0) cut = s.slice(0, stop + 1);
  const colon = cut.indexOf(": ");
  if (colon >= 12) {
    const rest = cut.slice(colon + 2);
    if (rest.includes(",") || rest.length > 40) cut = cut.slice(0, colon);
  }
  if (cut.length > max) {
    const at = cut.lastIndexOf(" ", max - 1);
    cut = `${cut.slice(0, at > 40 ? at : max - 1)}…`;
  }
  return cut;
}

const PROVENANCE_WORDS = {
  documented: "documented",
  observed: "observed",
  inferred: "inferred",
};

export function provenanceWords(p) {
  return PROVENANCE_WORDS[p] || "";
}

export function citeWords(cite) {
  if (!cite) return "";
  return `${cite.title}, read ${cite.read_on}`;
}

export function _reset() {
  docs.clear();
  inline.clear();
  fetched.clear();
  pending.clear();
  indexPromise = null;
}

export default { validateEntry, validateBindingProvenance, validateDocument, resolveCites, normalise, pickEntry, indexPack, dropPack, register, ready, loadPack, loadFor, packsOn, dictionary, licence, reference, bindingProvenance, valueOn, oneLiner, provenanceWords, citeWords, wordCount, FORMAT, VERSION, PROVENANCE, BINDING_KINDS, QUOTE_MAX_WORDS, BUDGET_BYTES };
