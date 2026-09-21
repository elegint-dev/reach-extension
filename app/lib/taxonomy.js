// The taxonomy: concept types above feeds. A pack's concept says
// `"type": "source_ip"`, and that is what makes CloudTrail's
// sourceIPAddress, an Entra sign-in's IPAddress and Falcon's aip the same
// kind of thing: one meaning fragment, one default role, one value shape
// and one set of hazards (NAT/VPN for addresses, PID recycling for
// process ids), written once in app/packs/taxonomy.json.
//
//   {
//     "format": "reach-taxonomy", "version": 1,
//     "types": { "<id>": { "label", "parent"?, "description", "role", "shape"?, "hazards": [<hazard id>] } },
//     "hazards": { "<id>": { "level": "note|caution|danger", "text" } }
//   }
//
// A type may name a parent; type(id) returns the merge (own fields win,
// hazards accumulate). Two levels are plenty; deeper chains are cut.
//
//   await load()                 the bundled taxonomy (idempotent)
//   register(doc)                a taxonomy document, replacing the bundled one (tests)
//   type(id)                     → { id, label, description, role, shape, hazards: [{ id, level, text }], parent } | null
//   types()                      → [type], sorted by id
//   hazard(id)                   → { id, level, text } | null
//   validate(doc)                → [errors]
//
// No DOM. Safe from a content script.

export const FORMAT = "reach-taxonomy";
export const VERSION = 1;

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
let doc = { types: {}, hazards: {} };
let loaded = false;

function fileUrl(name) {
  return new URL(`../packs/${name}`, import.meta.url).href;
}

export function validate(t) {
  const errors = [];
  if (!t || typeof t !== "object") return ["not an object"];
  if (t.format !== FORMAT) errors.push(`format must be ${FORMAT}`);
  if (t.version !== VERSION) errors.push(`version must be ${VERSION}`);
  if (!t.types || typeof t.types !== "object" || Array.isArray(t.types)) errors.push("types must be an object");
  if (t.hazards !== undefined && (!t.hazards || typeof t.hazards !== "object" || Array.isArray(t.hazards))) errors.push("hazards must be an object");
  for (const [id, rec] of Object.entries(t.types || {})) {
    if (UNSAFE.has(id) || !/^[a-z][a-z0-9_]*$/.test(id)) errors.push(`type id "${id}" must be lowercase letters, digits, underscores`);
    if (!rec || typeof rec !== "object") { errors.push(`type ${id} must be an object`); continue; }
    if (!rec.label) errors.push(`type ${id}: label is required`);
    if (rec.parent !== undefined && !(t.types && t.types[rec.parent])) errors.push(`type ${id}: unknown parent ${rec.parent}`);
    for (const h of rec.hazards || []) if (!(t.hazards && t.hazards[h])) errors.push(`type ${id}: unknown hazard ${h}`);
  }
  for (const [id, h] of Object.entries(t.hazards || {})) {
    if (UNSAFE.has(id)) errors.push(`hazards: unsafe key "${id}"`);
    if (!h || typeof h !== "object" || !h.text) errors.push(`hazard ${id}: text is required`);
  }
  return errors;
}

export function register(t) {
  const errors = validate(t);
  if (errors.length) throw new Error(`taxonomy rejected: ${errors.join("; ")}`);
  doc = { types: t.types || {}, hazards: t.hazards || {} };
  loaded = true;
  return doc;
}

export async function load() {
  if (loaded) return;
  try {
    const res = await fetch(fileUrl("taxonomy.json"));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    register(await res.json());
  } catch (err) {
    console.warn("[Reach] taxonomy:", String(err && err.message ? err.message : err));
    loaded = true; // an empty taxonomy: concepts still resolve, they just have no type
  }
}

export function hazard(id) {
  if (!id || UNSAFE.has(id)) return null;
  const h = Object.prototype.hasOwnProperty.call(doc.hazards, id) ? doc.hazards[id] : null;
  return h ? { id, level: h.level || "note", text: h.text } : null;
}

export function type(id) {
  if (!id || UNSAFE.has(id)) return null;
  const own = Object.prototype.hasOwnProperty.call(doc.types, id) ? doc.types[id] : null;
  if (!own) return null;
  const parent = own.parent && own.parent !== id ? doc.types[own.parent] : null;
  const hazardIds = [...((parent && parent.hazards) || []), ...(own.hazards || [])];
  return {
    id,
    label: own.label || id,
    description: own.description || (parent && parent.description) || "",
    role: own.role || (parent && parent.role) || null,
    shape: own.shape || (parent && parent.shape) || null,
    parent: own.parent || null,
    hazards: Array.from(new Set(hazardIds)).map(hazard).filter(Boolean),
  };
}

export function types() {
  return Object.keys(doc.types).sort().map(type);
}

export function _reset() {
  doc = { types: {}, hazards: {} };
  loaded = false;
}

export default { load, register, type, types, hazard, validate, FORMAT, VERSION };
