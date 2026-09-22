// Runbooks: an alert row recognised by its rule, and a runbook seeded from
// what the rule's author published. A rule is keyed per platform: Splunk's
// ESCU detection id or the saved search's name, Sentinel's AlertName (the
// rule id there is a per-workspace GUID, so the name is the only join), and
// a Sigma rule id wherever a row carries one. The bundles under
// app/data/enrich (escu, sigma, sentinel-rules) carry byId and byName
// indexes and are read lazily, on the first key, never before.
//
//   IDENTITY_FIELDS                the row fields a rule key is read from, both platforms
//   ENTITY_FIELDS                  the row fields a step's pivot binds from, by taxonomy type
//   ALERT_FIELDS                   both lists, the names the popups read off a clicked row
//   ruleKeyFor(row, platform)    → { platform, name, key, keys: [{ source, by, value }] } | null   (pure)
//   parseKey(key)                → { source, by, value } | null                                      (pure)
//   keyString({ source, by, value }) → "source:by:value"                                             (pure)
//   normalizeName(name)          → the byName key the bundles were projected with                    (pure)
//   entitiesOf(row)              → [{ field, value, type }]                                           (pure)
//   await load(source)           → { records, byId, byName, label, ref } | null   the bundle, once per session
//   await lookup(ruleKey)        → { source, record, by, url } | null   the first key that hits a bundle
//   await seedFor(ruleKey, { row }) → runbook   steps in order: confirm the trigger, one per false-positive
//                                  condition, one pivot per entity the row carries, then close (Hold or
//                                  Mark benign); seeded_from names the bundle so the runbook teaches
//                                  only what it knows, null when no bundle has the rule
//   pivotOptions(row, platform)  → [{ id, label, type, field, pivot: { packId, edge, container, type, binds }, edge }]
//                                  every pack pivot a runbook step can bind, by entity type, for the editor
//   href(ruleKey, row)           → "#/runbook/<key>?rule=…&st=…&<entity>=…"   the panel page, the row's container and entities carried
//   originOf(ruleKey, platform)  → { ruleKey, ruleName, platform }   what a Hold from the row stamps on the
//                                  investigation it starts (notebook.js origin); null without a key
//   reset()                        clears the loaded bundles (tests only)
//
// Plain ES module. No DOM. Safe from a content script.

import * as packs from "./packs.js";
import * as concepts from "./concepts.js";
import { PLATFORM } from "./platform.js";

const SOURCES = {
  escu: { file: "escu.json", list: "detections", label: "Splunk ESCU", name: (r) => r.name },
  sigma: { file: "sigma.json", list: "rules", label: "Sigma", name: (r) => r.title },
  "sentinel-rules": { file: "sentinel-rules.json", list: "rules", label: "Sentinel analytic rules", name: (r) => r.name },
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ESCU_NAME_RE = /^ESCU\s+-\s+(.+?)\s+-\s+Rule$/i;
const MAX_PIVOTS_PER_ENTITY = 3;
const MAX_ENTITIES = 6;

export const IDENTITY_FIELDS = Object.freeze({
  splunk: Object.freeze([
    "action.correlationsearch.metadata.detection_id",
    "action.correlationsearch.metadata",
    "detection_id",
    "search_name",
    "savedsearch_name",
    "rule_name",
    "rule_id",
    "sigma_id",
    "orig_sid",
    "event_id",
  ]),
  sentinel: Object.freeze(["AlertName", "AlertType", "SystemAlertId", "ProviderName", "Tactics", "Techniques", "Entities", "CompromisedEntity", "sigma_id", "rule_id"]),
});

// Row field name → taxonomy type, both platforms' spellings. Scope facts
// (index, workspace, time) are never here: they are configuration.
export const ENTITY_FIELDS = Object.freeze({
  dest: "hostname",
  dest_host: "hostname",
  dest_nt_host: "hostname",
  src_host: "hostname",
  dvc: "hostname",
  Computer: "hostname",
  HostName: "hostname",
  DeviceName: "hostname",
  user: "user_name",
  src_user: "user_name",
  dest_user: "user_name",
  Account: "user_name",
  AccountName: "user_name",
  UserPrincipalName: "user_name",
  src: "source_ip",
  src_ip: "source_ip",
  IPAddress: "source_ip",
  SourceIP: "source_ip",
  file_hash: "file_hash",
  sha256: "file_hash",
  SHA256HashData: "file_hash",
  FileHash: "file_hash",
  file_name: "file_name",
  process_name: "file_name",
  FileName: "file_name",
  aid: "host_id",
  Aid: "host_id",
  risk_object: null,
  risk_object_type: null,
});

export const ALERT_FIELDS = Object.freeze(Array.from(new Set([...IDENTITY_FIELDS.splunk, ...IDENTITY_FIELDS.sentinel, ...Object.keys(ENTITY_FIELDS)])));

// The same normalisation the bundles' byName indexes were projected with.
export function normalizeName(name) {
  if (!name) return "";
  return String(name)
    .toLowerCase()
    .replace(/[^\w\s]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function keyString(k) {
  return `${k.source}:${k.by}:${k.value}`;
}

export function parseKey(key) {
  const s = String(key || "");
  const m = /^([a-z-]+):(id|name):(.+)$/.exec(s);
  if (!m || !SOURCES[m[1]]) return null;
  return { source: m[1], by: m[2], value: m[3] };
}

function str(v) {
  if (v === undefined || v === null) return "";
  return String(v).trim();
}

function jsonField(row, name) {
  const raw = str(row[name]);
  if (!raw || raw[0] !== "{") return null;
  try {
    const o = JSON.parse(raw);
    return o && typeof o === "object" ? o : null;
  } catch {
    return null;
  }
}

// The search's own name, stripped of ESCU's "ESCU - <name> - Rule" frame.
function escuName(name) {
  const m = ESCU_NAME_RE.exec(name);
  return m ? m[1] : name;
}

function push(keys, seen, k) {
  if (!k.value) return;
  const s = keyString(k);
  if (seen.has(s)) return;
  seen.add(s);
  keys.push(k);
}

export function ruleKeyFor(row, platform = PLATFORM) {
  if (!row || typeof row !== "object") return null;
  const keys = [];
  const seen = new Set();
  let name = null;
  if (platform === "sentinel") {
    const alertName = str(row.AlertName);
    if (alertName) {
      name = alertName;
      push(keys, seen, { source: "sentinel-rules", by: "name", value: normalizeName(alertName) });
    }
    for (const f of ["sigma_id", "rule_id"]) {
      const v = str(row[f]);
      if (UUID_RE.test(v)) push(keys, seen, { source: "sigma", by: "id", value: v.toLowerCase() });
    }
  } else {
    const meta = jsonField(row, "action.correlationsearch.metadata");
    const ids = [str(row["action.correlationsearch.metadata.detection_id"]), meta ? str(meta.detection_id) : "", str(row.detection_id)];
    for (const v of ids) if (UUID_RE.test(v)) push(keys, seen, { source: "escu", by: "id", value: v.toLowerCase() });
    for (const f of ["search_name", "savedsearch_name", "rule_name"]) {
      const v = str(row[f]);
      if (!v) continue;
      if (!name) name = escuName(v);
      push(keys, seen, { source: "escu", by: "name", value: normalizeName(escuName(v)) });
    }
    for (const f of ["rule_id", "sigma_id"]) {
      const v = str(row[f]);
      if (!UUID_RE.test(v)) continue;
      if (f === "rule_id") push(keys, seen, { source: "escu", by: "id", value: v.toLowerCase() });
      push(keys, seen, { source: "sigma", by: "id", value: v.toLowerCase() });
    }
  }
  if (!keys.length) return null;
  return { platform: platform === "sentinel" ? "sentinel" : "splunk", name, key: keyString(keys[0]), keys };
}

// Sentinel's Entities column: a JSON list of typed entities.
function sentinelEntities(row) {
  const raw = str(row.Entities);
  if (!raw || raw[0] !== "[") return [];
  let list;
  try {
    list = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const e of list) {
    if (!e || typeof e !== "object") continue;
    const t = String(e.Type || "").toLowerCase();
    if (t === "host" && e.HostName) out.push({ field: "Entities.HostName", value: str(e.HostName), type: "hostname" });
    else if (t === "account" && e.Name) out.push({ field: "Entities.Name", value: str(e.Name), type: "user_name" });
    else if (t === "ip" && e.Address) out.push({ field: "Entities.Address", value: str(e.Address), type: "source_ip" });
    else if (t === "filehash" && e.Value) out.push({ field: "Entities.Value", value: str(e.Value), type: "file_hash" });
  }
  return out;
}

export function entitiesOf(row) {
  if (!row || typeof row !== "object") return [];
  const out = [];
  const seen = new Set();
  const add = (e) => {
    if (!e.value) return;
    const k = `${e.type}\u0000${e.value}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(e);
  };
  for (const [field, type] of Object.entries(ENTITY_FIELDS)) {
    if (!type) continue;
    const v = str(row[field]);
    if (v) add({ field, value: v, type });
  }
  for (const e of sentinelEntities(row)) add(e);
  return out.slice(0, MAX_ENTITIES);
}

// ---------------------------------------------------------------------------
// The bundles

const cache = {};

export async function load(source) {
  const spec = SOURCES[source];
  if (!spec) return null;
  if (!cache[source]) {
    cache[source] = (async () => {
      let res;
      try {
        res = await fetch(new URL(`../data/enrich/${spec.file}`, import.meta.url).href);
      } catch {
        return null;
      }
      if (!res || !res.ok) return null;
      let doc;
      try {
        doc = await res.json();
      } catch {
        return null;
      }
      const records = doc && Array.isArray(doc[spec.list]) ? doc[spec.list] : null;
      if (!records) return null;
      return { records, byId: doc.byId || {}, byName: doc.byName || {}, label: spec.label, ref: doc.ref || doc.release || null, meta: doc.meta || {} };
    })();
  }
  return cache[source];
}

export function reset() {
  for (const k of Object.keys(cache)) delete cache[k];
}

export function label(source) {
  return SOURCES[source] ? SOURCES[source].label : source;
}

function keysOf(ruleKey) {
  if (!ruleKey) return [];
  if (typeof ruleKey === "string") {
    const k = parseKey(ruleKey);
    return k ? [k] : [];
  }
  if (Array.isArray(ruleKey.keys) && ruleKey.keys.length) return ruleKey.keys;
  const k = ruleKey.key ? parseKey(ruleKey.key) : ruleKey.source ? ruleKey : null;
  return k ? [k] : [];
}

// A rule id is a GUID: when the listed source misses it, the other
// id-keyed bundles are tried too, so a page opened on one key string
// finds a Sigma rule behind an escu:id key.
function withIdFallbacks(keys) {
  const out = keys.slice();
  const seen = new Set(keys.map(keyString));
  for (const k of keys) {
    if (k.by !== "id") continue;
    for (const source of Object.keys(SOURCES)) {
      const alt = { source, by: "id", value: k.value };
      if (seen.has(keyString(alt))) continue;
      seen.add(keyString(alt));
      out.push(alt);
    }
  }
  return out;
}

export async function lookup(ruleKey) {
  for (const k of withIdFallbacks(keysOf(ruleKey))) {
    const idx = await load(k.source);
    if (!idx) continue;
    const table = k.by === "id" ? idx.byId : idx.byName;
    const value = k.by === "id" ? String(k.value).toLowerCase() : normalizeName(k.value);
    const pos = Object.prototype.hasOwnProperty.call(table, value) ? table[value] : undefined;
    const record = typeof pos === "number" ? idx.records[pos] : null;
    if (record) return { source: k.source, by: k.by, record, url: record.url || null, label: idx.label, ref: idx.ref, meta: idx.meta };
  }
  return null;
}

// ---------------------------------------------------------------------------
// The seed

const NO_FP_RE = /^(no (known )?false positives?( have been identified)?\.?|none\.?|unknown\.?|unlikely\.?|n\/a\.?)$/i;

function sentences(text) {
  return String(text || "")
    .split(/(?<=[.!?])\s+(?=[A-Z])/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// One condition per listed false positive: Sigma lists them, ESCU writes a
// paragraph (split by sentence), Sentinel's schema has no field.
export function falsePositivesOf(source, record) {
  if (!record) return [];
  if (source === "sigma") return (record.falsepositives || []).map((s) => str(s)).filter((s) => s && !NO_FP_RE.test(s));
  if (source === "escu") {
    const text = str(record.known_false_positives);
    if (!text || NO_FP_RE.test(text)) return [];
    return sentences(text).filter((s) => !NO_FP_RE.test(s));
  }
  return [];
}

function unquote(s) {
  const t = str(s);
  return t.length > 1 && t[0] === "'" && t[t.length - 1] === "'" ? t.slice(1, -1) : t;
}

// Every pack pivot leaving a column that carries this entity's type on
// this platform, its parameters bound from the row.
function pivotsFor(entity, row, platform) {
  const out = [];
  const seen = new Set();
  let list = [];
  try {
    list = concepts.ofType(entity.type, platform);
  } catch {
    list = [];
  }
  for (const c of list) {
    for (const b of concepts.bindingsOf(c.key, platform)) {
      for (const edge of packs.edgesFrom(b.container, b.column)) {
        const id = `${edge.packId}/${edge.id}`; // one step per pivot, on the first container that carries the entity
        if (seen.has(id)) continue;
        seen.add(id);
        const pmeta = packs.params(edge.packId, edge.src.sourcetype);
        const params = { value: entity.value };
        const bound = ["value"];
        for (const [pname, pm] of Object.entries(pmeta)) {
          if (pm && pm.from_field && params[pname] === undefined) {
            const v = str(row[pm.from_field]);
            if (v) {
              params[pname] = v;
              bound.push(pname);
            }
          }
        }
        out.push({ edge, packId: edge.packId, params, bound, meta: pmeta });
        if (out.length >= MAX_PIVOTS_PER_ENTITY) return out;
      }
    }
  }
  return out;
}

export async function seedFor(ruleKey, { row = {}, platform = PLATFORM } = {}) {
  const rk = typeof ruleKey === "string" ? { key: ruleKey, keys: keysOf(ruleKey), name: null, platform } : ruleKey;
  const hit = await lookup(rk);
  const record = hit ? hit.record : null;
  const source = hit ? hit.source : null;
  const title = (record && SOURCES[source].name(record)) || rk.name || (rk.keys && rk.keys[0] ? rk.keys[0].value : "") || "";
  const description = record ? unquote(record.description) : "";
  const falsePositives = falsePositivesOf(source, record);
  const techniques = record && Array.isArray(record.techniques) ? record.techniques.slice() : [];
  const entities = entitiesOf(row);

  const steps = [];
  steps.push({
    id: "confirm",
    kind: "confirm",
    question: "Does the row match what the rule looks for?",
    why: description || (record ? "The bundle carries no description for this rule; read the rule's own text." : `${title || "This rule"} is not in the bundled rule indexes: read the rule's own description in ${platform === "sentinel" ? "the analytics rule" : "the saved search"}.`),
  });
  falsePositives.forEach((text, i) => {
    steps.push({ id: `fp-${i + 1}`, kind: "false_positive", question: "Does this false-positive condition apply?", why: text });
  });
  for (const entity of entities) {
    for (const p of pivotsFor(entity, row, platform)) {
      steps.push({
        id: `pivot-${entity.field}-${p.packId}-${p.edge.id}`,
        kind: "pivot",
        question: `${p.edge.label} for ${entity.field} = ${entity.value}`,
        why: p.edge.note || null,
        entity,
        pivot: { edge: p.edge, packId: p.packId, params: p.params, bound: p.bound, meta: p.meta },
      });
    }
  }
  steps.push({
    id: "close",
    kind: "close",
    question: "Hold the entity for the investigation, or mark it benign?",
    why: falsePositives.length ? "A false-positive condition that applies closes the alert as benign; the trigger confirmed with none applying is held." : "The trigger confirmed is held; anything the rule's author did not foresee is your own call.",
  });

  const bound = steps.filter((s) => s.pivot && s.pivot.bound.length).length;
  return {
    format: "reach-runbook",
    version: 1,
    id: rk.key || (rk.keys && rk.keys[0] ? keyString(rk.keys[0]) : ""),
    title,
    rule: { platform: rk.platform || platform, keys: rk.keys || [], name: rk.name || title },
    seeded_from: hit ? { source, id: record.id || null, url: hit.url, label: `seeded from ${hit.label}`, ref: hit.ref, author: (source === "sigma" && record.author) || null, truncated: Boolean(hit.meta && hit.meta.description_truncated) } : null,
    description,
    false_positives: falsePositives,
    techniques,
    entities,
    steps,
    bound,
    benign_when: falsePositives.map((text) => ({ text })),
    escalate_when: [{ text: description ? "The trigger is confirmed and no false-positive condition applies." : "The trigger is confirmed." }],
  };
}

// Every pack pivot leaving a column of each entity type on this platform,
// its value bound from the row's own field of that type when the row
// carries one, else from the type's first spelling.
export function pivotOptions(row = {}, platform = PLATFORM) {
  const out = [];
  const seen = new Set();
  const present = new Map(entitiesOf(row).map((e) => [e.type, e.field]));
  const types = Array.from(new Set(Object.values(ENTITY_FIELDS).filter(Boolean)));
  for (const type of types) {
    const field = present.get(type) || Object.keys(ENTITY_FIELDS).find((f) => ENTITY_FIELDS[f] === type);
    let list = [];
    try {
      list = concepts.ofType(type, platform);
    } catch {
      list = [];
    }
    for (const c of list) {
      for (const b of concepts.bindingsOf(c.key, platform)) {
        for (const edge of packs.edgesFrom(b.container, b.column)) {
          const id = `${edge.packId}/${edge.id}`;
          if (seen.has(id)) continue;
          seen.add(id);
          const pmeta = packs.params(edge.packId, edge.src.sourcetype);
          const binds = { value: field };
          for (const [pname, pm] of Object.entries(pmeta)) if (pm && pm.from_field && binds[pname] === undefined) binds[pname] = pm.from_field;
          out.push({ id, label: edge.label, type, field, pivot: { packId: edge.packId, edge: edge.id, container: edge.src.sourcetype, type, binds }, edge });
        }
      }
    }
  }
  return out;
}

// The primary entity a close step holds or marks benign: the risk object
// when the row names one, else the compromised entity, else the first
// entity the row carries. A compromised entity is returned as the row
// entity carrying its value, so the Hold's field is the one the pack
// pivots bind from and a pivot run finds the pin.
export function primaryEntity(runbook, row = {}) {
  const ro = str(row.risk_object);
  if (ro) {
    const type = str(row.risk_object_type).toLowerCase();
    const field = type === "user" ? "user" : type === "system" ? "dest" : "risk_object";
    return { field, value: ro, type: type === "user" ? "user_name" : "hostname" };
  }
  const ce = str(row.CompromisedEntity);
  if (ce) {
    const same = ce.toLowerCase();
    const listed = entitiesOf(row).find((e) => e.value.toLowerCase() === same);
    return listed || { field: "CompromisedEntity", value: ce, type: null };
  }
  return runbook && runbook.entities && runbook.entities[0] ? runbook.entities[0] : null;
}

export function href(ruleKey, row = {}) {
  const rk = typeof ruleKey === "string" ? { key: ruleKey } : ruleKey;
  const key = rk && (rk.key || (rk.keys && rk.keys[0] && keyString(rk.keys[0])));
  if (!key) return null;
  // Encoded the way router.js decodes (decodeURIComponent: a space is %20, never +).
  const pairs = [];
  const set = (k, v) => pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  if (rk.name) set("rule", rk.name);
  if (str(row.sourcetype) || str(row.Type)) set("st", str(row.sourcetype) || str(row.Type));
  for (const e of entitiesOf(row)) if (!e.field.startsWith("Entities.")) set(e.field, e.value);
  for (const f of ["risk_object", "risk_object_type", "CompromisedEntity"]) if (str(row[f])) set(f, str(row[f]));
  if (str(row.Entities)) set("Entities", str(row.Entities).slice(0, 2000));
  return `#/runbook/${encodeURIComponent(key)}${pairs.length ? `?${pairs.join("&")}` : ""}`;
}

export function originOf(ruleKey, platform = PLATFORM) {
  const rk = typeof ruleKey === "string" ? { key: ruleKey } : ruleKey;
  const key = rk && (rk.key || (rk.keys && rk.keys[0] && keyString(rk.keys[0])));
  if (!key) return null;
  return { ruleKey: key, ruleName: rk.name || null, platform: rk.platform || platform };
}

export default { IDENTITY_FIELDS, ENTITY_FIELDS, ALERT_FIELDS, ruleKeyFor, parseKey, keyString, normalizeName, entitiesOf, load, lookup, label, falsePositivesOf, seedFor, pivotOptions, primaryEntity, href, originOf, reset };
