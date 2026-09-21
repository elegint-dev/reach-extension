// The discovered layer's store: one environment per storage key, one
// writer for both platforms, a byte budget. discovery.js (Splunk, over the
// relay) and recipe.js (Sentinel, pasted results) write their records
// through update(); catalogue.js, the Discover pages, the sweep and the
// Coverage page read them here. The record's shape is stated below; what
// it means is the readers' business.
//
//   load()                      → reconciles the index against the stored keys; once per app load
//   readAll()                   → { [envKey]: env }
//   read(envKey)                → env | null
//   update(envKey, fn, opts?)   → { env, notice }   fn(env) mutates in place; serialised behind every other write
//   forget(envKey)
//   subscribe(fn)               → fn(envKey, env | undefined) after any change from any context; returns unsubscribe
//   bytes(doc)                  → the document's size as stored
//   platformOf(envKey)          → "splunk" | "sentinel"
//   epochOf(value)              → first_seen / last_seen as epoch seconds, from either stored form
//   systemFields(platform?)     → Set of the platform's own columns (SYSTEM_FIELDS), both when unnamed
//
// An envKey is the Splunk origin (https://splunk.example) or the Sentinel
// workspace resource id, used verbatim after the prefix.
//
// Storage:
//   catalogue.discovered.<envKey>   one environment
//   catalogue.discovered.envs       { version: 2, envs: { [envKey]: { discovered_at, bytes } } }
// A write touches its own environment and the index, never another
// environment. The index is what readAll() and the layer-wide budget read;
// load() reconciles it against the keys actually stored.
//
// The record both writers store per sourcetype (Splunk) or table (Sentinel):
//   { indexes, count, fields: { [name]: { profile?, declared?, provenance?, decodes? } },
//     first_seen, last_seen            epoch seconds on both platforms; epochOf() reads
//                                      them, and the ISO strings stored before they were normalised
//     inventoried_at, profiled_at, ... ISO strings: when Reach measured, not when the data was
//     discriminator, record_types, runs, missing_since, profile_delta, sample, mb, solution, billable }
// A field's profile: { count, distinct, distinct_exact (true | false | null when the
// platform's query cannot say), fill, numeric, min, max, mean, top, sample, measured_at, window }.
// The platform's own columns (SYSTEM_FIELDS) are not recorded as fields.
//
// An environment also carries what is measured once per environment, not
// per sourcetype: env.org_corpus, the fleet's process binaries (known.js
// states its shape and keeps it under its own byte budget).
//
// Budget: chrome.storage.local is capped at 10 MB without unlimitedStorage.
// One environment stays under ENV_MAX_BYTES and the layer under MAX_BYTES;
// update() prunes before it writes, cheapest-to-recover data first, and
// says in `notice` what went and which button reads it again:
//   1. the organisation corpus, one search to read again
//   2. decode tables, oldest read_at first
//   3. field top values, least recently profiled sourcetype first
//   4. run history, trimmed to RUNS_AFTER_PRUNE per sourcetype
//   5. across the layer: the environment with the oldest discovered_at,
//      other than the one being written
//
// pushRun(rec, run), profileDelta(before, after) and applyProfile(rec,
// fields, meta) are the run-history arithmetic both writers share.
//
// No DOM.

import * as store from "./store.js";
import { toMillis } from "./when.js";

export const PREFIX = "catalogue.discovered.";
export const INDEX_KEY = "catalogue.discovered.envs";
export const INDEX_VERSION = 2;
export const MAX_BYTES = 6_000_000;
export const ENV_MAX_BYTES = 3_000_000;
export const RUNS_AFTER_PRUNE = 3;

const INDEX_NAME = INDEX_KEY.slice(PREFIX.length);

function envKeyOf(storeKey) {
  return storeKey.startsWith(PREFIX) && storeKey !== INDEX_KEY ? storeKey.slice(PREFIX.length) : null;
}

export function bytes(doc) {
  const s = JSON.stringify(doc === undefined ? null : doc);
  return typeof TextEncoder !== "undefined" ? new TextEncoder().encode(s).length : s.length;
}

function isSplunk(envKey) {
  return /^https?:\/\//.test(String(envKey));
}

// A Splunk environment is keyed by its origin; anything else is a workspace.
export function platformOf(envKey) {
  return isSplunk(envKey) ? "splunk" : "sentinel";
}

// first_seen and last_seen as epoch seconds: a number as is (milliseconds
// at or above 1e12), a numeric string, or an ISO instant; null otherwise.
export function epochOf(v) {
  if (typeof v === "number") return !Number.isFinite(v) ? null : Math.abs(v) >= 1e12 ? Math.floor(v / 1000) : v;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return epochOf(Number(v));
  const ms = toMillis(v);
  return ms === undefined ? null : Math.floor(ms / 1000);
}

// Columns the platform puts on every event or row; a profile skips them
// and the record's fields never carry them.
export const SYSTEM_FIELDS = Object.freeze({
  splunk: Object.freeze(["reach_total", "_raw", "_time", "_indextime", "_cd", "_bkt", "_serial", "_si", "_subsecond", "_sourcetype", "_eventtype_color", "punct", "linecount", "splunk_server", "splunk_server_group", "timestartpos", "timeendpos", "date_hour", "date_mday", "date_minute", "date_month", "date_second", "date_wday", "date_year", "date_zone", "eventtype", "tag", "tag::eventtype"]),
  sentinel: Object.freeze(["TenantId", "Type", "_ResourceId", "SourceSystem", "_ItemId", "_IsBillable", "_BilledSize", "_TimeReceived", "_SubscriptionId", "_ResourceGroup", "MG", "ManagementGroupName", "Title", "UniqueId", "id", "BilledSize", "IsBillable", "InvalidTimeGenerated"]),
});

// The set for one platform, or both when none is named.
export function systemFields(platform) {
  const lists = platform ? [SYSTEM_FIELDS[platform] || []] : Object.values(SYSTEM_FIELDS);
  return new Set(lists.flat());
}

function now() {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Run history and the profile delta: the same arithmetic for both writers
// (discovery.js runs the searches on Splunk, recipe.js reads pasted results
// on Sentinel), so health reads one record shape on both platforms.

export const RUNS_KEPT = 12;

// Newest first, capped.
export function pushRun(rec, run) {
  rec.runs = [run, ...(rec.runs || [])].slice(0, RUNS_KEPT);
}

// Two profiles of the same sourcetype: what moved. `fill` lists fields
// whose fill rate changed by FILL_SHIFT or more, largest move first.
export const FILL_SHIFT = 0.1;
export function profileDelta(before, after) {
  const was = new Set(Object.keys(before));
  const now = new Set(Object.keys(after));
  const added = [...now].filter((f) => !was.has(f)).sort();
  const gone = [...was].filter((f) => !now.has(f)).sort();
  const fill = [];
  for (const f of now) {
    if (!was.has(f)) continue;
    const a = before[f].fill;
    const b = after[f].fill;
    if (a === null || a === undefined || b === null || b === undefined) continue;
    if (Math.abs(b - a) >= FILL_SHIFT) fill.push({ field: f, from: a, to: b });
  }
  fill.sort((x, y) => Math.abs(y.to - y.from) - Math.abs(x.to - x.from) || x.field.localeCompare(y.field));
  return { added, gone, fill };
}

// A profile run's record shape: `before` is the previous profiles by field,
// `fields` the new ones. Writes the fields, drops the numbers of a field this
// sample did not see (a profile is a measurement, and this run did not make
// one), records the delta against the run before and the run itself.
export function applyProfile(rec, fields, { at, window, index = null, sample, previous_at = null }) {
  const before = {};
  for (const [f, v] of Object.entries(rec.fields || {})) if (v && v.profile) before[f] = v.profile;
  const delta = profileDelta(before, Object.fromEntries(Object.entries(fields).map(([f, v]) => [f, v.profile])));
  rec.fields = rec.fields || {};
  for (const [f, v] of Object.entries(fields)) rec.fields[f] = { ...(rec.fields[f] || {}), ...v };
  for (const f of delta.gone) {
    if (!rec.fields[f]) continue;
    delete rec.fields[f].profile;
    if (!Object.keys(rec.fields[f]).length) delete rec.fields[f];
  }
  const previous = (rec.runs || []).find((r) => r.kind === "profile");
  rec.profile_delta = Object.keys(before).length ? { at, previous_at: previous ? previous.at : previous_at || rec.profiled_at || null, ...delta } : null;
  rec.profiled_at = at;
  rec.sample = sample;
  pushRun(rec, { kind: "profile", at, window, index, sample, fields: Object.keys(fields).length });
  return delta;
}

// ---------------------------------------------------------------------------
// The write chain. Every write, the migration and every read queue behind
// the last write; the chain holds the tail, never a rejection.

let writes = Promise.resolve();
function chain(fn) {
  const next = writes.then(fn);
  writes = next.catch(() => {});
  return next;
}

// The first read or write in a context runs load() once; catalogue.load()
// calls it explicitly first, and both share the one run.
let loaded = null;
function ready() {
  if (!loaded) load();
  return loaded;
}

async function readIndex() {
  const idx = await store.get(INDEX_KEY);
  if (idx && typeof idx === "object" && idx.envs && typeof idx.envs === "object") return { version: INDEX_VERSION, envs: { ...idx.envs } };
  return { version: INDEX_VERSION, envs: {} };
}

function indexEntry(env) {
  return { discovered_at: (env && env.discovered_at) || null, bytes: bytes(env) };
}

// ---------------------------------------------------------------------------
// Load: an environment key the index does not list is picked up; an index
// entry with no key is dropped.

export function load() {
  const run = chain(async () => {
    const index = await readIndex();
    let dirty = false;
    const stored = (await store.keys(PREFIX)).map((k) => k.slice(PREFIX.length)).filter((k) => k !== INDEX_NAME);
    for (const envKey of stored) {
      if (index.envs[envKey]) continue;
      index.envs[envKey] = indexEntry(await store.get(PREFIX + envKey));
      dirty = true;
    }
    for (const envKey of Object.keys(index.envs)) {
      if (stored.includes(envKey) || (await store.get(PREFIX + envKey)) !== undefined) continue;
      delete index.envs[envKey];
      dirty = true;
    }
    if (dirty) await store.set(INDEX_KEY, index);
    return index;
  });
  loaded = run.catch(() => null);
  return run;
}

// ---------------------------------------------------------------------------
// Reads

export async function readAll() {
  await ready();
  return chain(async () => {
    const index = await readIndex();
    const names = Object.keys(index.envs);
    const got = await store.getMany(names.map((k) => PREFIX + k));
    const out = {};
    for (const k of names) if (got[PREFIX + k] !== undefined) out[k] = got[PREFIX + k];
    return out;
  });
}

export async function read(envKey) {
  await ready();
  return chain(async () => {
    const env = await store.get(PREFIX + envKey);
    return env === undefined ? null : env;
  });
}

// ---------------------------------------------------------------------------
// Pruning

function splunkHint(kind) {
  return { corpus: '"Baseline: what my fleet runs" on the Falcon sourcetype page measures it again', decodes: '"re-read structure" on the sourcetype reads them again', top: '"re-profile" measures them again', env: '"Inventory sourcetypes" there starts it again' }[kind];
}
function sentinelHint(kind) {
  return { corpus: "importing the fleet baseline step's result again measures it", decodes: "importing the decode step's result again reads them back", top: "importing the profile step's result again measures them", env: "importing its inventory step again starts it over" }[kind];
}
function hint(envKey, kind) {
  return (isSplunk(envKey) ? splunkHint : sentinelHint)(kind);
}

function list(items, max = 6) {
  if (items.length <= max) return items.join(", ");
  return `${items.slice(0, max).join(", ")} and ${items.length - max} more`;
}

function mb(n) {
  return `${Math.round(n / 100000) / 10} MB`;
}

// Drops inside one environment until it fits `limit`. Sizes are estimated
// by subtracting each dropped part from the starting size; a part's commas
// and key go with it, so the estimate errs on the large side.
function pruneEnv(envKey, env, limit) {
  let size = bytes(env);
  const dropped = { corpus: false, decodes: [], top: [], runs: false };
  if (size <= limit) return { dropped, size };
  const sts = env.sourcetypes && typeof env.sourcetypes === "object" ? env.sourcetypes : {};

  if (env.org_corpus) {
    size -= bytes(env.org_corpus);
    delete env.org_corpus;
    dropped.corpus = true;
  }
  if (size <= limit) return { dropped, size };

  const tables = [];
  for (const [st, rec] of Object.entries(sts)) {
    for (const [field, t] of Object.entries((rec && rec.decodes) || {})) tables.push({ at: (t && t.read_at) || "", label: `${(t && t.lookup) || field} on ${st}`, drop: () => delete rec.decodes[field], table: t });
  }
  for (const [alias, t] of Object.entries(env.decodes || {})) tables.push({ at: (t && t.read_at) || "", label: alias, drop: () => delete env.decodes[alias], table: t });
  tables.sort((a, b) => a.at.localeCompare(b.at));
  for (const t of tables) {
    if (size <= limit) break;
    size -= bytes(t.table);
    t.drop();
    dropped.decodes.push(t.label);
  }
  if (size <= limit) return { dropped, size };

  const byAge = Object.entries(sts).sort(([, a], [, b]) => String((a && a.profiled_at) || "").localeCompare(String((b && b.profiled_at) || "")));
  for (const [st, rec] of byAge) {
    if (size <= limit) break;
    let took = 0;
    for (const f of Object.values((rec && rec.fields) || {})) {
      if (!f || !f.profile || !Array.isArray(f.profile.top) || !f.profile.top.length) continue;
      took += bytes(f.profile.top);
      f.profile.top = [];
    }
    if (took) {
      size -= took;
      dropped.top.push(st);
    }
  }
  if (size <= limit) return { dropped, size };

  for (const rec of Object.values(sts)) {
    if (!rec || !Array.isArray(rec.runs) || rec.runs.length <= RUNS_AFTER_PRUNE) continue;
    size -= bytes(rec.runs.slice(RUNS_AFTER_PRUNE));
    rec.runs = rec.runs.slice(0, RUNS_AFTER_PRUNE);
    dropped.runs = true;
  }
  return { dropped, size: bytes(env) };
}

function envNotice(envKey, dropped, limit) {
  const parts = [];
  if (dropped.corpus) parts.push(`dropped the organisation corpus (${hint(envKey, "corpus")})`);
  if (dropped.decodes.length) parts.push(`dropped decode table${dropped.decodes.length === 1 ? "" : "s"} ${list(dropped.decodes)} (${hint(envKey, "decodes")})`);
  if (dropped.top.length) parts.push(`dropped the top values of ${list(dropped.top)} (${hint(envKey, "top")})`);
  if (dropped.runs) parts.push(`trimmed run history to the last ${RUNS_AFTER_PRUNE}`);
  if (!parts.length) return "";
  return `${envKey} was over its ${mb(limit)} bound: ${parts.join(", ")}.`;
}

function layerNotice(forgotten, limit) {
  if (!forgotten.length) return "";
  const names = forgotten.map((f) => `${f.envKey}${f.discovered_at ? ` (last discovered ${f.discovered_at.slice(0, 10)})` : ""}`);
  const hints = Array.from(new Set(forgotten.map((f) => hint(f.envKey, "env"))));
  return `The discovered layer was over its ${mb(limit)} bound: forgot ${list(names)}; ${hints.join("; ")}.`;
}

// ---------------------------------------------------------------------------
// Writes

export async function update(envKey, fn, { maxBytes = MAX_BYTES, envMaxBytes = ENV_MAX_BYTES } = {}) {
  if (!envKey) throw new Error("update needs an environment key");
  await ready();
  return chain(async () => {
    const env = (await store.get(PREFIX + envKey)) || { sourcetypes: {} };
    if (!env.sourcetypes || typeof env.sourcetypes !== "object") env.sourcetypes = {};
    fn(env);
    env.discovered_at = now();
    const { dropped, size } = pruneEnv(envKey, env, envMaxBytes);
    const notices = [envNotice(envKey, dropped, envMaxBytes)];
    await store.set(PREFIX + envKey, env);
    const index = await readIndex();
    index.envs[envKey] = { discovered_at: env.discovered_at, bytes: size };
    const total = () => Object.values(index.envs).reduce((n, e) => n + (Number(e && e.bytes) || 0), 0);
    const forgotten = [];
    while (total() > maxBytes) {
      const others = Object.entries(index.envs).filter(([k]) => k !== envKey).sort(([, a], [, b]) => String(a.discovered_at || "").localeCompare(String(b.discovered_at || "")));
      if (!others.length) break;
      const [k, entry] = others[0];
      await store.remove(PREFIX + k);
      delete index.envs[k];
      forgotten.push({ envKey: k, discovered_at: entry.discovered_at });
    }
    notices.push(layerNotice(forgotten, maxBytes));
    await store.set(INDEX_KEY, index);
    return { env, notice: notices.filter(Boolean).join(" ") };
  });
}

export async function forget(envKey) {
  await ready();
  return chain(async () => {
    await store.remove(PREFIX + envKey);
    const index = await readIndex();
    if (index.envs[envKey]) {
      delete index.envs[envKey];
      await store.set(INDEX_KEY, index);
    }
  });
}

// ---------------------------------------------------------------------------
// Change notification: one call per environment written or removed, from
// this context or another; the index write is not reported.

export function subscribe(fn) {
  return store.subscribe((key, value) => {
    const envKey = envKeyOf(key);
    if (envKey !== null) fn(envKey, value);
  });
}

export default { load, readAll, read, update, forget, subscribe, bytes, platformOf, epochOf, systemFields, pushRun, profileDelta, applyProfile, SYSTEM_FIELDS, PREFIX, INDEX_KEY, INDEX_VERSION, MAX_BYTES, ENV_MAX_BYTES, RUNS_AFTER_PRUNE, RUNS_KEPT, FILL_SHIFT };
