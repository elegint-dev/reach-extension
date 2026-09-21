// Discovery: what the user's own Splunk actually carries, written into the
// catalogue's discovered layer. Three fixed reporting searches (there is no
// free-form SPL surface here), each run only from a click. One click runs
// one search, or (Full discovery, discovery-sweep.js) a bounded, listed,
// cancellable batch of these same searches; nothing runs without a click
// and nothing runs in the background:
//
//   inventory   which sourcetypes live in which indexes, how many events,
//               first and last seen                          (| tstats)
//   profile     per-field count, distinct count, fill rate, top values,
//               min/max/mean, on a sample of one sourcetype   (| fieldsummary)
//   recordTypes the values of a sourcetype's record-type field (event_simpleName,
//               eventName…) with counts                       (| stats count by)
//   orgCorpus   what the fleet runs: per (hash, path, signing id) on the
//               Falcon process events, how many hosts and first/last seen
//               over the chosen window                        (| stats dc(aid) by)
//
// A fifth, hunt(), runs a pack workflow's search once as the page rendered
// it (pivot.js from the pack's template, the window its only input) and
// hands the rows back to the page; nothing is written to the layer.
//
// Every search is relayed to an open Splunk tab and runs there with the
// user's session (background.js → discovery-agent.js → live-lookup.js).
// Results land in the discovered layer (layer.js: one store key per
// origin), keyed by sourcetype; catalogue.js reads them as facts, never as
// meanings. Every writer here returns the environment it wrote and the
// layer's `notice` (what the byte budget dropped, or "").
//
//   available()                       → true inside the extension
//   environments()                    → [{ origin, tabs, title }]
//   jobStats(origin, sid)             → the job entry (counts only) of a search the user ran
//   inventory(origin, { index, earliest })
//   profile(origin, sourcetype, { index, sample, earliest })
//   recordTypes(origin, sourcetype, field, { index, sample, earliest })
//   orgCorpus(origin, { index, sourcetype, earliest })  → env.org_corpus (known.js projects it)
//   hunt(origin, spl, { timeoutMs })  → { rows, messages }   one pack hunt, rows to the caller, nothing stored
//   provenance(origin, sourcetype, { macros })  → how each field on the
//                                       sourcetype is produced: alias / calculated /
//                                       lookup / extracted, from props + transforms
//                                       (REST, GET); `macros`, when given, is a
//                                       pack's macro allowlist, checked on this
//                                       instance the same way (configs/conf-macros)
//                                       and stored at env.macros; also reads the
//                                       sourcetype's own configs/conf-props stanza
//                                       (INDEXED_EXTRACTIONS, KV_MODE), stored at
//                                       rec.props for efficiency.js's fallback class
//   decodes(origin, sourcetype)       → lookup tables with one input and one
//                                       output field, read with | inputlookup,
//                                       stored as decode tables
//   markSweep(origin, { at, total, done })  → stamps env.sweep after a full sweep
//   health(rec, env)                  → { lastSeenAge, missing, delta, profileAge } for one record
//
// Runs are kept, not just the latest: each sourcetype carries a short
// `runs` list (inventory / profile, newest first) and the last profile's
// delta against the one before it. Inventory writes this run's last_seen
// rather than the max ever seen: a feed that stopped sending has to be
// able to look stopped; and a sourcetype the latest inventory did not
// return, within an index scope that covers it, is reported missing.
//
// No DOM.

import * as layer from "./layer.js";
import { projectOrgCorpus, ORG_CORPUS_MAX_ROWS, ORG_CORPUS_SOURCETYPE } from "./known.js";

// Development: when served as a plain page with ?ext=<extension id> once
// (remembered in localStorage) and the extension's manifest carries an
// externally_connectable entry for this origin, talk to that extension.
// Shipped manifests have no such entry, so this is inert for users.
function devExtId() {
  try {
    const m = /[?&]ext=([a-p]{32})/.exec(location.hash || "");
    if (m) localStorage.setItem("reach.devExt", m[1]);
    return localStorage.getItem("reach.devExt") || null;
  } catch {
    return null;
  }
}

export function available() {
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) return false;
  return Boolean(chrome.runtime.id || devExtId());
}

function send(msg) {
  return new Promise((resolve, reject) => {
    try {
      const cb = (res) => {
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        if (!res) return reject(new Error("No answer from the extension."));
        if (!res.ok) {
          // The HTTP status the agent saw (401: session gone) rides along,
          // so a batch can tell a dead relay from one bad search.
          const e = new Error(res.error || "Discovery failed.");
          if (res.status) e.status = res.status;
          return reject(e);
        }
        resolve(res);
      };
      if (chrome.runtime.id) chrome.runtime.sendMessage(msg, cb);
      else chrome.runtime.sendMessage(devExtId(), msg, cb);
    } catch (err) {
      reject(err);
    }
  });
}

export async function environments() {
  if (!available()) return [];
  const res = await send({ type: "reach:discover:tabs" });
  return res.origins || [];
}

// The counts of a job the user already ran (the sid rides with a row
// click): one GET on the job through the same relay, on a click, never
// a dispatch. The agent answers with the stat keys alone.
const SID_RE = /^(?=[._-]*[A-Za-z0-9])[A-Za-z0-9._-]{1,200}$/;
export async function jobStats(origin, sid) {
  const s = String(sid || "");
  if (!SID_RE.test(s)) throw new Error("That is not a Splunk job id.");
  const res = await send({ type: "reach:discover:rest", origin, path: `servicesNS/-/-/search/v2/jobs/${s}` });
  const entry = (res.entries || [])[0];
  if (!entry) throw new Error(`Job ${s} is gone: Splunk keeps a job for a while after it runs, then drops it.`);
  return entry;
}

// Quoted SPL string literal: same escaping rule as spl.js (backslashes
// first, then quotes) so an index or sourcetype name can never break out.
function q(v) {
  return `"${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

const SAFE_TERM = /^[A-Za-z0-9_:\-.*]+$/;
function term(v, what) {
  const s = String(v == null ? "" : v).trim();
  if (!s) throw new Error(`${what} is required`);
  return SAFE_TERM.test(s) ? s : q(s);
}

// timeoutMs, when given, bounds one job's poll on the Splunk page (the
// agent's default is ten minutes); a batch passes a shorter one so one
// stuck job cannot hold the rest.
async function run(origin, spl, { earliest = "0", latest = "now", timeoutMs } = {}) {
  const msg = { type: "reach:discover:run", origin, spl, earliest, latest, app: "search" };
  if (timeoutMs) msg.timeoutMs = timeoutMs;
  const res = await send(msg);
  return { rows: res.rows || [], messages: res.messages || [] };
}

async function rest(origin, path, { search, count = 0 } = {}) {
  const res = await send({ type: "reach:discover:rest", origin, path, search, count });
  return res.entries || [];
}

// --------------------------------------------------------------------------
// Layer write: layer.update() serialises every writer on both platforms.

function update(origin, fn) {
  return layer.update(origin, fn);
}

// After a full sweep (discovery-sweep.js): when it ran and how far it got,
// so a reader can say its picture was computed over the whole environment.
export async function markSweep(origin, { at, total, done }) {
  return update(origin, (e) => {
    e.sweep = { at, total, done };
  });
}

// --------------------------------------------------------------------------
// The searches

export const RUNS_KEPT = layer.RUNS_KEPT;
const pushRun = layer.pushRun;

// Did a run over `index` look everywhere this sourcetype lives? Only then
// can its absence from the rows mean anything. A run over one of its two
// indexes says nothing about the other.
function scopeCovers(index, rec) {
  const list = (Array.isArray(index) ? index : [index]).map(String);
  if (list.includes("*")) return true;
  const mine = rec.indexes || [];
  return mine.length > 0 && mine.every((i) => list.includes(i));
}

export function inventorySpl({ index = "*" } = {}) {
  return `| tstats count, min(_time) as first_seen, max(_time) as last_seen where index=${term(index, "index")} by index, sourcetype`;
}

export async function inventory(origin, { index = "*", earliest = "-7d", timeoutMs } = {}) {
  const { rows, messages } = await run(origin, inventorySpl({ index }), { earliest, timeoutMs });
  const at = new Date().toISOString();
  // One sourcetype spans several index rows; fold them first.
  const bySt = new Map();
  for (const r of rows) {
    if (!r.sourcetype) continue;
    const cur = bySt.get(r.sourcetype) || { indexes: [], count: 0, first_seen: Infinity, last_seen: 0 };
    if (r.index && !cur.indexes.includes(r.index)) cur.indexes.push(r.index);
    cur.count += Number(r.count) || 0;
    cur.first_seen = Math.min(cur.first_seen, layer.epochOf(r.first_seen) || Infinity);
    cur.last_seen = Math.max(cur.last_seen, layer.epochOf(r.last_seen) || 0);
    bySt.set(r.sourcetype, cur);
  }
  const { env, notice } = await update(origin, (e) => {
    for (const [st, got] of bySt) {
      const rec = (e.sourcetypes[st] = e.sourcetypes[st] || { indexes: [], count: 0, fields: {} });
      for (const i of got.indexes) if (!rec.indexes.includes(i)) rec.indexes.push(i);
      rec.count = got.count;
      if (Number.isFinite(got.first_seen) && (!rec.first_seen || got.first_seen < rec.first_seen)) rec.first_seen = got.first_seen; // earliest ever known: cumulative
      if (got.last_seen) rec.last_seen = got.last_seen; // this run's: recency has to be able to go backwards
      rec.inventoried_at = at;
      rec.inventory_window = earliest;
      delete rec.missing_since;
      pushRun(rec, { kind: "inventory", at, window: earliest, index, count: rec.count, last_seen: rec.last_seen });
    }
    // Known here, in an index this run covered, and not returned: the feed
    // produced nothing in the window. Kept, and marked from the first miss.
    // A record that was only ever profiled or imported counts too: a run
    // over every index it could live in is the authority on its absence.
    for (const [st, rec] of Object.entries(e.sourcetypes)) {
      if (bySt.has(st) || !scopeCovers(index, rec)) continue;
      rec.missing_since = rec.missing_since || at;
      pushRun(rec, { kind: "inventory", at, window: earliest, index, count: 0, last_seen: rec.last_seen, missing: true });
    }
    e.inventory = { at, window: earliest, index };
  });
  return { rows, messages, env, notice };
}

// reach_total=1 on every sampled event gives fieldsummary a row whose count
// is the sample size (the denominator for fill rate) without a second search.
// One index, or every index the sourcetype was inventoried in. A sourcetype
// routed to several indexes is profiled across all of them.
function indexClause(index) {
  const list = (Array.isArray(index) ? index : [index]).map((i) => term(i, "index"));
  return list.length === 1 ? `index=${list[0]}` : `(${list.map((i) => `index=${i}`).join(" OR ")})`;
}

export function profileSpl({ sourcetype, index = "*", sample = 5000 } = {}) {
  const n = Math.max(1, Math.min(100000, Number(sample) || 5000));
  return `search ${indexClause(index)} sourcetype=${term(sourcetype, "sourcetype")} | head ${n} | eval reach_total=1 | fieldsummary maxvals=10`;
}

function parseValues(s) {
  try {
    const arr = JSON.parse(s);
    return Array.isArray(arr) ? arr.map((x) => ({ value: String(x.value), count: Number(x.count) || 0 })) : [];
  } catch {
    return [];
  }
}

export const SKIP_FIELDS = layer.systemFields("splunk");

export async function profile(origin, sourcetype, { index = "*", sample = 5000, earliest = "-24h", timeoutMs } = {}) {
  const { rows, messages } = await run(origin, profileSpl({ sourcetype, index, sample }), { earliest, timeoutMs });
  const totalRow = rows.find((r) => r.field === "reach_total");
  const total = totalRow ? Number(totalRow.count) || 0 : 0;
  const fields = {};
  for (const r of rows) {
    const f = r.field;
    if (!f || SKIP_FIELDS.has(f) || f.startsWith("tag::")) continue; // tag::<field> are Splunk's tag annotations, not fields
    const count = Number(r.count) || 0;
    const numericCount = Number(r.numeric_count) || 0;
    fields[f] = {
      profile: {
        count,
        distinct: Number(r.distinct_count) || 0,
        distinct_exact: r.is_exact === "1" || r.is_exact === 1,
        fill: total ? count / total : null,
        numeric: count > 0 && numericCount === count,
        min: r.min !== undefined && r.min !== "" ? r.min : null,
        max: r.max !== undefined && r.max !== "" ? r.max : null,
        mean: r.mean !== undefined && r.mean !== "" ? Number(r.mean) : null,
        top: parseValues(r.values),
        sample: total,
        measured_at: new Date().toISOString(),
        window: earliest,
      },
    };
  }
  const at = new Date().toISOString();
  const { env, notice } = await update(origin, (e) => {
    const rec = (e.sourcetypes[sourcetype] = e.sourcetypes[sourcetype] || { indexes: [], count: 0, fields: {} });
    for (const i of Array.isArray(index) ? index : [index]) if (i !== "*" && !rec.indexes.includes(i)) rec.indexes.push(i);
    // What changed since the last profile: fields this sample has that the
    // last did not, fields it no longer has, and fill rates that moved.
    layer.applyProfile(rec, fields, { at, window: earliest, index, sample: total });
  });
  return { rows, messages, total, fields: Object.keys(fields).length, env, notice };
}

// Two profiles of the same sourcetype → what moved (layer.js holds the
// arithmetic, shared with the Sentinel recipe).
export const FILL_SHIFT = layer.FILL_SHIFT;
export const profileDelta = layer.profileDelta;

// How healthy a discovered sourcetype looks, from its record alone:
//   lastSeenAge   seconds since the newest event the last inventory saw, or null
//   missing       true when the latest inventory covering its index did not return it
//   missingSince  ISO time of the first such miss
//   profileAge    seconds since the last profile, or null
//   delta         the last profile's changes against the one before, or null
export function health(rec, now = Date.now()) {
  if (!rec) return null;
  const secs = (iso) => (iso ? Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000)) : null);
  const lastSeen = layer.epochOf(rec.last_seen);
  return {
    lastSeenAge: lastSeen ? Math.max(0, Math.round(now / 1000 - lastSeen)) : null,
    missing: Boolean(rec.missing_since),
    missingSince: rec.missing_since || null,
    profileAge: secs(rec.profiled_at),
    delta: rec.profile_delta && (rec.profile_delta.added.length || rec.profile_delta.gone.length || rec.profile_delta.fill.length) ? rec.profile_delta : null,
  };
}

// "3d", "6h", "12m", "just now": coarse, for a badge.
export function ageLabel(seconds) {
  if (seconds === null || seconds === undefined) return "";
  if (seconds < 90) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400 * 2) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

// Past this, a profile is old enough to say so beside its numbers.
export const STALE_PROFILE_SECONDS = 7 * 86400;

export function recordTypesSpl({ sourcetype, field, index = "*", sample = 20000 } = {}) {
  const n = Math.max(1, Math.min(200000, Number(sample) || 20000));
  return `search ${indexClause(index)} sourcetype=${term(sourcetype, "sourcetype")} | head ${n} | stats count by ${term(field, "field")} | sort - count`;
}

export async function recordTypes(origin, sourcetype, field, { index = "*", sample = 20000, earliest = "-24h", timeoutMs } = {}) {
  const { rows, messages } = await run(origin, recordTypesSpl({ sourcetype, field, index, sample }), { earliest, timeoutMs });
  const values = rows.map((r) => ({ value: String(r[field]), count: Number(r.count) || 0 })).filter((x) => x.value && x.value !== "undefined");
  const { env, notice } = await update(origin, (e) => {
    const rec = (e.sourcetypes[sourcetype] = e.sourcetypes[sourcetype] || { indexes: [], count: 0, fields: {} });
    rec.discriminator = field;
    rec.record_types = values;
    rec.record_types_at = new Date().toISOString();
  });
  return { values, messages, env, notice };
}

// --------------------------------------------------------------------------
// The organisation corpus: one reporting search over the Falcon process
// events of every mac and windows host, grouped by hash, image path and
// signing id (absent on Windows, so it is filled before the stats, which
// would otherwise drop those rows). Costs a scan of the process events in
// the window; the head after the stats bounds what comes back, most
// widespread rows first, and known.js prunes the rest to its byte budget.

export { ORG_CORPUS_SOURCETYPE };

export function orgCorpusSpl({ sourcetype = ORG_CORPUS_SOURCETYPE, index = "*", top = ORG_CORPUS_MAX_ROWS } = {}) {
  const n = Math.max(1, Math.min(ORG_CORPUS_MAX_ROWS, Number(top) || ORG_CORPUS_MAX_ROWS));
  return [
    `search ${indexClause(index)} sourcetype=${term(sourcetype, "sourcetype")} event_simpleName=ProcessRollup2 (event_platform=Mac OR event_platform=Win) SHA256HashData=*`,
    '| eval SigningId=coalesce(SigningId, "-")',
    "| stats dc(aid) as hosts, count as events, min(_time) as first_seen, max(_time) as last_seen by SHA256HashData, ImageFileName, SigningId, event_platform",
    "| rename SHA256HashData as sha256, ImageFileName as path, SigningId as signing_id, event_platform as platform",
    `| sort ${n} - hosts, - last_seen`,
  ].join(" ");
}

export async function orgCorpus(origin, { index = "*", sourcetype = ORG_CORPUS_SOURCETYPE, earliest = "-30d", timeoutMs } = {}) {
  const { rows, messages } = await run(origin, orgCorpusSpl({ sourcetype, index }), { earliest, timeoutMs });
  const at = new Date().toISOString();
  const doc = projectOrgCorpus(rows, { at, window: earliest, index: Array.isArray(index) ? index.join(",") : String(index), sourcetype, source: "splunk" });
  const { env, notice } = await update(origin, (e) => {
    e.org_corpus = doc;
  });
  return { rows, messages, doc, env, notice };
}

// --------------------------------------------------------------------------
// A pack hunt (views/workflow.js): the rendered search runs as it stands,
// its window inside the text, so the job's own bounds are open. Rows come
// back as Splunk returned them; the page draws them and keeps nothing.

export const HUNT_MAX_ROWS = 2000;

export async function hunt(origin, spl, { timeoutMs } = {}) {
  const text = String(spl || "").trim();
  if (!text) throw new Error("Nothing to run: the search is empty.");
  const { rows, messages } = await run(origin, text, { earliest: "0", latest: "now", timeoutMs });
  return { rows: rows.slice(0, HUNT_MAX_ROWS), messages, truncated: rows.length > HUNT_MAX_ROWS };
}

// --------------------------------------------------------------------------
// Provenance: how a field comes to exist on a sourcetype, from what Splunk
// itself declares. Four props endpoints, filtered by stanza, plus the
// transforms a REPORT- extraction points at. Everything is a GET.

const PROPS = "servicesNS/-/-/data/props/";
const TRANSFORMS = "servicesNS/-/-/data/transforms/";
const MACROS = "servicesNS/-/-/configs/conf-macros";
const CONF_PROPS = "servicesNS/-/-/configs/conf-props";

// A parameterised macro's stanza carries its arg count, e.g.
// "cs_trace_process(3)"; the name a query calls it by has none.
function macroBaseName(stanza) {
  const m = /^([^(]+)\(/.exec(String(stanza || ""));
  return m ? m[1] : String(stanza || "");
}

// Field references inside an EVAL: 'quoted.names' always; bare identifiers
// only when they are not a known eval function or keyword.
const EVAL_WORDS = new Set(["if", "case", "coalesce", "null", "true", "false", "and", "or", "not", "in", "like", "match", "isnull", "isnotnull", "lower", "upper", "trim", "ltrim", "rtrim", "replace", "split", "mvindex", "mvjoin", "mvcount", "mvfilter", "mvappend", "mvdedup", "mvzip", "mvfind", "substr", "len", "tostring", "tonumber", "round", "floor", "ceil", "abs", "strftime", "strptime", "now", "relative_time", "cidrmatch", "searchmatch", "typeof", "validate", "spath", "json_extract", "urldecode", "md5", "sha1", "sha256", "min", "max", "sum", "avg", "exact", "eval", "printf", "nullif", "json_valid", "json_keys", "json_array", "json_object", "json_extract_exact", "mvmap", "mvrange", "mvsort", "mvindex", "commands", "ipmask", "cidrmatch", "random", "pi", "pow", "sqrt", "exp", "ln", "log", "sigfig", "tojson", "AND", "OR", "NOT", "IN", "LIKE"]);
export function evalRefs(statement) {
  const out = new Set();
  const text = String(statement || "");
  for (const m of text.matchAll(/'([^']+)'/g)) out.add(m[1]);
  const stripped = text.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'[^']*'/g, "''");
  for (const m of stripped.matchAll(/(?<![\w.$'])([A-Za-z_][A-Za-z0-9_.]*)(?![A-Za-z0-9_.]|\s*\()/g)) {
    const w = m[1];
    if (EVAL_WORDS.has(w) || /^\d/.test(w)) continue;
    out.add(w);
  }
  return Array.from(out);
}

function regexGroups(re) {
  const out = [];
  for (const m of String(re || "").matchAll(/\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/g)) out.push(m[1]);
  return out;
}

// macroNames: a pack's macro allowlist to check for existence on this
// instance alongside the field structure (a macro is not tied to any one
// sourcetype; the caller passes names only when this sourcetype belongs to
// a pack that declares some). One conf-macros read, filtered to those
// names and their parameterised stanzas ("name(3)"); stored as env.macros.
export async function provenance(origin, sourcetype, { macros: macroNames = [] } = {}) {
  const search = `stanza=${sourcetype}`;
  const names = Array.from(new Set((macroNames || []).filter(Boolean)));
  const [aliases, calcs, lookups, extractions, macroEntries, propsEntries] = await Promise.all([
    rest(origin, PROPS + "fieldaliases", { search }),
    rest(origin, PROPS + "calcfields", { search }),
    rest(origin, PROPS + "lookups", { search }),
    rest(origin, PROPS + "extractions", { search }),
    names.length ? rest(origin, MACROS, { search: names.map((n) => `name="${n}*"`).join(" OR ") }) : Promise.resolve(null),
    rest(origin, CONF_PROPS, { search }),
  ]);
  // The sourcetype's own stanza only (the exact-match search above), for
  // efficiency.js's fallback when discovery finds no provenance for a
  // field: INDEXED_EXTRACTIONS says index-time, KV_MODE says search-time.
  const propsStanza = (propsEntries || []).find((e) => e.name === sourcetype);
  const propsContent = propsStanza ? propsStanza.content || {} : {};
  const props = propsStanza
    ? { indexed_extractions: propsContent.INDEXED_EXTRACTIONS || propsContent.indexed_extractions || null, kv_mode: propsContent.KV_MODE || propsContent.kv_mode || null }
    : null;
  const fields = {}; // field → [prov]
  const push = (f, prov) => {
    if (!f) return;
    (fields[f] = fields[f] || []).push(prov);
  };
  for (const e of aliases) {
    const c = e.content || {};
    for (const [k, dst] of Object.entries(c)) {
      const m = /^alias\.\d+\.(.+)$/.exec(k);
      if (m) push(dst, { kind: "alias", from: m[1], statement: c.value, app: e.app, attribute: c.attribute });
    }
  }
  for (const e of calcs) {
    const c = e.content || {};
    push(c["field.name"], { kind: "calculated", statement: c.value, refs: evalRefs(c.value), app: e.app, attribute: c.attribute });
  }
  const lookupDefs = [];
  for (const e of lookups) {
    const c = e.content || {};
    const inputs = [];
    const outputs = [];
    // REST keys name the LOOKUP-side column; the value is the event-side
    // field it maps to, empty when they are the same (no AS in the stanza).
    //   inputs:  { column (lookup side), field (event side) }
    //   outputs: { column (lookup side), field (event side) }
    for (const [k, v] of Object.entries(c)) {
      const im = /^lookup\.field\.input\.(.+)$/.exec(k);
      if (im) inputs.push({ column: im[1], field: v || im[1] });
      const om = /^lookup\.field\.output\.\d+\.(.+)$/.exec(k);
      if (om) outputs.push({ column: om[1], field: v || om[1] });
    }
    const def = { transform: c.transform, inputs, outputs, statement: c.value, app: e.app, attribute: c.attribute, overwrite: Boolean(c.overwrite) };
    lookupDefs.push(def);
    for (const o of outputs) push(o.field, { kind: "lookup", transform: c.transform, inputs: inputs.map((i) => i.field), statement: c.value, app: e.app, attribute: c.attribute });
    for (const i of inputs) push(i.field, { kind: "lookup_key", transform: c.transform, outputs: outputs.map((o) => o.field), statement: c.value, app: e.app, attribute: c.attribute });
  }
  const reportNames = [];
  for (const e of extractions) {
    const c = e.content || {};
    if (c.type === "Uses transform" || /^REPORT-/.test(c.attribute || "")) {
      for (const n of String(c.value || "").split(",").map((x) => x.trim()).filter(Boolean)) reportNames.push({ name: n, app: e.app, attribute: c.attribute });
    } else {
      for (const g of regexGroups(c.value)) push(g, { kind: "extracted", regex: c.value, app: e.app, attribute: c.attribute });
    }
  }
  if (reportNames.length) {
    const defs = await rest(origin, TRANSFORMS + "extractions", { search: reportNames.map((r) => `name=${r.name}`).join(" OR ") });
    for (const d of defs) {
      const c = d.content || {};
      const via = reportNames.find((r) => r.name === d.name) || {};
      const names = new Set(regexGroups(c.REGEX));
      for (const m of String(c.FORMAT || "").matchAll(/([A-Za-z_][A-Za-z0-9_]*)::/g)) names.add(m[1]);
      for (const f of names) push(f, { kind: "extracted", transform: d.name, regex: c.REGEX, format: c.FORMAT || null, app: d.app, attribute: via.attribute });
    }
  }
  // The base name wins over a same-named disabled stanza when both exist.
  let macroRec = null;
  if (names.length) {
    const found = new Map();
    for (const e of macroEntries || []) {
      const base = macroBaseName(e.name);
      if (!names.includes(base)) continue;
      const c = e.content || {};
      const enabled = c.disabled !== "1" && c.disabled !== true;
      if (found.has(base) && found.get(base).enabled && !enabled) continue;
      found.set(base, { definition: c.definition || "", app: e.app || null, enabled });
    }
    macroRec = {};
    for (const n of names) {
      const got = found.get(n);
      macroRec[n] = got ? { defined: true, definition: got.definition, app: got.app } : { defined: false, definition: null, app: null };
    }
  }
  const at = new Date().toISOString();
  const { env, notice } = await update(origin, (e) => {
    const rec = (e.sourcetypes[sourcetype] = e.sourcetypes[sourcetype] || { indexes: [], count: 0, fields: {} });
    for (const [f, prov] of Object.entries(fields)) rec.fields[f] = { ...(rec.fields[f] || {}), provenance: prov };
    rec.lookups = lookupDefs;
    rec.provenance_at = at;
    rec.provenance_counts = { aliases: aliases.length, calculated: calcs.length, lookups: lookups.length, extractions: extractions.length };
    if (props) rec.props = props;
    if (macroRec) {
      e.macros = { ...(e.macros || {}), ...macroRec };
      e.macros_at = at;
    }
  });
  return { fields: Object.keys(fields).length, counts: env.sourcetypes[sourcetype].provenance_counts, macros: macroRec, props, env, notice };
}

// --------------------------------------------------------------------------
// Decode tables: every search-time lookup on the sourcetype with exactly one
// input and one output field is a code → label table. Read it once, store
// it. Capped so a 200k-row asset list never lands in storage.

export const DECODE_MAX_ROWS = 2000;

// Runs `concurrency` lookups at once (each is one small search job on the
// search head), and reports progress so a TA with 200 lookups is not a
// silent three minutes. Tables already read are kept unless `force`.
export async function decodes(origin, sourcetype, { concurrency = 4, force = false, onProgress, timeoutMs } = {}) {
  const known = await layer.read(origin);
  const rec = known && known.sourcetypes[sourcetype];
  if (!rec || !rec.lookups) throw new Error(`Run provenance for ${sourcetype} first. Decode tables are found through its LOOKUP stanzas.`);
  const have = (rec.decodes && !force) ? new Set(Object.values(rec.decodes).map((d) => d.lookup)) : new Set();
  const candidates = rec.lookups.filter((l) => l.inputs.length === 1 && l.outputs.length === 1 && l.transform && !have.has(l.transform));
  const out = {};
  const errors = [];
  let done = 0;
  const readOne = async (l) => {
    const input = l.inputs[0];
    const output = l.outputs[0];
    const spl = `| inputlookup ${term(l.transform, "lookup")} | head ${DECODE_MAX_ROWS + 1} | table ${term(input.column, "field")} ${term(output.column, "field")}`;
    try {
      const { rows } = await run(origin, spl, { timeoutMs });
      if (rows.length && rows.length <= DECODE_MAX_ROWS) {
        const values = {};
        for (const r of rows) {
          const k = r[input.column];
          const v = r[output.column];
          if (k === undefined || k === "" || v === undefined) continue;
          if (!(k in values)) values[String(k)] = String(v);
        }
        if (Object.keys(values).length) out[input.field] = { lookup: l.transform, meaning_field: output.field, values, rows: rows.length, read_at: new Date().toISOString() };
      }
    } catch (err) {
      errors.push(`${l.transform}: ${err.message}`);
    }
    done++;
    if (onProgress) onProgress({ done, total: candidates.length, tables: Object.keys(out).length });
  };
  const queue = candidates.slice();
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, async () => {
    while (queue.length) await readOne(queue.shift());
  }));
  const { env, notice } = await update(origin, (e) => {
    const r = (e.sourcetypes[sourcetype] = e.sourcetypes[sourcetype] || { indexes: [], count: 0, fields: {} });
    r.decodes = { ...(r.decodes || {}), ...out };
    r.decodes_at = new Date().toISOString();
  });
  return { tables: Object.keys(out).length, candidates: candidates.length, skipped: have.size, errors, env, notice };
}

export default { available, environments, jobStats, inventory, profile, recordTypes, orgCorpus, hunt, HUNT_MAX_ROWS, provenance, decodes, markSweep, inventorySpl, profileSpl, recordTypesSpl, orgCorpusSpl, ORG_CORPUS_SOURCETYPE, evalRefs, profileDelta, health, ageLabel, DECODE_MAX_ROWS, RUNS_KEPT, FILL_SHIFT, STALE_PROFILE_SECONDS };
