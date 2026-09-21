// The discovery recipe (docs/SENTINEL.md §5): what Reach asks the user to
// run in the portal, and what it makes of what comes back. Reach never
// runs a query. Each step is a fixed KQL query (built here from kql.js's
// primitives, as discovery.js builds its SPL from spl.js's) wrapped in the
// self-describing one-cell envelope, offered as a deep link that opens the
// Logs blade with it already run;
// the user copies the one result cell back, intake.js parses it, and
// apply() writes the discovered layer (layer.js): the same store and the
// same record shapes discovery.js writes on Splunk, so catalogue.js reads
// both without knowing which platform filled them.
//
// Environments are workspaces, keyed by their ARM resource id (the deep
// link needs it). A workspace is known from the portal (the top-frame
// content script records the one the Logs blade is open on), from a paste
// of its resource id, or from an envelope whose env label matches.
//
//   environments()                       → [{ key, label, name, resourceId, tenantId, seen_at, discovered_at, tables }]
//   addEnvironment(resourceId, label?)   → env record
//   forget(key)                          → drops the layer record and the seen entry
//   environment(key)                     → the layer record, or null
//   knownTables(env, { packTables })     → [names]
//   steps(env, { packTables, packDiscriminators })  → [Step]   (workspace-level: inventory, schema batches, watchlists)
//   tableSteps(env, table, { discriminator }) → [Step]         (per table: profile, record types)
//   orgCorpusSteps(env, { falconTables }) → [Step]             (the fleet baseline: one step per qualifying Falcon table, lives on the sourcetype page, not the generic list)
//   queryFor(step, env)                  → { kql, q, gen, bare }   (async: deep link needs gzip)
//   envelope({ query, step, env, params }) → { kql, q, gen }     the one-cell wrapper; stamp(text) its q
//   inventoryQuery, inventoryScanQuery, schemaQuery, profileQuery, recordTypesQuery,
//   watchlistsQuery, watchlistSchemaQuery, watchlistReadQuery, orgCorpusQuery    the bare queries
//   apply(key, parsed, { step, params }) → { step, written, verdicts, env, notice }
//   proposeDiscriminator(rec)            → column | null
//   proposeEdges(env)                    → [{ src, dst, overlap, type }]
//
// Step: { id, step, label, params, bare, q, status: "pending"|"imported"|"stale", imported_at, rows }
//
// No DOM.

import * as store from "./store.js";
import * as layer from "./layer.js";
import * as kql from "./kql.js";
import { projectOrgCorpus, ORG_CORPUS_MAX_ROWS } from "./known.js";

export const WORKSPACES_KEY = "sentinel.workspaces";

// pack_all() drags the platform's own columns in; they are not the table's
// schema in any sense a catalogue cares about.
export const SYSTEM_COLUMNS = layer.systemFields("sentinel");

// Why a Sentinel profile's distinct_exact is null: dcountif() estimates,
// and the profile query measures no exact count. Stated once here rather
// than on every column, which the environment's byte budget would pay for.
export const DISTINCT_ESTIMATED = "dcountif estimates the distinct count";

// Declared (getschema) vs runtime (gettype) names: verified live, a declared
// int reads back as long.
// gettype() names a dynamic value by its shape (dictionary, array); the
// declared type is dynamic: the same thing for a catalogue.
const TYPE_ALIASES = { int: "long", int64: "long", int32: "long", real: "double", float: "double", bool: "boolean", boolean: "boolean", guid: "string", uuid: "string", date: "datetime", time: "timespan", dictionary: "dynamic", array: "dynamic" };
export function normalType(t) {
  const s = String(t || "").toLowerCase();
  return TYPE_ALIASES[s] || s;
}
const NUMERIC_TYPES = new Set(["long", "double", "decimal"]);
export const TOP_VALUE_MAX = 200;

// ---------------------------------------------------------------------------
// Environments

function now() {
  return new Date().toISOString();
}

export async function seenWorkspaces() {
  return (await store.get(WORKSPACES_KEY)) || {};
}

// Called by the top-frame content script when the Logs blade is open on a
// workspace, and by the app when the user pastes one.
export async function rememberWorkspace(resourceId, { name } = {}) {
  if (!kql.isResourceId(resourceId)) throw new Error("not a Log Analytics workspace resource id");
  const all = await seenWorkspaces();
  const cur = all[resourceId] || {};
  all[resourceId] = { ...cur, name: name || cur.name || kql.workspaceNameOf(resourceId), seen_at: now() };
  await store.set(WORKSPACES_KEY, all);
  return all[resourceId];
}

export async function environments() {
  const [all, seen] = await Promise.all([layer.readAll(), seenWorkspaces()]);
  const out = new Map();
  for (const [key, env] of Object.entries(all)) {
    // A Splunk origin (http://…) in the same layer is not a workspace.
    if (!kql.isResourceId(key) && (/^https?:\/\//.test(key) || !(env && (env.resourceId || env.tenantId || env.label)))) continue;
    out.set(key, {
      key,
      label: env.label || kql.workspaceNameOf(key) || key,
      name: kql.workspaceNameOf(key) || env.label || key,
      resourceId: kql.isResourceId(key) ? key : env.resourceId || null,
      tenantId: env.tenantId || null,
      discovered_at: env.discovered_at || null,
      seen_at: seen[key] ? seen[key].seen_at : null,
      tables: Object.keys(env.sourcetypes || {}).length,
    });
  }
  for (const [rid, rec] of Object.entries(seen)) {
    if (out.has(rid)) continue;
    out.set(rid, { key: rid, label: rec.name || kql.workspaceNameOf(rid), name: rec.name || kql.workspaceNameOf(rid), resourceId: rid, tenantId: null, discovered_at: null, seen_at: rec.seen_at || null, tables: 0 });
  }
  return Array.from(out.values()).sort((a, b) => String(b.seen_at || b.discovered_at || "").localeCompare(String(a.seen_at || a.discovered_at || "")));
}

export async function addEnvironment(resourceId, label) {
  const rec = await rememberWorkspace(resourceId, { name: label });
  return { key: resourceId, label: rec.name, resourceId };
}

export async function environment(key) {
  return layer.read(key);
}

function update(key, fn) {
  return layer.update(key, (env) => {
    env.steps = env.steps || {};
    if (kql.isResourceId(key)) env.resourceId = key;
    fn(env);
  });
}

export async function forget(key) {
  await layer.forget(key);
  const seen = await seenWorkspaces();
  delete seen[key];
  await store.set(WORKSPACES_KEY, seen);
}

function tableRec(env, table) {
  const rec = (env.sourcetypes[table] = env.sourcetypes[table] || { indexes: [], count: 0, fields: {} });
  rec.fields = rec.fields || {};
  return rec;
}

// ---------------------------------------------------------------------------
// Envelope

export const ENVELOPE_VERSION = 1;

// FNV-1a over the query text: the `q` stamp that says which generated query
// a paste claims to be. Not a security hash: a replay/staleness check.
export function stamp(text) {
  let h = 0x811c9dc5;
  const s = String(text || "");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

function packLiteral(obj) {
  const parts = [];
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined || v === null) continue;
    parts.push(kql.quote(k), typeof v === "number" ? String(v) : typeof v === "boolean" ? String(v) : kql.quote(String(v)));
  }
  return parts.length ? `pack(${parts.join(", ")})` : "pack()";
}

// Wraps a query so its whole result folds into one row, one column, one
// JSON string that says what it is. `params` are the step's inputs, baked
// in as literals so intake can read them back; `env` is the workspace label
// the user chose in Reach.
export function envelope({ query, step, env, params = {}, gen = new Date().toISOString() }) {
  const body = String(query || "").trim();
  if (!body) throw new kql.KqlError("empty", "nothing to wrap");
  const s = kql.ident(step, "step");
  const stamped = stamp(body);
  const meta = packLiteral({ v: ENVELOPE_VERSION, step: s, env: env || "", gen, q: stamped });
  const p = packLiteral(params);
  return {
    kql: `${body}\n| summarize rows = make_list(pack_all())\n| project reach = tostring(pack("meta", ${meta}, "params", ${p}, "rows", rows))`,
    q: stamped,
    gen,
  };
}

// ---------------------------------------------------------------------------
// The recipe's queries. Each returns the bare query; the caller wraps it
// with envelope() so the step name and parameters travel with the result.

export const SAMPLE_DEFAULT = 5000;
export const RECORD_TYPES_SAMPLE = 20000;
export const DECODE_MAX_ROWS = 2000;
export const SCHEMA_BATCH = 25;

export function inventoryQuery({ window = "30d" } = {}) {
  const w = kql.windowSpan(window, "30d");
  return [
    "Usage",
    `| where TimeGenerated > ago(${w})`,
    "| summarize mb = round(sum(Quantity), 3), first_seen = min(TimeGenerated), last_seen = max(TimeGenerated), billable = take_any(IsBillable) by TenantId, DataType, Solution",
  ].join("\n");
}

// The literal tstats port: a scan of every table in the window. Costs what
// it says on a large workspace, but it is the only inventory a workspace
// whose Usage aggregate is empty (a new one, or one hours behind) can give.
export function inventoryScanQuery({ window = "1d" } = {}) {
  const w = kql.windowSpan(window, "1d");
  return [
    "union withsource = T *",
    `| where TimeGenerated > ago(${w})`,
    "| summarize n = count(), first_seen = min(TimeGenerated), last_seen = max(TimeGenerated) by T, TenantId",
  ].join("\n");
}

export function schemaQuery(tables) {
  const names = (tables || []).map((t) => kql.table(t));
  if (!names.length) throw new kql.KqlError("no_tables", "schema needs at least one table");
  if (names.length === 1) return `${names[0]} | getschema | extend T = ${kql.quote(names[0])} | project T, ColumnName, ColumnType`;
  return `union\n${names.map((t) => `  (${t} | getschema | extend T = ${kql.quote(t)})`).join(",\n")}\n| project T, ColumnName, ColumnType`;
}

// Column-agnostic profile: pack_all() + mv-expand turns each row into
// (column, value) pairs, so one query profiles a table Reach has never seen.
// Verified live (docs/SENTINEL.md §5.5): dense over empty and null columns,
// dcountif so "" is not a distinct value, gettype() ignoring nulls.
export function profileQuery({ table: t, sample = SAMPLE_DEFAULT, window = "1d", top = 10 } = {}) {
  const name = kql.table(t);
  const n = Math.max(1, Math.min(100000, Number(sample) || SAMPLE_DEFAULT));
  const k = Math.max(1, Math.min(50, Number(top) || 10));
  const w = kql.windowSpan(window, "1d");
  return [
    `let S = ${name} | where TimeGenerated > ago(${w}) | take ${n};`,
    "let total = toscalar(S | count);",
    "S",
    "| project p = pack_all()",
    "| mv-expand kind=array p",
    "| extend col = tostring(p[0]), val = tostring(p[1]), t = gettype(p[1])",
    '| summarize n = countif(isnotempty(val)), d = dcountif(val, isnotempty(val)), t = take_anyif(t, isnotempty(val) and t != "null") by col',
    "| extend total = total, row_kind = \"stat\"",
    "| union (",
    "    S",
    "    | project p = pack_all()",
    "    | mv-expand kind=array p",
    "    | extend col = tostring(p[0]), val = tostring(p[1])",
    "    | where isnotempty(val)",
    "    | summarize n = count() by col, val",
    `    | top-nested of col by outer = max(1), top-nested ${k} of val by cnt = sum(n)`,
    "    | project col, val, n = cnt, row_kind = \"top\")",
  ].join("\n");
}

export function recordTypesQuery({ table: t, column: c, sample = RECORD_TYPES_SAMPLE, window = "1d" } = {}) {
  const name = kql.table(t);
  const col = kql.column(c);
  const n = Math.max(1, Math.min(200000, Number(sample) || RECORD_TYPES_SAMPLE));
  const w = kql.windowSpan(window, "1d");
  return `${name} | where TimeGenerated > ago(${w}) | take ${n}\n| summarize n = count() by value = tostring(${col}) | order by n desc`;
}

// Sentinel-only: _GetWatchlistAlias fails on a workspace without Sentinel
// onboarded; the step degrades on the error the user pastes back.
export function watchlistsQuery() {
  return "_GetWatchlistAlias | project alias = WatchlistAlias";
}

export function watchlistSchemaQuery(aliases) {
  const list = (aliases || []).map((a) => String(a));
  if (!list.length) throw new kql.KqlError("no_aliases", "no watchlists to describe");
  return `union\n${list.map((a) => `  (_GetWatchlist(${kql.quote(a)}) | getschema | extend alias = ${kql.quote(a)})`).join(",\n")}\n| where ColumnName !in ("_DTItemId", "LastUpdatedTimeUTC", "SearchKey")\n| project alias, ColumnName, ColumnType`;
}

export function watchlistReadQuery({ alias, key, value, max = DECODE_MAX_ROWS } = {}) {
  const k = kql.column(key);
  const v = kql.column(value);
  const n = Math.max(1, Math.min(100000, Number(max) || DECODE_MAX_ROWS)) + 1;
  return `_GetWatchlist(${kql.quote(String(alias))}) | take ${n} | project k = tostring(${k}), v = tostring(${v})`;
}

// The organisation corpus (known.js): the fleet's process binaries from a
// Falcon process-event table, per hash, image path and signing id, mac and
// windows hosts. The sample table's spellings (docs/KNOWN.md §5); a column
// the table lacks (SigningId, SourceEventTime) is read as empty or as
// TimeGenerated rather than failing the query. A table qualifies when the
// caller names it (the packs bind these columns on it) or its discovered
// schema carries every column the query reads.
export const ORG_CORPUS_COLUMNS_NEEDED = Object.freeze(["EventSimpleName", "EventPlatform", "Aid", "SHA256HashData", "ImageFileName"]);

export function orgCorpusTables(env, { falconTables = [] } = {}) {
  const out = new Set(falconTables.filter((t) => TABLE_RE.test(t)));
  for (const [t, rec] of Object.entries((env && env.sourcetypes) || {})) {
    if (!TABLE_RE.test(t) || !rec || !rec.fields) continue;
    if (ORG_CORPUS_COLUMNS_NEEDED.every((c) => rec.fields[c])) out.add(t);
  }
  return Array.from(out).sort();
}

export function orgCorpusQuery({ table: t, window = "30d", top = ORG_CORPUS_MAX_ROWS } = {}) {
  const name = kql.table(t);
  const w = kql.windowSpan(window, "30d");
  const n = Math.max(1, Math.min(ORG_CORPUS_MAX_ROWS, Number(top) || ORG_CORPUS_MAX_ROWS));
  return [
    name,
    `| where TimeGenerated > ago(${w})`,
    '| where EventSimpleName == "ProcessRollup2" and EventPlatform in ("Mac", "Win") and isnotempty(SHA256HashData)',
    '| extend signing_id = tostring(column_ifexists("SigningId", "")), seen = todatetime(column_ifexists("SourceEventTime", TimeGenerated))',
    "| summarize hosts = dcount(Aid), events = count(), first_seen = min(seen), last_seen = max(seen) by sha256 = tostring(SHA256HashData), path = tostring(ImageFileName), signing_id, platform = tostring(EventPlatform)",
    `| top ${n} by hosts desc`,
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Steps

export const STEP_LABELS = {
  inventory: "Inventory: which tables the workspace carries, and how much (from Usage; cheap)",
  inventoryScan: "Inventory by scan: every table with rows in the window (union *; costs a full scan, for a workspace whose Usage is empty)",
  schema: "Schema: every column and its declared type",
  profile: "Profile: fill rate, distinct count and top values per column",
  recordTypes: "Record types: the values of the discriminator column",
  watchlists: "Watchlists: which ones exist (Sentinel only)",
  watchlistSchema: "Watchlist columns: which watchlists are two-column decode tables",
  decode: "Decode table: read one watchlist as code → meaning",
  orgCorpus: "Fleet baseline: which process binaries your mac and windows hosts run, per hash, path and signing id (scans the Falcon table's process events)",
};

const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// Only names that can be a Log Analytics table: a discovered layer written
// on Splunk (aws:cloudtrail) shares the store and must not reach a query.
export function knownTables(env, { packTables = [] } = {}) {
  const names = new Set(packTables);
  for (const t of Object.keys((env && env.sourcetypes) || {})) names.add(t);
  for (const t of (env && env.extra_tables) || []) names.add(t);
  return Array.from(names).filter((t) => TABLE_RE.test(t)).sort();
}

function withStatus(env, step) {
  const rec = env && env.steps ? env.steps[step.id] : null;
  if (!rec) return { ...step, status: "pending", imported_at: null, rows: 0 };
  return { ...step, status: rec.q === step.q ? "imported" : "stale", imported_at: rec.imported_at || null, rows: rec.rows || 0, imported_q: rec.q };
}

function makeStep(id, step, params, bare, label) {
  return { id, step, label: label || STEP_LABELS[step], params, bare, q: stamp(bare) };
}

export function steps(env, { packTables = [], window = "30d", scanWindow = "1d", sentinel = true } = {}) {
  const out = [];
  out.push(makeStep("inventory", "inventory", { window: kql.windowSpan(window, "30d") }, inventoryQuery({ window })));
  out.push(makeStep("inventoryScan", "inventoryScan", { window: kql.windowSpan(scanWindow, "1d") }, inventoryScanQuery({ window: scanWindow })));
  const tables = knownTables(env, { packTables });
  for (let i = 0; i < tables.length; i += SCHEMA_BATCH) {
    const batch = tables.slice(i, i + SCHEMA_BATCH);
    const n = Math.floor(i / SCHEMA_BATCH) + 1;
    out.push(makeStep(`schema:${n}`, "schema", { tables: batch.join(","), batch: n }, schemaQuery(batch), `${STEP_LABELS.schema}${tables.length > SCHEMA_BATCH ? ` (batch ${n})` : ""}`));
  }
  if (sentinel) {
    out.push(makeStep("watchlists", "watchlists", {}, watchlistsQuery()));
    const aliases = (env && env.watchlists) || [];
    if (aliases.length) out.push(makeStep("watchlistSchema", "watchlistSchema", { aliases: aliases.join(",") }, watchlistSchemaQuery(aliases)));
    for (const [alias, cols] of Object.entries((env && env.watchlist_schemas) || {})) {
      if (!Array.isArray(cols) || cols.length !== 2) continue;
      out.push(makeStep(`decode:${alias}`, "decode", { alias, key: cols[0].name, value: cols[1].name }, watchlistReadQuery({ alias, key: cols[0].name, value: cols[1].name }), `${STEP_LABELS.decode}: ${alias} (${cols[0].name} → ${cols[1].name})`));
    }
  }
  return out.map((s) => withStatus(env, s));
}

// The fleet baseline step, one per Falcon table the schema or the packs
// qualify (orgCorpusTables): lives off the generic list, on the sourcetype
// page for the table it measures, not the Discover page's queries section.
export function orgCorpusSteps(env, { falconTables = [], window = "30d" } = {}) {
  const out = [];
  for (const t of orgCorpusTables(env, { falconTables })) {
    const w = kql.windowSpan(window, "30d");
    out.push(makeStep(`orgCorpus:${t}`, "orgCorpus", { table: t, window: w }, orgCorpusQuery({ table: t, window }), `${STEP_LABELS.orgCorpus} (${t})`));
  }
  return out.map((s) => withStatus(env, s));
}

export function tableSteps(env, table, { discriminator = null, sample = SAMPLE_DEFAULT, window = "1d" } = {}) {
  const out = [];
  const w = kql.windowSpan(window, "1d");
  out.push(makeStep(`profile:${table}`, "profile", { table, sample, window: w }, profileQuery({ table, sample, window }), `${STEP_LABELS.profile} (${table})`));
  const rec = env && env.sourcetypes ? env.sourcetypes[table] : null;
  const disc = discriminator || (rec && rec.discriminator) || (rec ? proposeDiscriminator(rec) : null);
  if (disc) out.push(makeStep(`recordTypes:${table}`, "recordTypes", { table, column: disc, sample: RECORD_TYPES_SAMPLE, window: w }, recordTypesQuery({ table, column: disc, window }), `${STEP_LABELS.recordTypes} (${table} by ${disc})`));
  return out.map((s) => withStatus(env, s));
}

// The query the user runs: bare query + envelope, stamped with the
// workspace label so the paste says where it came from.
export function queryFor(step, env, { label } = {}) {
  const envLabel = label || (env && env.label) || "";
  return envelope({ query: step.bare, step: step.step, env: envLabel, params: step.params });
}

export async function linkFor(step, env, { resourceId, label } = {}) {
  const rid = resourceId || (env && env.resourceId);
  const wrapped = queryFor(step, env, { label });
  const span = step.params && step.params.window ? kql.timespanFor(step.params.window) : "P1D";
  return { ...wrapped, url: rid ? await kql.deepLink({ resourceId: rid, kql: wrapped.kql, timespan: span }) : null };
}

// ---------------------------------------------------------------------------
// Apply: rows in, layer out

function num(v) {
  if (v === null || v === undefined || v === "") return 0;
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function str(v) {
  return v === null || v === undefined ? "" : String(v);
}

// first_seen and last_seen as the layer stores them: epoch seconds, from
// the datetime strings the portal returns.
function seen(rec, r) {
  const first = layer.epochOf(r.first_seen);
  const last = layer.epochOf(r.last_seen);
  if (first !== null) rec.first_seen = first;
  if (last !== null) rec.last_seen = last;
}

function need(rows, cols, step) {
  const have = new Set();
  for (const r of rows) for (const k of Object.keys(r)) have.add(k);
  const missing = cols.filter((c) => !have.has(c));
  if (missing.length && rows.length) throw new Error(`${step}: the rows lack the column${missing.length === 1 ? "" : "s"} ${missing.join(", ")}. Was this the ${step} query?`);
}

const WRITERS = {
  inventory(env, rows, params) {
    need(rows, ["DataType"], "inventory");
    const at = now();
    const window = str(params && params.window) || null;
    const returned = new Set();
    for (const r of rows) {
      const t = str(r.DataType);
      if (!t) continue;
      const rec = tableRec(env, t);
      rec.mb = num(r.mb);
      rec.solution = str(r.Solution) || null;
      rec.billable = r.billable === true || r.billable === "true" || r.billable === "True";
      seen(rec, r);
      rec.inventoried_at = at;
      rec.inventory_window = window;
      rec.usage_at = at;
      delete rec.missing_since;
      layer.pushRun(rec, { kind: "inventory", at, window, mb: rec.mb, last_seen: rec.last_seen });
      if (r.TenantId && !env.tenantId) env.tenantId = str(r.TenantId);
      returned.add(t);
    }
    // The Usage inventory covers the whole workspace, so a table an earlier
    // Usage paste returned and this one did not produced nothing in the
    // window: kept, and marked from the first miss. A table known only from
    // a schema or decode paste is not Usage's to miss (custom tables can sit
    // outside it), and the scan step's one-day window marks none.
    if (rows.length) {
      for (const [t, rec] of Object.entries(env.sourcetypes)) {
        if (returned.has(t) || !rec.usage_at) continue;
        rec.missing_since = rec.missing_since || at;
        layer.pushRun(rec, { kind: "inventory", at, window, mb: 0, last_seen: rec.last_seen, missing: true });
      }
    }
    env.inventory = { at, window };
    return { tables: returned.size };
  },

  inventoryScan(env, rows) {
    need(rows, ["T", "n"], "inventory by scan");
    let n = 0;
    for (const r of rows) {
      const t = str(r.T);
      if (!t) continue;
      const rec = tableRec(env, t);
      rec.count = num(r.n);
      seen(rec, r);
      rec.inventoried_at = now();
      rec.inventory_basis = "scan";
      delete rec.missing_since; // rows are arrival, whatever the window
      if (r.TenantId && !env.tenantId) env.tenantId = str(r.TenantId);
      n++;
    }
    return { tables: n };
  },

  schema(env, rows) {
    need(rows, ["T", "ColumnName", "ColumnType"], "schema");
    const tables = new Set();
    for (const r of rows) {
      const t = str(r.T);
      const c = str(r.ColumnName);
      if (!t || !c || SYSTEM_COLUMNS.has(c)) continue;
      const rec = tableRec(env, t);
      rec.fields[c] = { ...(rec.fields[c] || {}), declared: { type: normalType(r.ColumnType), raw: str(r.ColumnType) } };
      rec.schema_at = now();
      tables.add(t);
    }
    return { tables: tables.size };
  },

  profile(env, rows, params) {
    const table = str(params.table);
    if (!table) throw new Error("profile: the envelope names no table");
    need(rows, ["col", "n"], "profile");
    const rec = tableRec(env, table);
    const stats = rows.filter((r) => str(r.row_kind) === "stat" || (r.total !== undefined && r.val === undefined));
    const tops = rows.filter((r) => str(r.row_kind) === "top" || (r.val !== undefined && r.total === undefined));
    const total = stats.length ? Math.max(...stats.map((r) => num(r.total))) : 0;
    const window = str(params.window) || null;
    const measured_at = now();
    const profiled = {};
    let fields = 0;
    for (const r of stats) {
      const c = str(r.col);
      if (!c || SYSTEM_COLUMNS.has(c)) continue;
      const count = num(r.n);
      const t = normalType(r.t) || null;
      const declared = rec.fields[c] && rec.fields[c].declared ? rec.fields[c].declared.type : null;
      const type = t && t !== "null" ? t : declared;
      // A dynamic column's "values" are whole JSON objects; keep enough to
      // recognise one, not the object.
      const top = tops.filter((x) => str(x.col) === c).map((x) => ({ value: str(x.val).slice(0, TOP_VALUE_MAX), count: num(x.n) })).sort((a, b) => b.count - a.count);
      profiled[c] = {
        profile: {
          count,
          distinct: num(r.d),
          distinct_exact: null, // DISTINCT_ESTIMATED
          fill: total ? count / total : null,
          numeric: NUMERIC_TYPES.has(type || ""),
          type,
          type_agrees: declared && type ? declared === type : null,
          min: null,
          max: null,
          mean: null,
          top,
          sample: total,
          measured_at,
          window,
        },
      };
      fields++;
    }
    // Field changes against the profile pasted before: new columns, columns
    // this sample lacks, fill rates that moved. Same arithmetic as Splunk.
    layer.applyProfile(rec, profiled, { at: measured_at, window, sample: total });
    if (!rec.discriminator) {
      const p = proposeDiscriminator(rec);
      if (p) rec.proposed_discriminator = p;
    }
    return { table, fields, total };
  },

  recordTypes(env, rows, params) {
    const table = str(params.table);
    const column = str(params.column);
    if (!table || !column) throw new Error("record types: the envelope names no table/column");
    need(rows, ["value", "n"], "record types");
    const rec = tableRec(env, table);
    rec.discriminator = column;
    rec.record_types = rows.map((r) => ({ value: str(r.value), count: num(r.n) })).filter((x) => x.value !== "");
    rec.record_types_at = now();
    delete rec.proposed_discriminator;
    return { table, values: rec.record_types.length };
  },

  watchlists(env, rows) {
    need(rows, ["alias"], "watchlists");
    env.watchlists = Array.from(new Set(rows.map((r) => str(r.alias)).filter(Boolean))).sort();
    env.watchlists_at = now();
    return { watchlists: env.watchlists.length };
  },

  watchlistSchema(env, rows) {
    need(rows, ["alias", "ColumnName", "ColumnType"], "watchlist columns");
    const schemas = {};
    for (const r of rows) {
      const a = str(r.alias);
      if (!a) continue;
      (schemas[a] = schemas[a] || []).push({ name: str(r.ColumnName), type: normalType(r.ColumnType) });
    }
    env.watchlist_schemas = { ...(env.watchlist_schemas || {}), ...schemas };
    return { watchlists: Object.keys(schemas).length, decodeCandidates: Object.values(schemas).filter((c) => c.length === 2).length };
  },

  decode(env, rows, params) {
    const alias = str(params.alias);
    if (!alias) throw new Error("decode: the envelope names no watchlist");
    need(rows, ["k", "v"], "decode");
    if (rows.length > DECODE_MAX_ROWS) throw new Error(`decode: ${alias} has more than ${DECODE_MAX_ROWS} rows. This looks like an asset list, not a decode table`);
    const values = {};
    for (const r of rows) {
      const k = str(r.k);
      if (k === "" || k in values) continue;
      values[k] = str(r.v);
    }
    const table = { lookup: alias, meaning_field: str(params.value) || "v", key_field: str(params.key) || "k", values, rows: rows.length, read_at: now() };
    env.decodes = { ...(env.decodes || {}), [alias]: table };
    // Bound to a table's column only when the envelope says so, or a column
    // of the same name as the watchlist's key exists on a known table.
    let bound = 0;
    const targets = params.table && params.column ? [[str(params.table), str(params.column)]] : [];
    if (!targets.length && table.key_field) {
      for (const [t, rec] of Object.entries(env.sourcetypes)) if (rec.fields && rec.fields[table.key_field]) targets.push([t, table.key_field]);
    }
    for (const [t, c] of targets) {
      const rec = tableRec(env, t);
      rec.decodes = { ...(rec.decodes || {}), [c]: { ...table } };
      bound++;
    }
    return { alias, values: Object.keys(values).length, bound };
  },
};

WRITERS.orgCorpus = function orgCorpus(env, rows, params) {
  const table = str(params.table);
  if (!table) throw new Error("fleet baseline: the envelope names no table");
  need(rows, ["sha256", "hosts"], "fleet baseline");
  env.org_corpus = projectOrgCorpus(rows, { at: now(), window: str(params.window) || null, table, source: "sentinel" });
  return { table, rows: env.org_corpus.kept, pruned: env.org_corpus.pruned };
};

export const STEPS = Object.freeze(Object.keys(WRITERS));

// `parsed` is intake.parse()'s result. An envelope carries its own step and
// params; a plain table needs them from the caller. `expect` (a Step from
// steps()/tableSteps()) makes the q/gen check possible.
export async function apply(key, parsed, { step, params, expect } = {}) {
  if (!key) throw new Error("apply needs an environment");
  const stepName = parsed.kind === "envelope" ? parsed.step : step;
  if (!stepName || !WRITERS[stepName]) throw new Error(`unknown step: ${stepName || "(none)"}`);
  const p = parsed.kind === "envelope" ? parsed.params : params || {};
  const rows = parsed.rows || [];
  const verdicts = [];
  if (parsed.kind === "envelope") {
    if (expect && parsed.q && expect.q !== parsed.q) verdicts.push("superseded: the query Reach generates for this step has changed since this result was produced");
    if (parsed.env && expect && expect.env && parsed.env !== expect.env) verdicts.push(`envelope says workspace "${parsed.env}"`);
  } else {
    verdicts.push("unverified: a plain export carries no step identity; trusted because you said which step it was");
  }
  let written;
  const { env, notice } = await update(key, (e) => {
    written = WRITERS[stepName](e, rows, p);
    const id = stepId(stepName, p);
    e.steps[id] = { q: parsed.q || (expect ? expect.q : null), gen: parsed.gen || null, imported_at: now(), rows: rows.length, verdicts };
    if (parsed.env && !e.label) e.label = parsed.env;
  });
  return { step: stepName, written, verdicts, env, notice };
}

export function stepId(step, params = {}) {
  switch (step) {
    case "profile": return `profile:${params.table}`;
    case "recordTypes": return `recordTypes:${params.table}`;
    case "decode": return `decode:${params.alias}`;
    case "schema": return `schema:${params.batch || 1}`;
    case "orgCorpus": return `orgCorpus:${params.table}`;
    default: return step;
  }
}

// ---------------------------------------------------------------------------
// Proposals: derived here, not stored as facts.

const DISC_NAME_RE = /(event|operation|action|category|activity|type|name|class|kind|id)$/i;

export function proposeDiscriminator(rec) {
  const cands = [];
  for (const [c, f] of Object.entries((rec && rec.fields) || {})) {
    const p = f.profile;
    if (!p || SYSTEM_COLUMNS.has(c) || c === "TimeGenerated") continue;
    if (!(p.type === "string" || p.type === "long" || !p.type)) continue;
    if (p.fill === null || p.fill < 0.9) continue;
    if (p.distinct < 2 || p.distinct > 500) continue;
    cands.push({ c, distinct: p.distinct, named: DISC_NAME_RE.test(c) ? 0 : 1 });
  }
  cands.sort((a, b) => a.named - b.named || a.distinct - b.distinct || a.c.localeCompare(b.c));
  return cands.length ? cands[0].c : null;
}

// Two tables sharing a column name, same runtime type, overlapping top
// values → a proposed edge (PROPOSAL.md §3 #10).
export function proposeEdges(env) {
  const out = [];
  const tables = Object.entries((env && env.sourcetypes) || {});
  for (let i = 0; i < tables.length; i++) {
    for (let j = i + 1; j < tables.length; j++) {
      const [ta, a] = tables[i];
      const [tb, b] = tables[j];
      for (const c of Object.keys(a.fields || {})) {
        const pa = a.fields[c] && a.fields[c].profile;
        const pb = b.fields && b.fields[c] && b.fields[c].profile;
        if (!pa || !pb || SYSTEM_COLUMNS.has(c) || c === "TimeGenerated") continue;
        if (pa.type !== pb.type || pa.distinct < 2 || pb.distinct < 2) continue;
        const va = new Set((pa.top || []).map((t) => t.value));
        const overlap = (pb.top || []).filter((t) => va.has(t.value)).length;
        if (!overlap) continue;
        out.push({ src: { sourcetype: ta, field: c }, dst: { sourcetype: tb, field: c }, overlap, type: pa.type, basis: "proposed" });
      }
    }
  }
  return out.sort((x, y) => y.overlap - x.overlap);
}

export default {
  WORKSPACES_KEY,
  SYSTEM_COLUMNS,
  DISTINCT_ESTIMATED,
  ENVELOPE_VERSION,
  SAMPLE_DEFAULT,
  RECORD_TYPES_SAMPLE,
  DECODE_MAX_ROWS,
  SCHEMA_BATCH,
  stamp,
  envelope,
  inventoryQuery,
  inventoryScanQuery,
  schemaQuery,
  profileQuery,
  recordTypesQuery,
  watchlistsQuery,
  watchlistSchemaQuery,
  watchlistReadQuery,
  orgCorpusQuery,
  orgCorpusTables,
  ORG_CORPUS_COLUMNS_NEEDED,
  STEP_LABELS,
  STEPS,
  normalType,
  seenWorkspaces,
  rememberWorkspace,
  environments,
  addEnvironment,
  environment,
  forget,
  knownTables,
  steps,
  orgCorpusSteps,
  tableSteps,
  queryFor,
  linkFor,
  apply,
  stepId,
  proposeDiscriminator,
  proposeEdges,
};
