// Known-good verdict on a process value: is a SigningId, ImageFileName
// (macOS/Falcon) or a path/hash/package (Linux) something the bundled
// corpus of platform-default executables has seen, and does it check out?
//
// The corpus (tools/dev/macos-corpus.sh, tools/dev/linux-corpus.sh) is
// projected by tools/dev/corpus-project.mjs into app/data/known/*.json:
// one macOS index over every enumerated build, one file per Linux
// (distro, release), plus index.json (what got bundled, its size, when it
// was generated). Nothing here reads the corpus CSVs; this module only
// reads the projections, lazily, and only once an event with a mac or
// linux value is actually in hand (a click, never eagerly on load).
//
// verdict(input) -> { tier, evidence: [string], corpus }
//   tier      macOS, where a binary's identity is its signature and the
//             corpus carries no hashes (they change with every point
//             release; the signing id and path do not):
//             "normal"         an Apple platform binary at a path the corpus
//                               saw its signing id at, on any enumerated
//                               build; or a path the corpus has under one
//                               platform signing id when the event carries
//                               no signing facts to compare;
//             "impersonation"  the corpus knows this identity and the
//                               event *disagrees* with it: a signing id
//                               the corpus has as Apple-platform-signed
//                               reports platform_binary=false or a team
//                               id, or sits at a path the corpus never
//                               saw it at; a path the corpus has under a
//                               platform signing id is claimed by another
//                               signing id, a team id, or a binary whose
//                               flags say it is not a platform binary.
//                               Absence from the corpus is never
//                               impersonation by itself (the enumeration
//                               only sees files on disk; dyld-shared-
//                               cache-only binaries and third-party
//                               installs are invisible to it and are
//                               legitimately unknown), and a column the
//                               event does not carry is never a
//                               disagreement;
//             "unknown"        nothing above applies: no bundled corpus,
//                               the identity is not in it, it is in it but
//                               not as an Apple platform binary, or too
//                               little was given (a hash alone says
//                               nothing on macOS).
//             Linux, where a package has no signature and its checksum is
//             the identity:
//             "normal"         sha256 matches a corpus row for this
//                               distro/release;
//             "consistent"     the path matches the corpus but no hash was
//                               given to confirm it;
//             "impersonation"  a path the corpus knows carries a different
//                               hash than the one seen;
//             "unknown"        nothing above applies.
//   evidence  short strings naming what matched or disagreed
//   corpus    { platform, build|null, builds|null, os_version|null,
//               distro|null, release|null, source, generated_at } of
//               whichever projection was consulted (build: the event's
//               build when the corpus enumerated it; builds: every macOS
//               build the index covers), or null when none was loaded
//
// input (platform-neutral; every key optional):
//   sha256, signing_id, team_id, path, os_build, distro, release,
//   cs_platform_binary (bool | null, Falcon CS_PLATFORM_BINARY),
//   sign_flags   accepted but not compared: the corpus does not carry
//                codesign flags today, only Identifier/TeamIdentifier/
//                Authority; kept in the signature so a caller can pass
//                the whole context object without picking it apart, and
//                so a later corpus rev can start using it without an API
//                change.
// Platform is read from the input: distro, release or platform "linux"
// means Linux (a Linux row with no release is unknown, never read against
// the macOS index), otherwise macOS (the corpus this ships today).
//
// Plain ES module. No DOM, no store. The only network is fetch() of the
// bundled projections, exactly as app/lib/values.js loads pack sidecars.

export const TIERS = ["normal", "consistent", "impersonation", "unknown"];

const indexCache = { promise: null, value: null };
const macosCache = { promise: null }; // { doc, bySigningId, byPath } | null, or a pending promise
const linuxCache = new Map(); // "distro/release" -> { doc, byPath, bySha256 } | null, or a pending promise

function fileUrl(name) {
  return new URL(`../data/known/${name}`, import.meta.url).href;
}

async function getJson(name) {
  const res = await fetch(fileUrl(name));
  if (!res.ok) return null;
  try { return await res.json(); } catch { return null; }
}

export function reset() {
  indexCache.promise = null;
  indexCache.value = null;
  macosCache.promise = null;
  linuxCache.clear();
}
export const _reset = reset;

async function loadIndex() {
  if (indexCache.value) return indexCache.value;
  if (!indexCache.promise) indexCache.promise = getJson("index.json").then((v) => { indexCache.value = v; return v; });
  return indexCache.promise;
}

function entryFor(idx, matcher) {
  if (!idx || !Array.isArray(idx.entries)) return null;
  return idx.entries.find(matcher) || null;
}

// ---------------------------------------------------------------------------
// macOS

// bySigningId: id -> { platform_binary, paths: Set, pathBuilds: Map path ->
// [build], builds: Set, description, team_id }; byPath: path -> [id].
function buildMacosIndex(doc) {
  const bySigningId = new Map();
  const byPath = new Map();
  const cols = doc.columns || [];
  const iId = cols.indexOf("signing_id"), iPath = cols.indexOf("path"), iPlat = cols.indexOf("platform_binary"), iBuilds = cols.indexOf("builds");
  for (const row of doc.rows || []) {
    const id = row[iId], path = row[iPath];
    if (!id || !path) continue;
    let e = bySigningId.get(id);
    if (!e) {
      e = { platform_binary: false, paths: new Set(), pathBuilds: new Map(), builds: new Set(), description: doc.description ? doc.description[id] || null : null, team_id: doc.team_id ? doc.team_id[id] || "" : "" };
      bySigningId.set(id, e);
    }
    if (row[iPlat]) e.platform_binary = true;
    const builds = Array.isArray(row[iBuilds]) ? row[iBuilds] : [];
    e.paths.add(path);
    e.pathBuilds.set(path, builds);
    for (const b of builds) e.builds.add(b);
    if (!byPath.has(path)) byPath.set(path, []);
    byPath.get(path).push(id);
  }
  return { bySigningId, byPath };
}

// Loads app/data/known/macos.json, the one index over every enumerated
// build, when index.json says it is bundled; returns null (never throws)
// when it is not, or the fetch fails.
export async function loadMacos() {
  if (macosCache.promise) return macosCache.promise;
  const p = (async () => {
    const idx = await loadIndex();
    const meta = entryFor(idx, (e) => e.platform === "macos" && e.kind === "projection");
    if (!meta || !meta.bundled) return null;
    const doc = await getJson(meta.file);
    if (!doc) return null;
    return { doc, ...buildMacosIndex(doc) };
  })();
  macosCache.promise = p;
  return p;
}

// The macOS builds index.json actually bundled, in the order listed.
export async function bundledMacosBuilds() {
  const idx = await loadIndex();
  const meta = entryFor(idx, (e) => e.platform === "macos" && e.kind === "projection" && e.bundled);
  return meta && Array.isArray(meta.builds) ? meta.builds.slice() : [];
}

function buildList(builds) {
  return Array.from(builds).join(", ");
}

async function verdictMacos(input) {
  const loaded = await loadMacos();
  if (!loaded) return { tier: "unknown", evidence: ["no macOS corpus bundled"], corpus: null };
  const builds = (loaded.doc.builds || []).map((b) => b.build);
  const buildKnown = Boolean(input.os_build) && builds.includes(input.os_build);
  const corpus = { platform: "macos", build: buildKnown ? input.os_build : null, builds, os_version: null, distro: null, release: null, source: loaded.doc.source || (loaded.doc.builds || []).map((b) => b.source).join("; "), generated_at: loaded.doc.generated_at };
  const buildLine = () => {
    if (!input.os_build) return null;
    return buildKnown ? `the event's build ${input.os_build} is one the corpus enumerated` : `the event reports build ${input.os_build}, which the corpus has not enumerated`;
  };

  if (input.signing_id) {
    const entry = loaded.bySigningId.get(input.signing_id);
    if (entry) {
      const pathKnown = !input.path || entry.paths.has(input.path);
      if (entry.platform_binary) {
        const disagreements = [];
        if (input.cs_platform_binary === false) disagreements.push("corpus has this signing id as an Apple platform binary, event reports cs_platform_binary=false");
        if (input.team_id) disagreements.push(`corpus has this signing id with no team id, event reports team id ${input.team_id}`);
        if (input.path && !pathKnown) disagreements.push(`corpus never saw signing id ${input.signing_id} at path ${input.path}`);
        if (disagreements.length) return { tier: "impersonation", evidence: disagreements, corpus };
        const seen = input.path ? entry.pathBuilds.get(input.path) || [] : Array.from(entry.builds);
        const evidence = [input.path ? `Apple platform binary ${input.signing_id} at its path in the corpus, seen on ${seen.length === 1 ? "build" : "builds"} ${buildList(seen)}` : `Apple platform binary ${input.signing_id} known to the corpus (no path given to check), seen on ${seen.length === 1 ? "build" : "builds"} ${buildList(seen)}`];
        const b = buildLine();
        if (b) evidence.push(b);
        return { tier: "normal", evidence, corpus };
      }
      return { tier: "unknown", evidence: [`signing id ${input.signing_id} is in the corpus${entry.team_id ? ` (team ${entry.team_id})` : ""} but not as an Apple platform binary${input.path && !pathKnown ? `, and not at path ${input.path}` : ""}`], corpus };
    }
  }

  if (input.path) {
    const owners = (loaded.byPath.get(input.path) || []).filter((id) => loaded.bySigningId.get(id).platform_binary);
    if (owners.length) {
      const owner = owners.join(", ");
      const disagreements = [];
      if (input.signing_id) disagreements.push(`path ${input.path} belongs to Apple platform binary ${owner} in the corpus, event claims signing id ${input.signing_id}`);
      if (input.team_id) disagreements.push(`path ${input.path} is an Apple platform binary in the corpus, event reports team id ${input.team_id}`);
      if (input.cs_platform_binary === false) disagreements.push(`path ${input.path} is an Apple platform binary in the corpus, event reports cs_platform_binary=false`);
      if (disagreements.length) return { tier: "impersonation", evidence: disagreements, corpus };
      const seen = new Set();
      for (const id of owners) for (const b of loaded.bySigningId.get(id).pathBuilds.get(input.path) || []) seen.add(b);
      const evidence = [`path ${input.path} is Apple platform binary ${owner} in the corpus, seen on ${seen.size === 1 ? "build" : "builds"} ${buildList(seen)}; the event carries no signing id to compare`];
      const b = buildLine();
      if (b) evidence.push(b);
      return { tier: "normal", evidence, corpus };
    }
  }

  if (input.signing_id) return { tier: "unknown", evidence: [`signing id ${input.signing_id} not in the corpus${input.path ? `, nor path ${input.path}` : ""}`], corpus };
  if (input.path) return { tier: "unknown", evidence: [`path ${input.path} not in the corpus`], corpus };
  return { tier: "unknown", evidence: [input.sha256 ? "only a hash given; the macOS corpus carries signing ids and paths, not hashes" : "no signing id or path given"], corpus };
}

// ---------------------------------------------------------------------------
// Linux

function buildLinuxIndex(doc) {
  const byPath = new Map();
  const bySha256 = new Map();
  const cols = doc.columns || [];
  const iPath = cols.indexOf("path"), iSha = cols.indexOf("sha256");
  for (const row of doc.rows || []) {
    const path = row[iPath], sha256 = row[iSha];
    if (path) byPath.set(path, row);
    if (sha256) { if (!bySha256.has(sha256)) bySha256.set(sha256, []); bySha256.get(sha256).push(row); }
  }
  return { byPath, bySha256 };
}

export async function loadLinux(distro, release) {
  if (!distro || !release) return null;
  const key = `${distro}/${release}`;
  if (linuxCache.has(key)) return linuxCache.get(key);
  const p = (async () => {
    const idx = await loadIndex();
    const meta = entryFor(idx, (e) => e.platform === "linux" && e.distro === distro && e.release === release);
    if (!meta || !meta.bundled) return null;
    const doc = await getJson(meta.file);
    if (!doc) return null;
    const { byPath, bySha256 } = buildLinuxIndex(doc);
    return { doc, byPath, bySha256 };
  })();
  linuxCache.set(key, p);
  return p;
}

async function verdictLinux(input) {
  if (!input.distro || !input.release) return { tier: "unknown", evidence: ["no distro/release given"], corpus: null };
  const loaded = await loadLinux(input.distro, input.release);
  if (!loaded) return { tier: "unknown", evidence: [`no Linux corpus bundled for ${input.distro} ${input.release}`], corpus: null };
  const corpus = { platform: "linux", build: null, os_version: null, distro: input.distro, release: input.release, source: loaded.doc.source, generated_at: loaded.doc.generated_at };

  if (input.sha256) {
    const rows = loaded.bySha256.get(input.sha256);
    if (rows && rows.length) {
      const packages = Array.from(new Set(rows.map((r) => r[2]).filter(Boolean)));
      return { tier: "normal", evidence: [`sha256 matches ${packages.join(", ") || "a known package"} at ${rows.map((r) => r[0]).join(", ")}`], corpus };
    }
  }

  if (input.path) {
    const row = loaded.byPath.get(input.path);
    if (row) {
      if (input.sha256 && row[1] && input.sha256 !== row[1]) {
        return { tier: "impersonation", evidence: [`path ${input.path} is known (package ${row[2] || "unknown"}), hash does not match the corpus's binary for it`], corpus };
      }
      return { tier: "consistent", evidence: [`path ${input.path} known to the corpus (package ${row[2] || "unknown"}), ${input.sha256 ? "hash not confirmed" : "no hash given"}`], corpus };
    }
  }

  return { tier: "unknown", evidence: ["neither sha256 nor a known path was given"], corpus };
}

// ---------------------------------------------------------------------------
export async function verdict(input) {
  const in_ = input || {};
  return in_.distro || in_.release || in_.platform === "linux" ? verdictLinux(in_) : verdictMacos(in_);
}

// ---------------------------------------------------------------------------
// The organisation corpus: what the analyst's own fleet runs, measured by
// one discovery search over their Falcon process events (discovery.js on
// Splunk, recipe.js on Sentinel) and stored per environment in the
// discovered layer as env.org_corpus. Nothing here reads a store: the
// caller passes the document, prevalenceOf() answers from it.
//
//   projectOrgCorpus(rows, meta) → the stored document
//     rows: [{ sha256, path, signing_id, platform, hosts, events, first_seen, last_seen }]
//           (first_seen / last_seen as epoch seconds, ISO strings or the
//           platform's numeric strings; hosts and events as numbers or strings)
//     meta: { at, window, index?, table?, sourcetype?, source }
//   document: { ...meta, columns: ORG_CORPUS_COLUMNS, rows: [[...]], received, kept, pruned }
//     rows sorted most widespread first (hosts desc, last_seen desc), cut
//     at ORG_CORPUS_MAX_ROWS, then from the tail until the document fits
//     ORG_CORPUS_MAX_BYTES. `pruned` says how many rows did not make it, so
//     a miss can say whether the corpus was complete.
//
//   prevalenceOf(input, doc | [doc]) → null when there is no document, else
//     { key, hosts, events, first_seen, last_seen, rows, at, window, kept, pruned, complete }
//     Given several documents (one per environment) the answer with the
//     most hosts wins, and a miss is complete only when every corpus is.
//     key     which of the input's fields the rows were matched on:
//             "sha256" | "signing_id+path" | "path" | "signing_id" | null (too little given)
//     hosts   the host count of the best-matching row (max over the rows
//             matched: the same hash at two paths counts each path's hosts
//             separately, so this is a floor when rows > 1)
//     rows    how many corpus rows matched; 0 means not seen in the fleet

export const ORG_CORPUS_COLUMNS = Object.freeze(["sha256", "path", "signing_id", "platform", "hosts", "events", "first_seen", "last_seen"]);
export const ORG_CORPUS_MAX_ROWS = 20000;
export const ORG_CORPUS_MAX_BYTES = 1_000_000;

// The sourcetype (Splunk) and table (Sentinel, via the pack's container
// name) the fleet baseline measures: one shared identifier, so the
// sourcetype page's gate and the verdict's "run it" link agree on both
// platforms without either importing the other's discovery module.
export const ORG_CORPUS_SOURCETYPE = "crowdstrike:events:sensor";

function docBytes(doc) {
  const s = JSON.stringify(doc);
  return typeof TextEncoder !== "undefined" ? new TextEncoder().encode(s).length : s.length;
}

function epoch(v) {
  if (v === null || v === undefined || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) ? (Math.abs(v) >= 1e12 ? Math.floor(v / 1000) : Math.floor(v)) : null;
  const s = String(v).trim();
  if (/^-?\d+(\.\d+)?$/.test(s)) return epoch(Number(s));
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

function count(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function text(v) {
  return v === null || v === undefined ? "" : String(v).trim();
}

export function projectOrgCorpus(rows, meta = {}) {
  const out = [];
  for (const r of rows || []) {
    if (!r) continue;
    const sha = text(r.sha256).toLowerCase();
    const path = text(r.path);
    const signing = text(r.signing_id);
    if (!sha && !path && !signing) continue;
    out.push([sha, path, signing === "-" ? "" : signing, text(r.platform), count(r.hosts), count(r.events), epoch(r.first_seen), epoch(r.last_seen)]);
  }
  out.sort((a, b) => b[4] - a[4] || (b[7] || 0) - (a[7] || 0) || a[0].localeCompare(b[0]));
  const received = out.length;
  const maxRows = Math.max(1, Number(meta.maxRows) || ORG_CORPUS_MAX_ROWS);
  const maxBytes = Math.max(1000, Number(meta.maxBytes) || ORG_CORPUS_MAX_BYTES);
  let kept = out.slice(0, maxRows);
  const { maxRows: _r, maxBytes: _b, ...rest } = meta;
  const doc = { ...rest, columns: [...ORG_CORPUS_COLUMNS], rows: kept, received, kept: kept.length, pruned: received - kept.length };
  let size = docBytes(doc);
  while (size > maxBytes && kept.length) {
    const row = kept.pop();
    size -= docBytes(row) + 1;
  }
  doc.rows = kept;
  doc.kept = kept.length;
  doc.pruned = received - kept.length;
  return doc;
}

const orgIndexCache = new WeakMap(); // doc -> { bySha, byPath, bySigning }

function orgIndex(doc) {
  let idx = orgIndexCache.get(doc);
  if (idx) return idx;
  const cols = doc.columns || ORG_CORPUS_COLUMNS;
  const iSha = cols.indexOf("sha256"), iPath = cols.indexOf("path"), iSign = cols.indexOf("signing_id");
  idx = { bySha: new Map(), byPath: new Map(), bySigning: new Map(), iSha, iPath, iSign };
  const add = (m, k, row) => {
    if (!k) return;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(row);
  };
  for (const row of doc.rows || []) {
    if (!Array.isArray(row)) continue;
    add(idx.bySha, row[iSha], row);
    add(idx.byPath, row[iPath], row);
    add(idx.bySigning, row[iSign], row);
  }
  orgIndexCache.set(doc, idx);
  return idx;
}

export function prevalenceOf(input, doc) {
  if (Array.isArray(doc)) {
    const answers = doc.map((d) => prevalenceOf(input, d)).filter(Boolean);
    if (!answers.length) return null;
    const best = answers.reduce((a, b) => (b.hosts > a.hosts ? b : a));
    return { ...best, complete: best.rows > 0 || answers.every((a) => a.complete) };
  }
  if (!doc || !Array.isArray(doc.rows)) return null;
  const in_ = input || {};
  const idx = orgIndex(doc);
  const cols = doc.columns || ORG_CORPUS_COLUMNS;
  const iHosts = cols.indexOf("hosts"), iEvents = cols.indexOf("events"), iFirst = cols.indexOf("first_seen"), iLast = cols.indexOf("last_seen");
  const sha = in_.sha256 ? String(in_.sha256).toLowerCase() : "";
  const path = text(in_.path);
  const signing = text(in_.signing_id);
  let key = null;
  let rows = [];
  if (sha) {
    key = "sha256";
    rows = idx.bySha.get(sha) || [];
  } else if (signing && path) {
    key = "signing_id+path";
    rows = (idx.bySigning.get(signing) || []).filter((r) => r[idx.iPath] === path);
  } else if (path) {
    key = "path";
    rows = idx.byPath.get(path) || [];
  } else if (signing) {
    key = "signing_id";
    rows = idx.bySigning.get(signing) || [];
  }
  const base = { key, hosts: 0, events: 0, first_seen: null, last_seen: null, rows: rows.length, at: doc.at || null, window: doc.window || null, kept: doc.kept || doc.rows.length, pruned: doc.pruned || 0, complete: rows.length > 0 || !(doc.pruned > 0) };
  for (const r of rows) {
    base.hosts = Math.max(base.hosts, r[iHosts] || 0);
    base.events = Math.max(base.events, r[iEvents] || 0);
    if (r[iFirst] && (base.first_seen === null || r[iFirst] < base.first_seen)) base.first_seen = r[iFirst];
    if (r[iLast] && (base.last_seen === null || r[iLast] > base.last_seen)) base.last_seen = r[iLast];
  }
  return base;
}

export default { TIERS, verdict, loadMacos, loadLinux, bundledMacosBuilds, prevalenceOf, projectOrgCorpus, ORG_CORPUS_COLUMNS, ORG_CORPUS_MAX_ROWS, ORG_CORPUS_MAX_BYTES, ORG_CORPUS_SOURCETYPE, reset, _reset };
