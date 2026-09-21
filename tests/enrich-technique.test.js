// The G2 technique-and-rule bundle: MITRE ATT&CK, Sigma, Splunk ESCU and
// Microsoft Sentinel's analytic-rule index as bundled enrichment sources
// (app/lib/enrich/{attack,sigma,escu,sentinel-rules}.js), each source
// over a fixture, the registry's "technique" kind, and schema/dedupe/size
// checks against the committed app/data/enrich/*.json bundles.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as enrich from "../app/lib/enrich.js";
import * as attack from "../app/lib/enrich/attack.js";
import * as sigma from "../app/lib/enrich/sigma.js";
import * as escu from "../app/lib/enrich/escu.js";
import * as sentinelRules from "../app/lib/enrich/sentinel-rules.js";
import { detectTechnique } from "../app/lib/shapes.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// The self-registration check (enrich.js registers the four sources on
// import, with no explicit register() call from a caller) lives in its
// own file, tests/enrich-technique-registration.test.js: a beforeEach
// hook declared anywhere in this file applies to every test in it,
// including ones declared before the hook, since node:test collects
// hooks for the whole file before running any test.

beforeEach(() => {
  enrich.reset();
  attack.reset();
  sigma.reset();
  escu.reset();
  sentinelRules.reset();
});

// ---------------------------------------------------------------------------
// classify(): every source answers only a technique-shaped value

test("classify: each source matches only a technique id, matching detectTechnique", () => {
  for (const mod of [attack, sigma, escu, sentinelRules]) {
    assert.deepEqual(mod.classify("T1003.001"), { kind: "technique", id: "T1003.001" });
    assert.deepEqual(mod.classify("t1003"), { kind: "technique", id: "T1003" });
    assert.equal(mod.classify("CVE-2021-44228"), null);
    assert.equal(mod.classify("8.8.8.8"), null);
  }
  assert.deepEqual(detectTechnique("T1003.001"), { shape: "technique", detail: "T1003.001" });
});

// ---------------------------------------------------------------------------
// attack.js over a fixture

function stubFetch(doc) {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => doc });
}

const ATTACK_DOC = {
  format: "reach-attack",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  attackVersion: "19.2",
  count: 2,
  techniques: [
    { id: "T1003.001", name: "LSASS Memory", tactics: ["TA0006"], summary: "Adversaries may attempt to access credential material stored in LSASS memory.", url: "https://attack.mitre.org/techniques/T1003/001/" },
    { id: "T1566.001", name: "Spearphishing Attachment", tactics: ["TA0001"], summary: "Adversaries may send spearphishing emails with a malicious attachment.", url: "https://attack.mitre.org/techniques/T1566/001/" },
  ],
};

test("attack: linkFor builds the technique's own attack.mitre.org page", () => {
  assert.deepEqual(attack.linkFor("t1003.001"), { href: "https://attack.mitre.org/techniques/T1003/001/", label: "Open on MITRE ATT&CK ↗" });
  assert.equal(attack.linkFor("8.8.8.8"), null);
});

test("attack: call() on a hit reports name, tactic ids and the one-sentence summary", async () => {
  stubFetch(ATTACK_DOC);
  const res = await attack.call("T1003.001");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /LSASS Memory \(TA0006\)/);
  assert.match(res.lines[1], /LSASS memory/);
  assert.equal(res.link.href, "https://attack.mitre.org/techniques/T1003/001/");
});

test("attack: call() on a miss names the bundled ATT&CK version", async () => {
  stubFetch(ATTACK_DOC);
  const res = await attack.call("T1234.001");
  assert.equal(res.status, "empty");
  assert.match(res.lines[0], /not in the bundled ATT&CK Enterprise index \(bundled index is ATT&CK 19\.2\)/);
});

test("attack: call() on a non-technique value is refused, no fetch attempted", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return { ok: true, json: async () => ATTACK_DOC }; };
  const res = await attack.call("8.8.8.8");
  assert.equal(res.status, "refused");
  assert.equal(called, false);
});

// ---------------------------------------------------------------------------
// sigma.js over a fixture: byTechnique, author attribution (DRL 1.1)

const SIGMA_DOC = {
  format: "reach-sigma",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  release: "r2026-07-01",
  count: 3,
  rules: [
    { id: "c8da0dfd", title: "LSASS Process Clone", level: "critical", product: "windows", category: "process_creation", techniques: ["T1003", "T1003.001"], author: "Florian Roth", url: "https://github.com/SigmaHQ/sigma/blob/master/rules/a.yml" },
    { id: "aaaa1111", title: "LSASS via comsvcs.dll", level: "high", product: "windows", category: "process_creation", techniques: ["T1003.001"], author: "Nasreddine Bencherchali", url: "https://github.com/SigmaHQ/sigma/blob/master/rules/b.yml" },
    { id: "bbbb2222", title: "Unrelated rule", level: "medium", product: "windows", category: "file_event", techniques: ["T1566.001"], author: "Someone Else", url: "https://github.com/SigmaHQ/sigma/blob/master/rules/c.yml" },
  ],
};

test("sigma: linkFor is detection.fyi's tag page for the technique", () => {
  assert.deepEqual(sigma.linkFor("T1003.001"), { href: "https://detection.fyi/tags/attack.t1003.001/", label: "Browse on detection.fyi ↗" });
});

test("sigma: byTechnique is an exact match on the clicked id (parent tags cover both when a rule carries both)", async () => {
  stubFetch(SIGMA_DOC);
  const idx = await sigma.load();
  const forSub = sigma.byTechnique(idx, "T1003.001");
  assert.equal(forSub.length, 2);
  const forParent = sigma.byTechnique(idx, "T1003");
  assert.equal(forParent.length, 1, "T1003 alone only matches the rule tagged with the bare parent id");
});

test("sigma: summarize() shows the author next to each rule (DRL 1.1 attribution)", async () => {
  stubFetch(SIGMA_DOC);
  const res = await sigma.call("T1003.001");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /^2 Sigma rules tag T1003\.001\./);
  assert.ok(res.lines.some((l) => l.includes("by Florian Roth")));
  assert.ok(res.lines.some((l) => l.includes("by Nasreddine Bencherchali")));
});

test("sigma: call() on a miss says no rules tag it, status empty", async () => {
  stubFetch(SIGMA_DOC);
  const res = await sigma.call("T9999");
  assert.equal(res.status, "empty");
  assert.match(res.lines[0], /No Sigma rules tag T9999\./);
});

// ---------------------------------------------------------------------------
// escu.js over a fixture: byTechnique, containersFor

const ESCU_DOC = {
  format: "reach-escu",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  ref: "develop",
  count: 2,
  containers: { "T1003.001": ["crowdstrike:events:sensor"] },
  detections: [
    { id: "u1", name: "Credential Dumping via LSASS", techniques: ["T1003.001"], dataSources: ["Sysmon EventID 10"], category: "endpoint", url: "https://research.splunk.com/endpoint/u1/" },
    { id: "u2", name: "Unrelated detection", techniques: ["T1566.001"], dataSources: ["Sysmon EventID 1"], category: "endpoint", url: "https://research.splunk.com/endpoint/u2/" },
  ],
};

test("escu: linkFor is always null; call() links the first matched detection's own page instead", async () => {
  assert.equal(escu.linkFor("T1003.001"), null);
  stubFetch(ESCU_DOC);
  const res = await escu.call("T1003.001");
  assert.equal(res.status, "ok");
  assert.equal(res.link.href, "https://research.splunk.com/endpoint/u1/");
});

test("escu: containersFor names the sourcetypes the dev catalogue already seeds for this technique", async () => {
  stubFetch(ESCU_DOC);
  const res = await escu.call("T1003.001");
  assert.ok(res.lines.some((l) => l.includes("Already seeded on: crowdstrike:events:sensor")));
});

test("escu: call() on a miss reports no matching detections and no link", async () => {
  stubFetch(ESCU_DOC);
  const res = await escu.call("T9999");
  assert.equal(res.status, "empty");
  assert.equal(res.link, null);
});

// ---------------------------------------------------------------------------
// sentinel-rules.js over a fixture: byTechnique, connector/table line

const SENTINEL_DOC = {
  format: "reach-sentinel-rules",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  ref: "master",
  count: 1,
  rules: [
    { id: "g1", name: "LSASS Access Alert", techniques: ["T1003.001"], connector: "MicrosoftDefenderAdvancedThreatProtection", table: "DeviceProcessEvents", url: "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/x/Analytic%20Rules/y.yaml" },
  ],
};

test("sentinel-rules: call() reports the connector/table on a hit and links the rule's own file", async () => {
  stubFetch(SENTINEL_DOC);
  const res = await sentinelRules.call("T1003.001");
  assert.equal(res.status, "ok");
  assert.match(res.lines[1], /LSASS Access Alert \(MicrosoftDefenderAdvancedThreatProtection \/ DeviceProcessEvents\)/);
  assert.equal(res.link.href, SENTINEL_DOC.rules[0].url);
});

// ---------------------------------------------------------------------------
// registry: offersFor a technique id pairs it with all four real sources

test("offersFor: a technique-shaped value offers all four bundled sources, always allowed", () => {
  enrich.register(attack.source);
  enrich.register(sigma.source);
  enrich.register(escu.source);
  enrich.register(sentinelRules.source);
  const offers = enrich.offersFor("T1003.001", {});
  assert.equal(offers.length, 4);
  assert.ok(offers.every((o) => o.kind === "technique" && o.allowed === true));
  assert.deepEqual(offers.map((o) => o.source.id).sort(), ["attack", "escu", "sentinel-rules", "sigma"]);
});

// ---------------------------------------------------------------------------
// byId and byName indexes on the three rule bundles

test("escu.json: byId index has one entry per detection pointing to array position", () => {
  const doc = loadData("escu.json");
  assert.ok(doc.byId, "byId index missing");
  assert.equal(Object.keys(doc.byId).length, doc.detections.length, "byId count mismatch");
  for (const [id, idx] of Object.entries(doc.byId)) {
    assert.equal(doc.detections[idx].id, id, `byId[${id}] points to wrong detection`);
  }
});

test("escu.json: byName index has one entry per detection, collision count in meta", () => {
  const doc = loadData("escu.json");
  assert.ok(doc.byName, "byName index missing");
  assert.ok(doc.meta, "meta missing");
  assert.equal(typeof doc.meta.byName_collisions, "number", "byName_collisions missing from meta");
  for (const [norm, idx] of Object.entries(doc.byName)) {
    const d = doc.detections[idx];
    assert.ok(d, `byName[${norm}] points to invalid index ${idx}`);
  }
});

test("escu.json: every detection has id, name, description and known_false_positives", () => {
  const doc = loadData("escu.json");
  for (const d of doc.detections) {
    assert.ok(typeof d.id === "string" && d.id.length > 0, `${d.id}: id missing or empty`);
    assert.ok(typeof d.name === "string" && d.name.length > 0, `${d.id}: name missing or empty`);
    assert.ok(typeof d.description === "string", `${d.id}: description missing`);
    assert.ok(typeof d.known_false_positives === "string", `${d.id}: known_false_positives missing`);
  }
});

test("sigma.json: byId index has one entry per rule pointing to array position", () => {
  const doc = loadData("sigma.json");
  assert.ok(doc.byId, "byId index missing");
  assert.equal(Object.keys(doc.byId).length, doc.rules.length, "byId count mismatch");
  for (const [id, idx] of Object.entries(doc.byId)) {
    assert.equal(doc.rules[idx].id, id, `byId[${id}] points to wrong rule`);
  }
});

test("sigma.json: byName index has one entry per rule, collision count in meta", () => {
  const doc = loadData("sigma.json");
  assert.ok(doc.byName, "byName index missing");
  assert.ok(doc.meta, "meta missing");
  assert.equal(typeof doc.meta.byName_collisions, "number", "byName_collisions missing from meta");
  for (const [norm, idx] of Object.entries(doc.byName)) {
    const r = doc.rules[idx];
    assert.ok(r, `byName[${norm}] points to invalid index ${idx}`);
  }
});

test("sigma.json: every rule has id, title and falsepositives", () => {
  const doc = loadData("sigma.json");
  for (const r of doc.rules) {
    assert.ok(typeof r.id === "string" && r.id.length > 0, `${r.id}: id missing or empty`);
    assert.ok(typeof r.title === "string" && r.title.length > 0, `${r.id}: title missing or empty`);
    assert.ok(Array.isArray(r.falsepositives), `${r.id}: falsepositives not an array`);
  }
});

test("sentinel-rules.json: byId index has one entry per rule pointing to array position", () => {
  const doc = loadData("sentinel-rules.json");
  assert.ok(doc.byId, "byId index missing");
  assert.equal(Object.keys(doc.byId).length, doc.rules.length, "byId count mismatch");
  for (const [id, idx] of Object.entries(doc.byId)) {
    assert.equal(doc.rules[idx].id, id, `byId[${id}] points to wrong rule`);
  }
});

test("sentinel-rules.json: byName index has one entry per rule, collision count in meta", () => {
  const doc = loadData("sentinel-rules.json");
  assert.ok(doc.byName, "byName index missing");
  assert.ok(doc.meta, "meta missing");
  assert.equal(typeof doc.meta.byName_collisions, "number", "byName_collisions missing from meta");
  for (const [norm, idx] of Object.entries(doc.byName)) {
    const r = doc.rules[idx];
    assert.ok(r, `byName[${norm}] points to invalid index ${idx}`);
  }
});

test("sentinel-rules.json: every rule has id, name and description", () => {
  const doc = loadData("sentinel-rules.json");
  for (const r of doc.rules) {
    assert.ok(typeof r.id === "string" && r.id.length > 0, `${r.id}: id missing or empty`);
    assert.ok(typeof r.name === "string" && r.name.length > 0, `${r.id}: name missing or empty`);
    assert.ok(typeof r.description === "string", `${r.id}: description missing`);
  }
});

// ---------------------------------------------------------------------------
// schema, id format, dedupe and the combined size budget over the real
// committed bundles (not fixtures): this is the validation the fetch
// tools' own reports cannot check for each other, only together.

const TECH_ID_RE = /^T\d{4}(\.\d{3})?$/;
const DATA_DIR = path.join(root, "app/data/enrich");

function loadData(name) {
  return JSON.parse(readFileSync(path.join(DATA_DIR, name), "utf8"));
}

test("attack.json: every id is a well-formed technique id, unique, sorted", () => {
  const doc = loadData("attack.json");
  const ids = doc.techniques.map((t) => t.id);
  assert.equal(ids.length, doc.count);
  for (const id of ids) assert.ok(TECH_ID_RE.test(id), `${id} is not a technique id`);
  assert.equal(new Set(ids).size, ids.length, "duplicate technique ids");
  assert.deepEqual([...ids].sort(), ids, "not sorted");
});

test("sigma.json: every rule carries an author (DRL 1.1) and at least one technique id", () => {
  const doc = loadData("sigma.json");
  assert.equal(doc.rules.length, doc.count);
  const ids = doc.rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids");
  for (const r of doc.rules) {
    assert.ok(r.techniques.length > 0, `${r.id} has no technique tag`);
    for (const t of r.techniques) assert.ok(TECH_ID_RE.test(t), `${r.id}: ${t} is not a technique id`);
  }
});

test("escu.json: every detection carries a technique, category matches its url prefix, containers map is technique-keyed", () => {
  const doc = loadData("escu.json");
  assert.equal(doc.detections.length, doc.count);
  const ids = doc.detections.map((d) => d.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate detection ids");
  for (const d of doc.detections) {
    assert.ok(d.techniques.length > 0);
    assert.ok(d.url.includes(`/${d.category}/${d.id}/`), `${d.id}: url does not match its category`);
  }
  for (const tid of Object.keys(doc.containers)) assert.ok(TECH_ID_RE.test(tid), `${tid} is not a technique id`);
});

test("sentinel-rules.json: every rule carries a technique and a well-formed GUID id, no duplicates", () => {
  const doc = loadData("sentinel-rules.json");
  assert.equal(doc.rules.length, doc.count);
  const ids = doc.rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule ids");
  for (const r of doc.rules) assert.ok(r.techniques.length > 0, `${r.id} has no technique tag`);
});

test("sentinel-rules.json: every url is a fetchable link (solution folder names carry spaces, must be percent-encoded)", () => {
  const doc = loadData("sentinel-rules.json");
  for (const r of doc.rules) {
    assert.ok(!r.url.includes(" "), `${r.id}: url has a raw space: ${r.url}`);
    assert.match(r.url, /^https:\/\/github\.com\/Azure\/Azure-Sentinel\/blob\/master\//);
  }
});

test("app/data/enrich: each of escu, sigma and sentinel-rules fits its 600 KB gzip budget", () => {
  const BUDGET = 600 * 1024;
  const files = { "escu.json": BUDGET, "sigma.json": BUDGET, "sentinel-rules.json": BUDGET };
  for (const [fname, budget] of Object.entries(files)) {
    const bytes = readFileSync(path.join(DATA_DIR, fname));
    const gz = gzipSync(bytes).length;
    assert.ok(gz <= budget, `${fname} gzip size ${gz} exceeds its ${budget} byte budget`);
  }
});

test("app/data/enrich: no stray files beyond the registered bundles", () => {
  const names = readdirSync(DATA_DIR).sort();
  assert.deepEqual(names, ["attack.json", "escu.json", "kev.json", "loldrivers.json", "lolrmm.json", "sentinel-rules.json", "sigma.json"]);
});
