// The organisation corpus: the fleet's process binaries measured by one
// discovery search (Splunk over the relay, Sentinel as a recipe step the
// user pastes back), projected by known.js into env.org_corpus under a
// byte budget, and read back by prevalenceOf() for the verdict's fourth
// line. The Splunk side is a stub answering the relay.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

let answer = () => ({ rows: [] });
globalThis.chrome = {
  runtime: {
    id: "test-extension",
    lastError: null,
    sendMessage(msg, cb) {
      Promise.resolve().then(() => cb({ ok: true, ...answer(msg) }));
    },
  },
};

const store = await import("../app/lib/store.js");
const layer = await import("../app/lib/layer.js");
const discovery = await import("../app/lib/discovery.js");
const recipe = await import("../app/lib/recipe.js");
const known = await import("../app/lib/known.js");
const { parse } = await import("../app/lib/intake.js");
const { fleetLine, verdictModel } = await import("../app/lib/popup-ui.js");
assert.equal(store.backend(), "memory");

const FIXTURE = JSON.parse(await readFile(new URL("./fixtures/org-corpus-rows.json", import.meta.url), "utf8"));
const ORIGIN = "https://splunk.test";
const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
const CONTACTSD = "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9";
const SVCHOST = "9f2c0b1e6a1d4c3b8e7f6a5d4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a392817";

beforeEach(async () => {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
});

test("the fleet corpus SPL is one fixed stats over mac and windows process events, the signing id filled before the stats so windows rows survive the by clause", () => {
  assert.equal(
    discovery.orgCorpusSpl({ index: "crowdstrike" }),
    'search index=crowdstrike sourcetype=crowdstrike:events:sensor event_simpleName=ProcessRollup2 (event_platform=Mac OR event_platform=Win) SHA256HashData=* | eval SigningId=coalesce(SigningId, "-") | stats dc(aid) as hosts, count as events, min(_time) as first_seen, max(_time) as last_seen by SHA256HashData, ImageFileName, SigningId, event_platform | rename SHA256HashData as sha256, ImageFileName as path, SigningId as signing_id, event_platform as platform | sort 20000 - hosts, - last_seen',
  );
  assert.ok(discovery.orgCorpusSpl({ index: ["main", "cs"] }).startsWith("search (index=main OR index=cs) sourcetype=crowdstrike:events:sensor"));
  const evil = discovery.orgCorpusSpl({ sourcetype: 'x" | delete', top: 10 ** 9 });
  assert.ok(evil.includes('sourcetype="x\\" | delete"'));
  assert.ok(evil.endsWith(`| sort ${known.ORG_CORPUS_MAX_ROWS} - hosts, - last_seen`), "the row cap is the corpus's own");
});

test("the fleet corpus KQL is one fixed summarize over the Falcon table, reading a SigningId or SourceEventTime column the table lacks as empty or TimeGenerated", () => {
  assert.equal(
    recipe.orgCorpusQuery({ table: "ReachCrowdStrike_CL", window: "7d" }),
    [
      "ReachCrowdStrike_CL",
      "| where TimeGenerated > ago(7d)",
      '| where EventSimpleName == "ProcessRollup2" and EventPlatform in ("Mac", "Win") and isnotempty(SHA256HashData)',
      '| extend signing_id = tostring(column_ifexists("SigningId", "")), seen = todatetime(column_ifexists("SourceEventTime", TimeGenerated))',
      "| summarize hosts = dcount(Aid), events = count(), first_seen = min(seen), last_seen = max(seen) by sha256 = tostring(SHA256HashData), path = tostring(ImageFileName), signing_id, platform = tostring(EventPlatform)",
      "| top 20000 by hosts desc",
    ].join("\n"),
  );
  assert.throws(() => recipe.orgCorpusQuery({ table: "T; bad" }), /identifier/);
});

test("the projection sorts most widespread first, normalises times and the '-' signing id, and cuts to the row cap then the byte budget, counting what it cut", () => {
  const doc = known.projectOrgCorpus(FIXTURE.splunk, { at: "2026-09-20T00:00:00Z", window: "-30d", index: "*", sourcetype: "crowdstrike:events:sensor", source: "splunk" });
  assert.deepEqual(doc.columns, [...known.ORG_CORPUS_COLUMNS]);
  assert.equal(doc.received, 4);
  assert.equal(doc.kept, 4);
  assert.equal(doc.pruned, 0);
  assert.deepEqual(doc.rows[0], [SVCHOST, "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe", "", "Win", 310, 120544, 1782864000, 1789776000]);
  assert.equal(doc.rows[1][0], CONTACTSD);
  assert.equal(doc.rows[1][2], "com.apple.contactsd");
  assert.equal(doc.rows[3][4], 1, "the singleton is last");
  assert.equal(doc.maxRows, undefined, "the caps are not stored");

  const capped = known.projectOrgCorpus(FIXTURE.splunk, { at: "x", window: "-30d", source: "splunk", maxRows: 2 });
  assert.equal(capped.kept, 2);
  assert.equal(capped.pruned, 2);
  assert.deepEqual(capped.rows.map((r) => r[4]), [310, 42]);

  const many = Array.from({ length: 40 }, (_, i) => ({ ...FIXTURE.splunk[i % 4], sha256: String(i).padStart(64, "0"), hosts: 1000 - i }));
  const budget = known.projectOrgCorpus(many, { at: "x", window: "-30d", source: "splunk", maxBytes: 2000 });
  assert.ok(budget.kept < 40 && budget.kept > 0, `kept ${budget.kept}`);
  assert.equal(budget.pruned, 40 - budget.kept);
  assert.ok(layer.bytes(budget) <= 2000, `${layer.bytes(budget)} bytes`);
  assert.deepEqual(budget.rows.map((r) => r[4]).slice(0, 3), [1000, 999, 998], "the most widespread survive the cut");

  const junk = known.projectOrgCorpus([null, { hosts: 3 }, { sha256: "AB", hosts: "x" }], { at: "x" });
  assert.deepEqual(junk.rows, [["ab", "", "", "", 0, 0, null, null]]);
});

test("prevalenceOf matches on the strongest key given, answers a floor over several rows of one hash, and a miss says whether the corpus was complete", () => {
  const doc = known.projectOrgCorpus(FIXTURE.splunk, { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk" });
  assert.equal(known.prevalenceOf({ sha256: CONTACTSD }), null, "no corpus, no answer");
  assert.equal(known.prevalenceOf({ sha256: CONTACTSD }, { rows: "no" }), null);

  const hit = known.prevalenceOf({ sha256: CONTACTSD.toUpperCase(), signing_id: "com.apple.contactsd" }, doc);
  assert.equal(hit.key, "sha256");
  assert.equal(hit.hosts, 42);
  assert.equal(hit.rows, 1);
  assert.equal(hit.first_seen, 1788220800);
  assert.equal(hit.last_seen, 1789776000);
  assert.equal(hit.window, "-30d");
  assert.equal(hit.complete, true);

  const two = known.prevalenceOf({ sha256: SVCHOST }, doc);
  assert.equal(two.rows, 2, "the same hash at two volumes");
  assert.equal(two.hosts, 310, "the widest row, not the sum");
  assert.equal(two.first_seen, 1782864000);

  assert.equal(known.prevalenceOf({ signing_id: "com.apple.contactsd", path: "/System/Library/Frameworks/Contacts.framework/Support/contactsd" }, doc).key, "signing_id+path");
  assert.equal(known.prevalenceOf({ signing_id: "com.apple.contactsd", path: "/tmp/contactsd" }, doc).rows, 0, "the pair must match, not either");
  assert.equal(known.prevalenceOf({ path: "/Users/dev/Downloads/updater" }, doc).hosts, 1);
  assert.equal(known.prevalenceOf({ signing_id: "com.example.updater" }, doc).key, "signing_id");

  const miss = known.prevalenceOf({ sha256: "00".repeat(32) }, doc);
  assert.equal(miss.rows, 0);
  assert.equal(miss.hosts, 0);
  assert.equal(miss.complete, true);
  const none = known.prevalenceOf({}, doc);
  assert.equal(none.key, null, "nothing to match on");

  const cut = known.projectOrgCorpus(FIXTURE.splunk, { at: "x", window: "-30d", source: "splunk", maxRows: 2 });
  assert.equal(known.prevalenceOf({ sha256: "00".repeat(32) }, cut).complete, false, "a miss against a cut corpus is not a miss");
  assert.equal(known.prevalenceOf({ sha256: SVCHOST }, cut).complete, true, "a hit is a hit");
});

test("prevalenceOf over several environments takes the most hosts, and a miss is complete only when every corpus is", () => {
  const a = known.projectOrgCorpus(FIXTURE.splunk, { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk" });
  const b = known.projectOrgCorpus(FIXTURE.sentinel, { at: "2026-09-19T00:00:00Z", window: "30d", source: "sentinel", maxRows: 1 });
  const hit = known.prevalenceOf({ sha256: CONTACTSD }, [b, a]);
  assert.equal(hit.hosts, 42, "the Splunk fleet saw it on more hosts");
  assert.equal(hit.window, "-30d");
  assert.equal(known.prevalenceOf({ sha256: SVCHOST }, [a, b]).hosts, 310);
  const miss = known.prevalenceOf({ sha256: "00".repeat(32) }, [a, b]);
  assert.equal(miss.rows, 0);
  assert.equal(miss.complete, false, "b was cut to one row");
  assert.equal(known.prevalenceOf({ sha256: "00".repeat(32) }, [a]).complete, true);
  assert.equal(known.prevalenceOf({ sha256: CONTACTSD }, []), null);
});

test("the fleet line says seen on N of your hosts with the first date, at least N when the hash sits at several paths, not seen elsewhere when the corpus is complete, cut to budget when it is not", () => {
  const doc = known.projectOrgCorpus(FIXTURE.splunk, { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk" });
  assert.equal(fleetLine(known.prevalenceOf({ sha256: CONTACTSD }, doc)), "Seen on 42 of your hosts, first 2026-09-01");
  assert.equal(fleetLine(known.prevalenceOf({ sha256: SVCHOST }, doc)), "Seen on at least 310 of your hosts, first 2026-07-01");
  assert.equal(fleetLine(known.prevalenceOf({ path: "/Users/dev/Downloads/updater" }, doc)), "Seen on 1 of your hosts, first 2026-09-18");
  assert.equal(fleetLine(known.prevalenceOf({ sha256: "00".repeat(32) }, doc)), "Not seen elsewhere in your fleet (the last 30d of process events)");
  const all = known.projectOrgCorpus(FIXTURE.splunk, { at: "x", window: "0", source: "splunk" });
  assert.equal(fleetLine(known.prevalenceOf({ sha256: "00".repeat(32) }, all)), "Not seen elsewhere in your fleet (all time of process events)");
  const cut = known.projectOrgCorpus(FIXTURE.splunk, { at: "x", window: "-30d", source: "splunk", maxRows: 2 });
  assert.equal(fleetLine(known.prevalenceOf({ sha256: "00".repeat(32) }, cut)), "Not among the 2 most widespread binaries in your fleet (corpus cut to budget)");
  assert.equal(fleetLine(null), null, "no corpus, no line");
  assert.equal(fleetLine(known.prevalenceOf({}, doc)), null, "nothing to match on, no line");
  for (const line of [fleetLine(known.prevalenceOf({ sha256: CONTACTSD }, doc)), fleetLine(known.prevalenceOf({ sha256: "00".repeat(32) }, cut))]) assert.ok(!line.includes(String.fromCharCode(0x2014)), "no em dashes");
});

test("verdictModel carries the fleet line as a fourth field beneath the tier, and none without a corpus", () => {
  const doc = known.projectOrgCorpus(FIXTURE.splunk, { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk" });
  const verdict = { tier: "unknown", evidence: ["signing id com.example.updater not in the corpus for build 25G83"], corpus: { platform: "macos", build: "25G83", os_version: "26.6.2" } };
  const input = { sha256: "4d1c8a2b9e0f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b", signing_id: "com.example.updater", path: "/Users/dev/Downloads/updater" };
  const m = verdictModel({ verdict, input, prevalence: known.prevalenceOf(input, doc) });
  assert.equal(m.tier, "unknown");
  assert.equal(m.headline, "Not in any known-good corpus");
  assert.equal(m.fleet, "Seen on 1 of your hosts, first 2026-09-18");
  assert.equal(verdictModel({ verdict, input }).fleet, null);
});

test("Splunk: the fleet baseline click runs the search through the relay with the window as the job's earliest and writes env.org_corpus, leaving the sourcetype records alone", async () => {
  const seen = [];
  answer = (msg) => {
    seen.push(msg);
    return { rows: FIXTURE.splunk };
  };
  const r = await discovery.orgCorpus(ORIGIN, { index: "cs", earliest: "-7d" });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].type, "reach:discover:run");
  assert.equal(seen[0].origin, ORIGIN);
  assert.equal(seen[0].earliest, "-7d");
  assert.equal(seen[0].spl, discovery.orgCorpusSpl({ index: "cs" }));
  assert.equal(r.doc.kept, 4);
  assert.equal(r.doc.source, "splunk");
  assert.equal(r.doc.index, "cs");
  assert.equal(r.doc.window, "-7d");
  assert.equal(r.doc.sourcetype, "crowdstrike:events:sensor");
  assert.equal(r.notice, "");
  const env = await layer.read(ORIGIN);
  assert.deepEqual(env.org_corpus, r.doc);
  assert.deepEqual(env.sourcetypes, {}, "the corpus is the environment's, not a sourcetype's");
  assert.equal(known.prevalenceOf({ sha256: CONTACTSD }, env.org_corpus).hosts, 42);
});

test("Sentinel: the fleet baseline is a recipe step for each Falcon table, and its pasted envelope writes the same env.org_corpus shape", async () => {
  const declared = Object.fromEntries(recipe.ORG_CORPUS_COLUMNS_NEEDED.map((c) => [c, { declared: { type: "string" } }]));
  await layer.update(RID, (e) => {
    e.sourcetypes.ReachCrowdStrike_CL = { indexes: [], count: 0, fields: declared };
    e.sourcetypes.CrowdStrike_Secondary_Data_CL = { indexes: [], count: 0, fields: { Aid: { declared: { type: "string" } }, SHA256HashData: { declared: { type: "string" } } } };
    e.sourcetypes.SigninLogs = { indexes: [], count: 0, fields: {} };
  });
  const env = await layer.read(RID);
  const steps = recipe.orgCorpusSteps(env);
  const step = steps.find((s) => s.id === "orgCorpus:ReachCrowdStrike_CL");
  assert.ok(step, "one fleet step per table whose schema carries every column the query reads");
  assert.deepEqual(steps.filter((s) => s.step === "orgCorpus").map((s) => s.params.table), ["ReachCrowdStrike_CL"], "not the inventory table that only shares a name and a hash column");
  assert.deepEqual(recipe.orgCorpusTables({ sourcetypes: {} }, { falconTables: ["ReachCrowdStrike_CL", "bad name"] }), ["ReachCrowdStrike_CL"], "a pack-named table qualifies when it is a table name");
  assert.deepEqual(recipe.orgCorpusSteps({ sourcetypes: {} }, { falconTables: ["ReachCrowdStrike_CL"] }).filter((s) => s.step === "orgCorpus").map((s) => s.id), ["orgCorpus:ReachCrowdStrike_CL"]);
  assert.equal(step.params.window, "30d");
  assert.equal(step.bare, recipe.orgCorpusQuery({ table: "ReachCrowdStrike_CL", window: "30d" }));
  assert.match(step.label, /^Fleet baseline: /);
  assert.equal(recipe.stepId("orgCorpus", step.params), step.id);
  assert.ok(recipe.STEPS.includes("orgCorpus"));
  assert.deepEqual(recipe.steps(env).filter((s) => s.step === "orgCorpus"), [], "the generic step list carries no fleet step: it lives on the sourcetype page");

  const r = await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "orgCorpus", env: "dev", q: step.q }, params: step.params, rows: FIXTURE.sentinel })), { expect: step });
  assert.deepEqual(r.verdicts, []);
  assert.deepEqual(r.written, { table: "ReachCrowdStrike_CL", rows: 2, pruned: 0 });
  const stored = (await layer.read(RID)).org_corpus;
  assert.equal(stored.source, "sentinel");
  assert.equal(stored.table, "ReachCrowdStrike_CL");
  assert.equal(stored.window, "30d");
  assert.deepEqual(stored.columns, [...known.ORG_CORPUS_COLUMNS]);
  assert.deepEqual(stored.rows[0], [SVCHOST, "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe", "", "Win", 55, 20011, 1787270400, 1789819200]);
  assert.equal(fleetLine(known.prevalenceOf({ sha256: CONTACTSD }, stored)), "Seen on 7 of your hosts, first 2026-09-01");
  assert.equal(recipe.orgCorpusSteps(await layer.read(RID)).find((s) => s.id === step.id).status, "imported");
  await assert.rejects(() => recipe.apply(RID, parse("a,b\n1,2\n"), { step: "orgCorpus", params: { table: "ReachCrowdStrike_CL" } }), /lack the columns sha256, hosts/);
});

test("over the environment bound the organisation corpus goes first, and the notice names the button that measures it again on each platform", async () => {
  const seed = (e) => {
    e.org_corpus = known.projectOrgCorpus(FIXTURE.splunk, { at: "x", window: "-30d", source: "splunk" });
    e.sourcetypes["a:feed"] = { indexes: ["main"], count: 1, fields: {}, decodes: { code: { lookup: "codes", values: { a: "b" }, read_at: "2026-09-10T00:00:00Z" } } };
  };
  let r = await layer.update(ORIGIN, seed, { envMaxBytes: 1_000_000 });
  assert.equal(r.notice, "");
  assert.ok(r.env.org_corpus);
  const full = layer.bytes(r.env);
  r = await layer.update(ORIGIN, seed, { envMaxBytes: full - 100 });
  assert.equal(r.env.org_corpus, undefined);
  assert.ok(r.env.sourcetypes["a:feed"].decodes.code, "the decode table stays while the corpus suffices");
  assert.equal(r.notice, `${ORIGIN} was over its ${Math.round((full - 100) / 100000) / 10} MB bound: dropped the organisation corpus ("Baseline: what my fleet runs" on the Falcon sourcetype page measures it again).`);
  r = await layer.update(RID, seed, { envMaxBytes: full - 100 });
  assert.match(r.notice, /dropped the organisation corpus \(importing the fleet baseline step's result again measures it\)/);
});
