// The seeded runbook (app/lib/runbooks.js seedFor): from each bundle the
// steps come in one order, confirm the trigger (the rule's description),
// one step per listed false-positive condition, one pivot per pack edge
// leaving a column that carries an entity the row names (parameters bound
// from the row), then the close; every seeded runbook is labelled with the
// bundle it came from, and a rule no bundle carries is not seeded, only
// walked. Splunk here; the Sentinel bundle in runbooks-seed-sentinel.test.js.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as catalogue from "../app/lib/catalogue.js";
import * as runbooks from "../app/lib/runbooks.js";

await catalogue.load();
const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));

test("an ESCU notable seeds from Splunk ESCU: description, one false-positive step per sentence, bound pivots, then the close, in that order", async () => {
  const row = rows.splunk.notable_search_name;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.equal(rb.format, "reach-runbook");
  assert.equal(rb.title, "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser");
  assert.equal(rb.seeded_from.source, "escu");
  assert.equal(rb.seeded_from.label, "seeded from Splunk ESCU");
  assert.equal(rb.seeded_from.id, "114c6bfe-9406-11ec-bcce-acde48001122");
  assert.match(rb.seeded_from.url, /^https:\/\/research\.splunk\.com\//);
  assert.deepEqual(rb.techniques, ["T1558.004"]);
  assert.match(rb.description, /Get-ADUser/);
  const kinds = rb.steps.map((s) => s.kind);
  assert.equal(kinds[0], "confirm");
  assert.equal(kinds[kinds.length - 1], "close");
  assert.deepEqual(kinds.filter((k) => k === "false_positive").length, rb.false_positives.length);
  assert.ok(rb.false_positives.length >= 1);
  assert.match(rb.steps[0].why, /Get-ADUser/, "the confirm step carries the description");
  assert.match(rb.steps[1].why, /Administrators or power users/, "the false-positive step carries the condition");
  const firstPivot = kinds.indexOf("pivot");
  const lastFp = kinds.lastIndexOf("false_positive");
  assert.ok(firstPivot > lastFp, "pivots follow the false-positive checks");
  assert.deepEqual(rb.benign_when.map((b) => b.text), rb.false_positives);
  assert.equal(rb.escalate_when.length, 1);
});

test("pivot steps bind the entity value and the pack's from_field parameters off the row, one step per pack edge, and count as bound", async () => {
  const row = rows.splunk.notable_search_name;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  const pivots = rb.steps.filter((s) => s.kind === "pivot");
  assert.ok(pivots.length >= 3, `pivot steps: ${pivots.length}`);
  assert.equal(rb.bound, pivots.length, "every pivot binds at least the entity value");
  const byField = new Map(pivots.map((s) => [s.entity.field, s]));
  assert.ok(byField.has("dest") && byField.has("user") && byField.has("src"), "each entity the row carries gets a pivot");
  const host = byField.get("dest");
  assert.equal(host.pivot.params.value, "WIN-DC01");
  assert.equal(host.pivot.params.aid, row.aid, "the pack's aid parameter is bound from the row's aid");
  assert.ok(host.pivot.bound.includes("aid"));
  assert.ok(host.pivot.edge.spl && Array.isArray(host.pivot.edge.spl.lines), "a Splunk edge renders SPL");
  const ids = pivots.map((s) => `${s.pivot.packId}/${s.pivot.edge.id}`);
  assert.equal(new Set(ids).size, ids.length, "one step per pack edge");
  for (const s of pivots) assert.ok(!("index" in s.pivot.params) && !("earliest" in s.pivot.params), "scope and time are never bound as step parameters");
});

test("a Sigma rule seeds from Sigma with one step per listed false positive and the level kept out of the steps", async () => {
  const row = rows.splunk.sigma_rule_id;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.equal(rb.seeded_from.source, "sigma", "the GUID is not an ESCU id, so Sigma answers");
  assert.equal(rb.seeded_from.label, "seeded from Sigma");
  assert.equal(rb.title, "Azure Firewall Rule Collection Modified or Deleted");
  assert.equal(rb.false_positives.length, 2);
  assert.equal(rb.steps.filter((s) => s.kind === "false_positive").length, 2);
  assert.match(rb.steps[1].why, /system administrator/);
  assert.ok(rb.steps.some((s) => s.kind === "pivot" && s.entity.field === "user"));
});

test("a page opened on an escu:id key whose GUID is a Sigma rule's still finds it: the other id-keyed bundles are tried", async () => {
  const rb = await runbooks.seedFor("escu:id:025c9fe7-db72-49f9-af0d-31341dd7dd57", { row: {}, platform: "splunk" });
  assert.equal(rb.seeded_from.source, "sigma");
  assert.equal(rb.title, "Azure Firewall Rule Collection Modified or Deleted");
});

test("a Sigma rule whose false positives are only Unknown lists no false-positive step", async () => {
  const rb = await runbooks.seedFor("sigma:id:002bdb95-0cf1-46a6-9e08-d38c128a6127", { row: {}, platform: "splunk" });
  assert.equal(rb.title, "WScript or CScript Dropper - File");
  assert.deepEqual(rb.false_positives, []);
  assert.deepEqual(rb.steps.map((s) => s.kind), ["confirm", "close"]);
  assert.equal(rb.bound, 0);
});

test("a renamed search that no bundle carries is walked, not seeded: no description, the packs' pivots for its entities, the close", async () => {
  const row = rows.splunk.renamed_search;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.equal(rb.seeded_from, null);
  assert.equal(rb.title, "SOC - Kerberos PreAuth Discovery (custom)");
  assert.equal(rb.description, "");
  assert.match(rb.steps[0].why, /not in the bundled rule indexes/);
  assert.deepEqual(rb.false_positives, []);
  assert.ok(rb.steps.some((s) => s.kind === "pivot" && s.entity.field === "dest"));
  assert.equal(rb.steps[rb.steps.length - 1].kind, "close");
});

test("the primary entity a close step acts on is the risk object when the row names one, else the first entity", async () => {
  const row = rows.splunk.notable_search_name;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.deepEqual(runbooks.primaryEntity(rb, row), { field: "dest", value: "WIN-DC01", type: "hostname" });
  assert.deepEqual(runbooks.primaryEntity(rb, { user: "jdoe" }), rb.entities[0]);
  assert.equal(runbooks.primaryEntity({ entities: [] }, {}), null);
});

test("the bundles are read once per session and only on a key: a lookup with no key reads nothing", async () => {
  runbooks.reset();
  let reads = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    reads += 1;
    return realFetch(url);
  };
  try {
    assert.equal(await runbooks.lookup(null), null);
    assert.equal(reads, 0);
    await runbooks.lookup("escu:id:114c6bfe-9406-11ec-bcce-acde48001122");
    await runbooks.lookup("escu:name:disabled kerberos preauthentication discovery with getaduser");
    assert.equal(reads, 1, "one bundle, one read");
    assert.equal(await runbooks.lookup("escu:id:00000000-0000-0000-0000-000000000000"), null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a pivot step's id names the entity field, the pack and the edge: pivot-<field>-<pack id>-<edge id>", async () => {
  const row = rows.splunk.notable_search_name;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.deepEqual(
    rb.steps.map((s) => s.id),
    // The fixture row carries aid, so the two host-events pivots follow the five the spec lists for a row without one.
    ["confirm", "fp-1", "pivot-dest-crowdstrike-falcon-cs_host_by_name", "pivot-user-aws-cloudtrail-ct_iam_target_user", "pivot-src-aws-cloudtrail-ct_source_ip", "pivot-src-aws-cloudtrail-ct_ip_elsewhere", "pivot-src-entra-signin-aad_ip_signins", "pivot-aid-crowdstrike-falcon-cs_host_events", "pivot-aid-crowdstrike-events-cs_host_events", "close"],
  );
});
