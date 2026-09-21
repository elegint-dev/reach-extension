// Rule identity off an alert row (app/lib/runbooks.js ruleKeyFor): a
// Splunk row joins ESCU by the detection id first and by the search name
// stripped of its "ESCU - … - Rule" frame second; a Sentinel SecurityAlert
// row joins the analytic-rule bundle by AlertName only, never by AlertType
// (a per-workspace GUID); a Sigma rule id is read wherever a row carries
// one; a plain event row has no key. The rows are tests/fixtures/alert-rows.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { ruleKeyFor, parseKey, keyString, normalizeName, entitiesOf, ALERT_FIELDS, IDENTITY_FIELDS, href } from "../app/lib/runbooks.js";

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const escu = JSON.parse(await readFile(new URL("../app/data/enrich/escu.json", import.meta.url), "utf8"));
const sentinel = JSON.parse(await readFile(new URL("../app/data/enrich/sentinel-rules.json", import.meta.url), "utf8"));

test("a Splunk notable's search_name strips the ESCU frame and keys the bundle by name", () => {
  const k = ruleKeyFor(rows.splunk.notable_search_name, "splunk");
  assert.equal(k.platform, "splunk");
  assert.equal(k.name, "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser");
  assert.equal(k.key, "escu:name:disabled kerberos preauthentication discovery with getaduser");
  assert.ok(k.key.split(":")[2] in escu.byName, "the key is a byName entry of the bundle as projected");
});

test("a detection id on a saved-search row, as a dotted leaf or inside the metadata JSON, keys ESCU by id before any name", () => {
  const leaf = ruleKeyFor(rows.splunk.rest_metadata_leaf, "splunk");
  assert.equal(leaf.key, "escu:id:114c6bfe-9406-11ec-bcce-acde48001122");
  const json = ruleKeyFor(rows.splunk.rest_metadata_json, "splunk");
  assert.equal(json.key, "escu:id:114c6bfe-9406-11ec-bcce-acde48001122");
  assert.ok(json.key.split(":")[2] in escu.byId);
  const both = ruleKeyFor({ ...rows.splunk.rest_metadata_leaf, search_name: rows.splunk.notable_search_name.search_name }, "splunk");
  assert.deepEqual(both.keys.map((x) => x.by), ["id", "name"], "id first, then the name");
});

test("a renamed search keeps a name key that misses the bundle, so the seed says so rather than guessing", () => {
  const k = ruleKeyFor(rows.splunk.renamed_search, "splunk");
  assert.equal(k.name, "SOC - Kerberos PreAuth Discovery (custom)");
  assert.equal(k.keys[0].by, "name");
  assert.ok(!(k.keys[0].value in escu.byName));
});

test("a Sigma rule id on a row is a sigma:id key, and on Splunk the same GUID is tried against ESCU too", () => {
  const k = ruleKeyFor(rows.splunk.sigma_rule_id, "splunk");
  assert.deepEqual(
    k.keys.map(keyString),
    ["escu:id:025c9fe7-db72-49f9-af0d-31341dd7dd57", "sigma:id:025c9fe7-db72-49f9-af0d-31341dd7dd57"],
  );
  const s = ruleKeyFor({ sigma_id: "025C9FE7-DB72-49F9-AF0D-31341DD7DD57" }, "sentinel");
  assert.equal(s.key, "sigma:id:025c9fe7-db72-49f9-af0d-31341dd7dd57", "lower-cased");
});

test("a Sentinel SecurityAlert row keys the rule bundle by AlertName; AlertType and SystemAlertId are never keys", () => {
  const k = ruleKeyFor(rows.sentinel.security_alert, "sentinel");
  assert.equal(k.platform, "sentinel");
  assert.equal(k.name, "GitLab - Brute-force Attempts");
  assert.deepEqual(k.keys, [{ source: "sentinel-rules", by: "name", value: "gitlab bruteforce attempts" }]);
  assert.ok(k.keys[0].value in sentinel.byName);
  for (const x of k.keys) assert.ok(!x.value.includes(rows.sentinel.security_alert.AlertType));
});

test("a plain event row on either platform carries no rule key", () => {
  assert.equal(ruleKeyFor(rows.splunk.plain_event, "splunk"), null);
  assert.equal(ruleKeyFor(rows.sentinel.plain_row, "sentinel"), null);
  assert.equal(ruleKeyFor(null, "splunk"), null);
  assert.equal(ruleKeyFor({}, "sentinel"), null);
});

test("normalizeName is the projection the bundles' byName indexes were built with", () => {
  for (const d of escu.detections.slice(0, 200)) assert.equal(escu.byName[normalizeName(d.name)], escu.detections.indexOf(d), d.name);
  assert.equal(normalizeName("  GitLab - Brute-force  Attempts! "), "gitlab bruteforce attempts");
});

test("a key string round-trips through parseKey, and an unknown source or shape is refused", () => {
  const k = { source: "escu", by: "name", value: "a b c" };
  assert.deepEqual(parseKey(keyString(k)), k);
  assert.equal(parseKey("cortex:id:x"), null);
  assert.equal(parseKey("escu:technique:T1003"), null);
  assert.equal(parseKey(""), null);
});

test("the entities a row carries are typed by field name and read out of Sentinel's Entities list; scope keys are never entities", () => {
  assert.deepEqual(
    entitiesOf(rows.splunk.notable_search_name).map((e) => [e.field, e.type]),
    [["dest", "hostname"], ["user", "user_name"], ["src", "source_ip"], ["aid", "host_id"]],
  );
  assert.deepEqual(
    entitiesOf(rows.sentinel.security_alert).map((e) => [e.field, e.value, e.type]),
    [["Entities.Address", "10.1.2.3", "source_ip"], ["Entities.Name", "jdoe", "user_name"], ["Entities.HostName", "WEB01", "hostname"]],
  );
  assert.deepEqual(entitiesOf({ index: "main", workspace: "ws1", earliest: "-24h" }), []);
  assert.ok(!ALERT_FIELDS.includes("index") && !ALERT_FIELDS.includes("workspace") && !ALERT_FIELDS.includes("earliest"));
});

test("the popups' alert field list carries every identity field of both platforms", () => {
  for (const name of [...IDENTITY_FIELDS.splunk, ...IDENTITY_FIELDS.sentinel]) assert.ok(ALERT_FIELDS.includes(name), name);
  assert.ok(ALERT_FIELDS.includes("Entities") && ALERT_FIELDS.includes("dest") && ALERT_FIELDS.includes("Computer"));
});

test("the panel link carries the key and the row's entities, never a scope key", () => {
  const row = { ...rows.splunk.notable_search_name, index: "main" };
  const k = ruleKeyFor(row, "splunk");
  const link = href(k, row);
  assert.match(link, /^#\/runbook\/escu%3Aname%3A/);
  assert.match(link, /[?&]rule=Disabled%20Kerberos/);
  assert.match(link, /[?&]dest=WIN-DC01/);
  assert.match(link, /[?&]risk_object=WIN-DC01/);
  assert.ok(!/[?&]index=/.test(link));
});
