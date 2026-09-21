// The seeded runbook on Sentinel (app/lib/runbooks.js seedFor): a
// SecurityAlert row joins the analytic-rule bundle by AlertName, the seed
// carries the description and no false-positive step (the Sentinel rule
// schema has no such field), the pivots are KQL edges bound from the
// row's Entities list, and a renamed rule is walked, not seeded.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as catalogue from "../app/lib/catalogue.js";
import * as runbooks from "../app/lib/runbooks.js";

await catalogue.load();
const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));

test("a SecurityAlert row seeds from the Sentinel analytic rules by AlertName: description, no false-positive step, KQL pivots from Entities, the close", async () => {
  const row = rows.sentinel.security_alert;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "sentinel"), { row, platform: "sentinel" });
  assert.equal(rb.seeded_from.source, "sentinel-rules");
  assert.equal(rb.seeded_from.label, "seeded from Sentinel analytic rules");
  assert.equal(rb.title, "GitLab - Brute-force Attempts");
  assert.match(rb.description, /^This query relies on GitLab/, "the bundle's quoting is stripped");
  assert.deepEqual(rb.techniques, ["T1110"]);
  assert.deepEqual(rb.false_positives, [], "the Sentinel rule schema carries no false-positive field");
  const kinds = rb.steps.map((s) => s.kind);
  assert.equal(kinds[0], "confirm");
  assert.equal(kinds[kinds.length - 1], "close");
  assert.ok(!kinds.includes("false_positive"));
  const pivots = rb.steps.filter((s) => s.kind === "pivot");
  assert.ok(pivots.length >= 3, `pivot steps: ${pivots.length}`);
  for (const s of pivots) assert.ok(s.pivot.edge.kql && Array.isArray(s.pivot.edge.kql.lines), `${s.id} renders KQL`);
  const fields = new Set(pivots.map((s) => s.entity.field));
  assert.ok(fields.has("Entities.Address") && fields.has("Entities.Name") && fields.has("Entities.HostName"));
  assert.equal(pivots.find((s) => s.entity.field === "Entities.HostName").pivot.params.value, "WEB01");
  assert.equal(rb.bound, pivots.length);
  assert.match(rb.steps[kinds.length - 1].why, /your own call/, "with no false-positive condition the close says so");
});

test("the close step's primary entity on Sentinel is the row entity carrying the CompromisedEntity value, the field the pack pivots bind from; the literal column only when no entity carries it", async () => {
  const row = rows.sentinel.security_alert;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "sentinel"), { row, platform: "sentinel" });
  assert.deepEqual(runbooks.primaryEntity(rb, row), { field: "Entities.Address", value: "10.1.2.3", type: "source_ip" });
  assert.deepEqual(runbooks.primaryEntity(rb, { ...row, CompromisedEntity: "web01" }), { field: "Entities.HostName", value: "WEB01", type: "hostname" }, "matched by value, not the first entry; the list's spelling is kept");
  assert.deepEqual(runbooks.primaryEntity(rb, { ...row, Computer: "WEB01", CompromisedEntity: "WEB01" }), { field: "Computer", value: "WEB01", type: "hostname" }, "a plain column carrying the value is the field the pivots bind from");
  assert.deepEqual(runbooks.primaryEntity(rb, rows.sentinel.renamed_alert), { field: "CompromisedEntity", value: "WEB01", type: null });
  assert.deepEqual(runbooks.primaryEntity(rb, { ...row, CompromisedEntity: "10.9.9.9" }), { field: "CompromisedEntity", value: "10.9.9.9", type: null }, "a value no entry carries keeps the column name");
});

test("a renamed analytics rule is walked, not seeded, and the key is the name the row shows", async () => {
  const row = rows.sentinel.renamed_alert;
  const k = runbooks.ruleKeyFor(row, "sentinel");
  const rb = await runbooks.seedFor(k, { row, platform: "sentinel" });
  assert.equal(rb.seeded_from, null);
  assert.equal(rb.title, "SOC GitLab brute force (tuned)");
  assert.match(rb.steps[0].why, /read the rule's own description in the analytics rule/);
  assert.deepEqual(rb.steps.map((s) => s.kind), ["confirm", "close"], "CompromisedEntity alone has no type, so no pivot");
});

test("the panel link on Sentinel carries the Entities list so a new tab can bind the pivots", () => {
  const row = rows.sentinel.security_alert;
  const link = runbooks.href(runbooks.ruleKeyFor(row, "sentinel"), row);
  assert.match(link, /^#\/runbook\/sentinel-rules%3Aname%3Agitlab%20bruteforce%20attempts\?rule=GitLab%20-%20Brute-force%20Attempts&/);
  assert.match(link, /[?&]Entities=%5B/);
  assert.match(link, /[?&]CompromisedEntity=10\.1\.2\.3/);
});
