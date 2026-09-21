// The runbook band (app/lib/popup-ui.js runbookBlock): drawn only for a
// row that carries a rule key, null otherwise; it names the rule, says
// which bundle seeded it once the bundle lands with the step and bound
// counts, and links the panel page; it sits in HEAD, owned by the runbooks
// module, so both popups place it by the registry and a switched-off
// module removes it from both.
import "./_splunk.js";
import "./_bundle.js";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

const restore = dom.install();
const catalogue = await import("../app/lib/catalogue.js");
const modules = await import("../app/lib/modules.js");
const { runbookBlock, alertFields, ALERT_FIELDS } = await import("../app/lib/popup-ui.js");
const runbooks = await import("../app/lib/runbooks.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const appUrl = (hash) => `chrome-extension://id/index.html?platform=splunk${hash}`;
test("a row without a rule key draws no band", () => {
  assert.equal(runbookBlock({ row: rows.splunk.plain_event, platform: "splunk", appUrl }), null);
  assert.equal(runbookBlock({ row: rows.sentinel.plain_row, platform: "sentinel", appUrl }), null);
  assert.equal(runbookBlock({ row: {}, platform: "splunk", appUrl }), null);
});

test("a Splunk notable row draws the band with the rule name, then the seed source and the counts once the bundle lands", async () => {
  const row = rows.splunk.notable_search_name;
  const el = runbookBlock({ row, platform: "splunk", appUrl });
  assert.ok(el && el.classList.contains("reach-runbook"));
  assert.equal(dom.text(el.querySelector(".reach-row__title")), "Runbook");
  assert.equal(dom.text(el.querySelector(".reach-runbook__name")), "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser");
  const link = el.querySelector(".reach-runbook__open");
  assert.equal(link.attributes.href, appUrl(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row)));
  assert.equal(link.attributes.target, "_blank");
  await el.ready;
  assert.equal(dom.text(el.querySelector(".reach-runbook__source")), "seeded from Splunk ESCU");
  assert.match(dom.text(el.querySelector(".reach-runbook__count")), /^\d+ steps, \d+ bound from this row$/);
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  assert.equal(dom.text(el.querySelector(".reach-runbook__count")), `${rb.steps.length} steps, ${rb.bound} bound from this row`);
});

test("a Sentinel SecurityAlert row draws the band keyed by AlertName, and a renamed rule says it is not in the bundles", async () => {
  const el = runbookBlock({ row: rows.sentinel.security_alert, platform: "sentinel", appUrl: (hash) => `x${hash}` });
  assert.equal(dom.text(el.querySelector(".reach-runbook__name")), "GitLab - Brute-force Attempts");
  assert.match(el.querySelector(".reach-runbook__open").attributes.href, /^x#\/runbook\/sentinel-rules%3Aname%3A/);
  await el.ready;
  assert.equal(dom.text(el.querySelector(".reach-runbook__source")), "seeded from Sentinel analytic rules");
  const renamed = runbookBlock({ row: rows.sentinel.renamed_alert, platform: "sentinel", appUrl: (hash) => `x${hash}` });
  await renamed.ready;
  assert.equal(dom.text(renamed.querySelector(".reach-runbook__source")), "not in the bundled rules");
  assert.equal(dom.text(renamed.querySelector(".reach-runbook__count")), "2 steps, 0 bound from this row");
});

test("alertFields reads the identity and entity fields off a row and nothing else", () => {
  const row = { ...rows.splunk.notable_search_name, ImageFileName: "/bin/ls", index: "main" };
  const got = alertFields((n) => row[n] ?? null);
  assert.equal(got.search_name, row.search_name);
  assert.equal(got.dest, "WIN-DC01");
  assert.ok(!("ImageFileName" in got), "a verdict field is the verdict list's, not this one's");
  assert.ok(!("index" in got), "scope is never read as an alert field");
  for (const k of Object.keys(got)) assert.ok(ALERT_FIELDS.includes(k), k);
});

test("the band is HEAD's, owned by the runbooks module on both platforms, and gone from both while the module is off", async () => {
  assert.ok(modules.HEAD.includes("runbook"));
  assert.equal(modules.bandOwner("runbook").id, "runbooks");
  assert.deepEqual(modules.get("runbooks").platforms, ["splunk", "sentinel"]);
  assert.ok(modules.bands("splunk").includes("runbook") && modules.bands("sentinel").includes("runbook"));
  assert.ok(modules.routes("splunk").includes("runbook") && modules.routes("sentinel").includes("runbook"));
  await modules.setEnabled("runbooks", false);
  assert.ok(!modules.bands("splunk").includes("runbook") && !modules.bands("sentinel").includes("runbook"));
  assert.ok(!modules.routes("splunk").includes("runbook"));
  await modules.setEnabled("runbooks", true);
  const section = await readFile(new URL("../app/lib/click-section.js", import.meta.url), "utf8");
  const context = await readFile(new URL("../app/lib/click-context.js", import.meta.url), "utf8");
  assert.match(section, /on\("runbooks"\)/, "click-section.js gates the band on the module");
  assert.match(section, /ui\.runbookBlock\(/, "click-section.js draws the band");
  assert.match(context, /alertFields\(read\)/, "click-context.js reads the alert fields off the row");
  for (const name of ["value-popup.js", "sentinel-grid.js"]) {
    const src = await readFile(new URL(`../${name}`, import.meta.url), "utf8");
    assert.match(src, /runbooks: (?:on\("runbooks"\)|click\.kind === "value" && lib\.modules\.on\("runbooks", "sentinel"\))/, `${name} asks the context for the alert fields only while the module is on`);
  }
});

after(() => restore());
