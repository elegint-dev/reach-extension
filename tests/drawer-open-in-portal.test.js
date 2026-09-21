// The drawer's open action on Sentinel: "Open in portal ↗" beside Copy KQL
// once the Logs blade has named a workspace, the deep link carrying the
// query; until then a hint that says what gives one, never a dead link.
import "./_sentinel.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as recipe from "../app/lib/recipe.js";
import * as store from "../app/lib/store.js";
import * as layer from "../app/lib/layer.js";
import { drawer } from "../app/components/drawer.js";

dom.install();

const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
const KQL = "ReachCrowdStrike_CL | where SHA256HashData == \"abc\" | take 50";
async function reset() {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.remove(recipe.WORKSPACES_KEY);
}

test("with no workspace known the drawer shows the hint and no link; Copy KQL stays", async () => {
  await reset();
  const d = drawer({ state: "filled", spl: KQL });
  await d.ready();
  const link = d.querySelector(".r-drawer__run");
  const hint = d.querySelector(".r-drawer__runhint");
  assert.equal(link.hidden, true, "no link without a workspace");
  assert.equal(hint.hidden, false);
  assert.match(dom.text(hint), /Open the Logs blade once/);
  assert.equal(dom.text(d.querySelector(".r-drawer__copylabel")), "Copy KQL");
});

test("once the blade named a workspace the link reads Open in portal and opens the Logs blade deep link with the query", async () => {
  await reset();
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  const d = drawer({ state: "filled", spl: KQL });
  await d.ready();
  const link = d.querySelector(".r-drawer__run");
  assert.equal(link.hidden, false, "the link once the workspace is known");
  assert.equal(dom.text(link), "Open in portal ↗");
  assert.equal(d.querySelector(".r-drawer__runhint").hidden, true);
  assert.match(link.href, /^https:\/\/portal\.azure\.com\/#view\/Microsoft_Azure_Monitoring_Logs\/LogsBlade\/resourceId\/.+\/source\/LogsBlade\.AnalyticsShareLinkToQuery\/q\/.+\/timespan\/P1D$/);
  assert.ok(link.href.includes(encodeURIComponent(RID)), "the workspace the blade was seen on");
  // An empty drawer offers nothing to open.
  d.setState("empty");
  await d.ready();
  assert.equal(link.hidden, true);
  assert.equal(d.querySelector(".r-drawer__runhint").hidden, true);
  // A refill re-links; the earlier text's link never lands on the new one.
  d.setState("filled");
  d.setSpl("ReachCrowdStrike_CL | take 1");
  await d.ready();
  assert.equal(link.hidden, false);
  const before = link.href;
  d.setSpl("ReachCrowdStrike_CL | take 2");
  await d.ready();
  assert.notEqual(link.href, before, "the link follows the text");
  await reset();
});
