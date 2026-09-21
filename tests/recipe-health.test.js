// Sentinel feed health is computed between successive pasted inventories
// and profiles, as on Splunk between runs: a table the latest Usage
// inventory did not return is marked missing from that paste, a second
// profile records the columns that came and went, and the table page draws
// the same health chips and the Field changes (N) section (Column changes
// (N) in Sentinel's words) the Splunk sourcetype page does. Platform is
// pinned by the first import.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as recipe from "../app/lib/recipe.js";
import * as store from "../app/lib/store.js";
import * as layer from "../app/lib/layer.js";
import * as discovery from "../app/lib/discovery.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { parse } from "../app/lib/intake.js";
import { PLATFORM } from "../app/lib/platform.js";
import { render } from "../app/views/sourcetype.js";

assert.equal(PLATFORM, "sentinel");
globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });
await catalogue.load();

const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
const TABLE = "ReachCrowdStrike_CL";
const DAY1 = "2026-09-17T23:06:00Z";
const DAY2 = "2026-09-18T23:06:00Z";

async function reset() {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.remove(recipe.WORKSPACES_KEY);
}

const envelope = (step, rows) => JSON.stringify({ meta: { v: 1, step: step.step, env: "dev", gen: new Date().toISOString(), q: step.q }, params: step.params, rows });

const invRow = (table, last) => ({ TenantId: "4f43", DataType: table, Solution: "LogManagement", mb: 0.5, first_seen: "2026-09-10T00:06:00Z", last_seen: last, billable: true });
const stat = (col, n, total) => ({ col, n, d: 2, t: "string", total, row_kind: "stat" });

async function pasteInventory(rows) {
  const env = await recipe.environment(RID);
  const [inv] = recipe.steps(env, { packTables: [TABLE] });
  return recipe.apply(RID, parse(envelope(inv, rows)), { expect: inv });
}

async function pasteSchema(tables) {
  const env = await recipe.environment(RID);
  const sch = recipe.steps(env, { packTables: tables }).find((s) => s.step === "schema");
  const rows = tables.map((T) => ({ T, ColumnName: "TimeGenerated", ColumnType: "datetime" }));
  return recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "schema", env: "dev", q: sch.q }, params: sch.params, rows })), { expect: sch });
}

async function pasteScan(rows) {
  const env = await recipe.environment(RID);
  const scan = recipe.steps(env, { packTables: [TABLE] }).find((s) => s.step === "inventoryScan");
  return recipe.apply(RID, parse(envelope(scan, rows)), { expect: scan });
}

async function pasteProfile(cols, total) {
  const env = await recipe.environment(RID);
  const [prof] = recipe.tableSteps(env, TABLE);
  return recipe.apply(RID, parse(envelope(prof, cols.map((c) => stat(c, total, total)))), { expect: prof });
}

function ctx(params) {
  return { fields, catalogue, route: "sourcetype", params, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules };
}

test("a table the second Usage inventory does not return is marked missing since that paste; one it returns again is cleared, and last_seen follows the latest paste", async () => {
  await reset();
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  await pasteInventory([invRow(TABLE, DAY1), invRow("ReachAzureAD_CL", DAY1)]);
  let env = await recipe.environment(RID);
  assert.equal(env.sourcetypes[TABLE].missing_since, undefined);
  assert.equal(env.sourcetypes[TABLE].runs.length, 1);
  assert.equal(env.sourcetypes[TABLE].runs[0].kind, "inventory");
  assert.equal(env.sourcetypes[TABLE].inventory_window, "30d");

  await pasteInventory([invRow(TABLE, DAY2)]);
  env = await recipe.environment(RID);
  const azure = env.sourcetypes.ReachAzureAD_CL;
  assert.ok(azure.missing_since, "the table the second inventory did not return is marked");
  assert.equal(azure.runs[0].missing, true);
  assert.equal(azure.runs.length, 2);
  assert.equal(layer.epochOf(azure.last_seen), layer.epochOf(DAY1), "its last_seen stays what the last inventory that saw it said");
  const cs = env.sourcetypes[TABLE];
  assert.equal(cs.missing_since, undefined);
  assert.equal(layer.epochOf(cs.last_seen), layer.epochOf(DAY2));
  const hl = discovery.health(azure, new Date(DAY2).getTime() + 3600 * 1000);
  assert.equal(hl.missing, true);
  assert.equal(hl.missingSince, azure.missing_since);
  assert.equal(discovery.health(cs, new Date(DAY2).getTime() + 3600 * 1000).lastSeenAge, 3600);

  // Returned again: the mark clears from the first paste that sees it.
  await pasteInventory([invRow(TABLE, DAY2), invRow("ReachAzureAD_CL", DAY2)]);
  env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.missing_since, undefined);
  assert.equal(env.inventory.window, "30d");
});

test("a table known only from a schema paste is not marked missing by a Usage inventory that never returned it, and rows from the scan step clear a mark", async () => {
  await reset();
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  await pasteInventory([invRow(TABLE, DAY1), invRow("ReachAzureAD_CL", DAY1)]);
  await pasteSchema([TABLE, "ReachCloudTrail_CL"]);
  let env = await recipe.environment(RID);
  assert.ok(env.sourcetypes.ReachCloudTrail_CL, "the schema paste declares the table");
  await pasteInventory([invRow(TABLE, DAY2)]);
  env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachCloudTrail_CL.missing_since, undefined, "never Usage's to miss");
  assert.ok(env.sourcetypes.ReachAzureAD_CL.missing_since, "returned once, dropped now: marked");
  await pasteScan([{ T: "ReachAzureAD_CL", n: 12, first_seen: DAY2, last_seen: DAY2, TenantId: "4f43" }]);
  env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.missing_since, undefined, "rows are arrival, whatever the window");
  assert.equal(env.sourcetypes.ReachAzureAD_CL.count, 12);
});

test("a second pasted profile records the column that went and the one that came against the paste before, and drops the numbers of the column this sample lacks", async () => {
  await reset();
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  await pasteInventory([invRow(TABLE, DAY1)]);
  await pasteProfile(["EventSimpleName", "DesiredAccess", "OldColumn"], 100);
  let env = await recipe.environment(RID);
  assert.equal(env.sourcetypes[TABLE].profile_delta, null, "the first profile has nothing to compare against");
  const firstAt = env.sourcetypes[TABLE].profiled_at;
  assert.equal(env.sourcetypes[TABLE].runs[0].kind, "profile");

  await pasteProfile(["EventSimpleName", "DesiredAccess", "NewColumn"], 100);
  env = await recipe.environment(RID);
  const rec = env.sourcetypes[TABLE];
  assert.deepEqual(rec.profile_delta.added, ["NewColumn"]);
  assert.deepEqual(rec.profile_delta.gone, ["OldColumn"]);
  assert.deepEqual(rec.profile_delta.fill, []);
  assert.equal(rec.profile_delta.previous_at, firstAt);
  assert.equal(rec.profile_delta.at, rec.profiled_at);
  assert.equal(rec.fields.OldColumn, undefined, "a column this sample did not see loses its numbers");
  assert.ok(rec.fields.NewColumn.profile);
  assert.equal(rec.runs.filter((r) => r.kind === "profile").length, 2);
  const hl = discovery.health(rec);
  assert.deepEqual(hl.delta.added, ["NewColumn"]);
  assert.deepEqual(hl.delta.gone, ["OldColumn"]);
});

test("the Sentinel table page draws the health chip and Column changes (N), the registry's word for Field changes, from the pasted inventories and profiles, and missing since when the latest inventory dropped it", async () => {
  await reset();
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  await pasteInventory([invRow(TABLE, DAY1), invRow("ReachAzureAD_CL", DAY1)]);
  await pasteProfile(["EventSimpleName", "DesiredAccess", "OldColumn"], 100);
  await pasteProfile(["EventSimpleName", "DesiredAccess", "NewColumn"], 100);
  await pasteInventory([invRow(TABLE, DAY2)]);
  const restore = dom.install();
  try {
    const el = render(ctx({ name: TABLE }));
    const chips = el.querySelector(".r-title").querySelectorAll(".r-chip").map(dom.text);
    assert.ok(chips.some((c) => /^last seen /.test(c)), `last seen among ${chips.join(", ")}`);
    assert.ok(chips.some((c) => /^measured /.test(c)), `measured among ${chips.join(", ")}`);
    assert.equal(chips.some((c) => /missing since/.test(c)), false);
    const h2s = el.querySelectorAll("h2").map(dom.text);
    assert.ok(h2s.includes("Column changes (2)"), h2s.join(", "));
    const changes = el.querySelectorAll("section").find((s) => dom.text(s.querySelector("h2")) === "Column changes (2)");
    assert.match(dom.text(changes), /New: NewColumn/);
    assert.match(dom.text(changes), /Not in this sample: OldColumn/);

    const gone = render(ctx({ name: "ReachAzureAD_CL" }));
    const goneChips = gone.querySelector(".r-title").querySelectorAll(".r-chip").map(dom.text);
    assert.ok(goneChips.some((c) => /missing since \d/.test(c)), `missing since among ${goneChips.join(", ")}`);
    assert.equal(goneChips.some((c) => /^last seen /.test(c)), false, "missing replaces last seen");
  } finally {
    restore();
    await reset();
  }
});
