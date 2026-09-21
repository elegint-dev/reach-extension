import { test } from "node:test";
import assert from "node:assert/strict";
import * as recipe from "../app/lib/recipe.js";
import * as store from "../app/lib/store.js";
import * as layer from "../app/lib/layer.js";
import { parse } from "../app/lib/intake.js";

const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";

async function reset() {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.remove(recipe.WORKSPACES_KEY);
}

// What the profile query returns for a small table, in envelope form.
function profileEnvelope(step, rows) {
  return JSON.stringify({ meta: { v: 1, step: "profile", env: "dev", gen: "2026-09-17T00:00:00Z", q: step.q }, params: step.params, rows });
}

test("environments come from the portal and from pastes; forget drops both", async () => {
  await reset();
  assert.deepEqual(await recipe.environments(), []);
  await recipe.rememberWorkspace(RID, { name: "sentinel" });
  let envs = await recipe.environments();
  assert.equal(envs.length, 1);
  assert.equal(envs[0].key, RID);
  assert.equal(envs[0].name, "sentinel");
  await assert.rejects(() => recipe.addEnvironment("/subscriptions/nope"), /resource id/);
  await recipe.forget(RID);
  assert.deepEqual(await recipe.environments(), []);
});

test("the recipe grows as results come back", async () => {
  await reset();
  let env = null;
  let s = recipe.steps(env, { packTables: ["ReachAzureAD_CL"] });
  assert.deepEqual(s.map((x) => x.id), ["inventory", "inventoryScan", "schema:1", "watchlists"]);
  assert.equal(s[0].status, "pending");

  // inventory
  const inv = s[0];
  const invPaste = JSON.stringify({ meta: { v: 1, step: "inventory", env: "dev", gen: "g", q: inv.q }, params: inv.params, rows: [
    { TenantId: "4f43", DataType: "ReachCloudTrail_CL", Solution: "LogManagement", mb: 0.5, first_seen: "2026-09-17T00:06:00Z", last_seen: "2026-09-17T23:06:00Z", billable: true },
    { TenantId: "4f43", DataType: "ReachAzureAD_CL", Solution: "LogManagement", mb: 0.1, first_seen: "2026-09-17T23:04:00Z", last_seen: "2026-09-17T23:06:00Z", billable: true },
  ] });
  const r1 = await recipe.apply(RID, parse(invPaste), { expect: inv });
  assert.deepEqual(r1.written, { tables: 2 });
  assert.deepEqual(r1.verdicts, []);
  env = await recipe.environment(RID);
  assert.equal(env.tenantId, "4f43");
  assert.equal(env.label, "dev");
  s = recipe.steps(env, { packTables: ["ReachAzureAD_CL"] });
  assert.equal(s[0].status, "imported");
  assert.match(s[2].bare, /ReachAzureAD_CL \| getschema/);
  assert.match(s[2].bare, /ReachCloudTrail_CL \| getschema/);

  // schema
  const sch = s[2];
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "schema", env: "dev", q: sch.q }, params: sch.params, rows: [
    { T: "ReachAzureAD_CL", ColumnName: "TimeGenerated", ColumnType: "datetime" },
    { T: "ReachAzureAD_CL", ColumnName: "ResultType", ColumnType: "string" },
    { T: "ReachAzureAD_CL", ColumnName: "DurationMs", ColumnType: "int" },
    { T: "ReachAzureAD_CL", ColumnName: "TenantId", ColumnType: "string" },
  ] })), { expect: sch });
  env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.fields.DurationMs.declared.type, "long");
  assert.equal(env.sourcetypes.ReachAzureAD_CL.fields.TenantId, undefined);
  assert.equal(recipe.steps(env, {})[2].status, "imported");

  // profile, from the real query's row shape
  const [prof] = recipe.tableSteps(env, "ReachAzureAD_CL");
  assert.equal(prof.id, "profile:ReachAzureAD_CL");
  assert.equal(prof.params.table, "ReachAzureAD_CL");
  const rows = [
    { col: "ResultType", n: 31, d: 1, t: "string", total: 31, row_kind: "stat" },
    { col: "UserPrincipalName", n: 31, d: 31, t: "string", total: 31, row_kind: "stat" },
    { col: "DurationMs", n: 31, d: 3, t: "long", total: 31, row_kind: "stat" },
    { col: "Country", n: 0, d: 0, t: null, total: 31, row_kind: "stat" },
    { col: "Type", n: 31, d: 1, t: "string", total: 31, row_kind: "stat" },
    { col: "ResultType", val: "50126", n: 31, row_kind: "top" },
    { col: "DurationMs", val: "0", n: 29, row_kind: "top" },
    { col: "DurationMs", val: "12", n: 2, row_kind: "top" },
  ];
  const r3 = await recipe.apply(RID, parse(profileEnvelope(prof, rows)), { expect: prof });
  assert.equal(r3.written.fields, 4);
  env = await recipe.environment(RID);
  const f = env.sourcetypes.ReachAzureAD_CL.fields;
  assert.equal(f.ResultType.profile.fill, 1);
  assert.equal(f.ResultType.profile.distinct, 1);
  assert.deepEqual(f.ResultType.profile.top, [{ value: "50126", count: 31 }]);
  assert.equal(f.DurationMs.profile.numeric, true);
  assert.equal(f.DurationMs.profile.type_agrees, true);
  assert.equal(f.Country.profile.fill, 0);
  assert.equal(f.Type, undefined);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.sample, 31);
  assert.equal(recipe.tableSteps(env, "ReachAzureAD_CL")[0].status, "imported");

  // a superseded paste is applied but labelled
  const stale = { ...prof, q: "00000000" };
  const r4 = await recipe.apply(RID, parse(profileEnvelope(prof, rows)), { expect: stale });
  assert.match(r4.verdicts[0], /superseded/);

  // record types, with the discriminator proposed from the profile
  const disc = recipe.proposeDiscriminator({ fields: { EventName: { profile: { type: "string", fill: 1, distinct: 2 } }, RequestId: { profile: { type: "string", fill: 1, distinct: 75 } }, ReadOnly: { profile: { type: "boolean", fill: 1, distinct: 2 } } } });
  assert.equal(disc, "EventName");
  const [, rt] = recipe.tableSteps(env, "ReachAzureAD_CL", { discriminator: "ResultType" });
  assert.equal(rt.step, "recordTypes");
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "recordTypes", env: "dev", q: rt.q }, params: rt.params, rows: [{ value: "50126", n: 31 }] })), { expect: rt });
  env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.discriminator, "ResultType");
  assert.deepEqual(env.sourcetypes.ReachAzureAD_CL.record_types, [{ value: "50126", count: 31 }]);

  // a plain table export needs the step named, and is marked unverified
  const r6 = await recipe.apply(RID, parse("alias\nfoo\nbar\n"), { step: "watchlists" });
  assert.match(r6.verdicts[0], /unverified/);
  env = await recipe.environment(RID);
  assert.deepEqual(env.watchlists, ["bar", "foo"]);
  assert.ok(recipe.steps(env, {}).some((x) => x.id === "watchlistSchema"));
  await assert.rejects(() => recipe.apply(RID, parse("a\n1\n"), { step: "nope" }), /unknown step/);
  await assert.rejects(() => recipe.apply(RID, parse("x,y\n1,2\n"), { step: "schema" }), /lack the columns/);
});

test("inventory by scan fills counts when Usage has nothing", async () => {
  await reset();
  const s = recipe.steps(null, {});
  const scan = s.find((x) => x.id === "inventoryScan");
  assert.match(scan.bare, /^union withsource = T \*\n\| where TimeGenerated > ago\(1d\)/);
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "inventoryScan", env: "dev", q: scan.q }, params: scan.params, rows: [
    { T: "ReachAzureAD_CL", TenantId: "4f43", n: 62, first_seen: "2026-09-17T23:04:27Z", last_seen: "2026-09-17T23:06:00Z" },
  ] })), { expect: scan });
  const env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.count, 62);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.inventory_basis, "scan");
  assert.equal(env.tenantId, "4f43");
  assert.equal(recipe.steps(env, {}).find((x) => x.id === "inventoryScan").status, "imported");
});

test("decode tables bind to a same-named column and edges are proposed across tables", async () => {
  await reset();
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "schema", env: "dev", q: "x" }, params: { batch: 1 }, rows: [{ T: "A", ColumnName: "ResultType", ColumnType: "string" }, { T: "B", ColumnName: "ResultType", ColumnType: "string" }] })));
  const r = await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "decode", env: "dev", q: "y" }, params: { alias: "codes", key: "ResultType", value: "meaning" }, rows: [{ k: "0", v: "ok" }, { k: "50126", v: "bad password" }, { k: "", v: "dropped" }] })));
  assert.equal(r.written.values, 2);
  assert.equal(r.written.bound, 2);
  let env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.A.decodes.ResultType.values["50126"], "bad password");
  assert.equal(env.sourcetypes.A.decodes.ResultType.lookup, "codes");
  for (const t of ["A", "B"]) {
    await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "profile", env: "dev", q: "z" }, params: { table: t }, rows: [
      { col: "ResultType", n: 10, d: 2, t: "string", total: 10, row_kind: "stat" },
      { col: "ResultType", val: "0", n: 8, row_kind: "top" }, { col: "ResultType", val: "50126", n: 2, row_kind: "top" },
    ] })));
  }
  env = await recipe.environment(RID);
  const edges = recipe.proposeEdges(env);
  assert.equal(edges.length, 1);
  assert.deepEqual(edges[0].src, { sourcetype: "A", field: "ResultType" });
  assert.equal(edges[0].overlap, 2);
  assert.equal(edges[0].basis, "proposed");
});

test("linkFor produces a deep link for a known workspace and none otherwise", async () => {
  const env = { resourceId: RID, label: "dev", sourcetypes: {}, steps: {} };
  const [step] = recipe.steps(env, {});
  const link = await recipe.linkFor(step, env);
  assert.match(link.url, /^https:\/\/portal\.azure\.com\/#view\//);
  assert.match(link.kql, /"env", "dev"/);
  assert.equal(link.q, recipe.stamp(step.bare));
  const none = await recipe.linkFor(step, { label: "x", sourcetypes: {}, steps: {} });
  assert.equal(none.url, null);
});
