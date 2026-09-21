// The discovered layer's record carries first_seen and last_seen as epoch
// seconds on both platforms: the Sentinel recipe converts the portal's
// datetime strings on write, and every reader goes through layer.epochOf(),
// which still reads the ISO strings stored before writers normalised.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as layer from "../app/lib/layer.js";
import * as store from "../app/lib/store.js";
import * as recipe from "../app/lib/recipe.js";
import * as discovery from "../app/lib/discovery.js";
import { parse } from "../app/lib/intake.js";

const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
const T0 = 1_789_603_560; // 2026-09-17T00:06:00Z

beforeEach(async () => {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.remove(recipe.WORKSPACES_KEY);
});

test("epochOf reads epoch seconds, a numeric string, milliseconds and an ISO instant as the same number", () => {
  assert.equal(layer.epochOf(T0), T0);
  assert.equal(layer.epochOf(String(T0)), T0);
  assert.equal(layer.epochOf(T0 * 1000), T0);
  assert.equal(layer.epochOf("2026-09-17T00:06:00Z"), T0);
  assert.equal(layer.epochOf("2026-09-17T00:06:00.0000000Z"), T0, "Kusto's seven fractional digits");
  assert.equal(layer.epochOf(1789636410.5), 1789636410.5, "a fractional second from tstats is kept");
});

test("epochOf answers null, never NaN, for nothing and for text it cannot read", () => {
  for (const v of [null, undefined, "", "soon", NaN, Infinity, {}]) assert.equal(layer.epochOf(v), null, String(v));
});

test("platformOf keys a Splunk origin apart from a workspace resource id", () => {
  assert.equal(layer.platformOf("https://splunk.example"), "splunk");
  assert.equal(layer.platformOf(RID), "sentinel");
});

test("the Sentinel recipe stores first_seen and last_seen as epoch seconds, from Usage and from the scan", async () => {
  const inv = recipe.steps(null, {}).find((s) => s.id === "inventory");
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "inventory", env: "dev", gen: "g", q: inv.q }, params: inv.params, rows: [
    { TenantId: "4f43", DataType: "ReachCloudTrail_CL", Solution: "LogManagement", mb: 0.5, first_seen: "2026-09-17T00:06:00Z", last_seen: "2026-09-17T23:06:00.0000000Z", billable: true },
  ] })), { expect: inv });
  const scan = recipe.steps(null, {}).find((s) => s.id === "inventoryScan");
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "inventoryScan", env: "dev", q: scan.q }, params: scan.params, rows: [
    { T: "ReachAzureAD_CL", TenantId: "4f43", n: 62, first_seen: "2026-09-17T23:04:27Z", last_seen: "" },
  ] })), { expect: scan });
  const env = await recipe.environment(RID);
  assert.equal(env.sourcetypes.ReachCloudTrail_CL.first_seen, T0);
  assert.equal(env.sourcetypes.ReachCloudTrail_CL.last_seen, T0 + 23 * 3600);
  assert.equal(env.sourcetypes.ReachAzureAD_CL.first_seen, T0 + 23 * 3600 - 93);
  assert.equal("last_seen" in env.sourcetypes.ReachAzureAD_CL, false, "an empty cell writes nothing");
});

test("discovery.health ages a last_seen stored as an ISO string the same as one stored in seconds", () => {
  const now = (T0 + 3 * 86400) * 1000;
  const fromSeconds = discovery.health({ last_seen: T0 }, now);
  const fromIso = discovery.health({ last_seen: "2026-09-17T00:06:00Z" }, now);
  assert.equal(fromSeconds.lastSeenAge, 3 * 86400);
  assert.equal(fromIso.lastSeenAge, fromSeconds.lastSeenAge);
  assert.equal(discovery.health({}).lastSeenAge, null);
});

test("the last-seen chip ages an ISO last_seen instead of printing NaN, and states the instant in the shared stamp", async () => {
  const restore = dom.install();
  try {
    const { healthChips } = await import("../app/components/health.js");
    const now = (T0 + 3 * 86400) * 1000;
    const iso = healthChips({ lastSeen: "2026-09-17T00:06:00Z" }, now);
    const secs = healthChips({ lastSeen: T0 }, now);
    assert.equal(dom.text(iso[0]), "last seen 3d ago");
    assert.equal(dom.text(secs[0]), dom.text(iso[0]));
    assert.equal(iso[0].attributes.title, "newest event the last inventory saw: 2026-09-17 00:06:00 UTC");
    assert.deepEqual(healthChips({ lastSeen: "soon" }, now), []);
  } finally {
    restore();
  }
});

test("a Sentinel profile records distinct_exact null, the reason stated once in the module rather than on every column", async () => {
  const step = recipe.tableSteps(null, "ReachAzureAD_CL", {})[0];
  await recipe.apply(RID, parse(JSON.stringify({ meta: { v: 1, step: "profile", env: "dev", q: step.q }, params: step.params, rows: [
    { col: "ResultType", n: 31, d: 3, t: "string", total: 31, row_kind: "stat" },
  ] })), { expect: step });
  const p = (await recipe.environment(RID)).sourcetypes.ReachAzureAD_CL.fields.ResultType.profile;
  assert.equal(p.distinct, 3);
  assert.equal(p.distinct_exact, null);
  assert.equal("distinct_note" in p, false);
  assert.match(recipe.DISTINCT_ESTIMATED, /dcountif/);
});

test("the platform's own columns are one table: each platform skips only its own names, and no name is on both lists", () => {
  const splunk = new Set(layer.SYSTEM_FIELDS.splunk);
  const sentinel = new Set(layer.SYSTEM_FIELDS.sentinel);
  assert.deepEqual([...splunk].filter((n) => sentinel.has(n)), []);
  assert.deepEqual(discovery.SKIP_FIELDS, layer.systemFields("splunk"));
  assert.deepEqual(recipe.SYSTEM_COLUMNS, layer.systemFields("sentinel"));
  assert.equal(layer.systemFields().size, splunk.size + sentinel.size);
  assert.equal(layer.systemFields("splunk").has("TenantId"), false);
  assert.equal(layer.systemFields("sentinel").has("_raw"), false);
});
