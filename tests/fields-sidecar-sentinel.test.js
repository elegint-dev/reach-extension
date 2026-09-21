// A Sentinel build never fetches the Falcon field catalogue: none of the
// sidecar's containers exist on the platform, so the boot's load and a
// click in the sample table that binds Falcon concepts fetch nothing.
// A Falcon table bound on Sentinel is the one thing that fetches it.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as values from "../app/lib/values.js";
import { PLATFORM } from "../app/lib/platform.js";

const fetched = [];
const inner = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  fetched.push(String(url).replace(/^.*\/app\/packs\//, "app/packs/"));
  return inner(url, opts);
};
const sidecars = () => fetched.filter((p) => p.endsWith(".fields.json"));

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

test("the boot's load fetches the packs and no fields sidecar", () => {
  assert.ok(fetched.includes("app/packs/index.json"));
  assert.deepEqual(sidecars(), []);
  assert.equal(fields.loaded(), false);
  assert.equal(fields.field("TargetProcessId"), null);
  assert.deepEqual(catalogue.searchIndex().events, []);
});

test("a click in the sample table that binds Falcon concepts fetches nothing: the concepts are bound there, the Falcon containers are not", async () => {
  assert.ok(values.packsOn("ReachCrowdStrike_CL", "sentinel").includes("crowdstrike-falcon"), "the sample table resolves to Falcon concepts");
  await catalogue.loadFields("ReachCrowdStrike_CL");
  await catalogue.loadFields();
  assert.deepEqual(sidecars(), []);
  assert.equal(catalogue.fieldOn("ReachCrowdStrike_CL", "TargetProcessId").pack, null, "the concept's record, not the sidecar's");
});

test("a Falcon table bound on Sentinel is what fetches the catalogue, once", async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
  await catalogue.bindField("crowdstrike:events:sensor", "aid", "crowdstrike-falcon/aid");
  await catalogue.loadFields();
  assert.deepEqual(sidecars(), ["app/packs/crowdstrike-falcon.fields.json"]);
  assert.ok(fields.loaded());
  await catalogue.loadFields("crowdstrike:events:sensor");
  assert.equal(sidecars().length, 1);
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
});
