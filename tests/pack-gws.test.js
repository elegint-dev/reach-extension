// The gws pack: every Splunk binding names a column the real Google
// Workspace activity captures carry (tests/fixtures/gws-observed-columns.json,
// flattened from splunk/attack_data), the dictionary sidecar validates, and
// login/admin (Reports API shape) plus drive (this capture's flattened
// shape) each bind on both platforms where a connector table exists.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as packs from "../app/lib/packs.js";
import * as values from "../app/lib/values.js";
import * as taxonomy from "../app/lib/taxonomy.js";

await taxonomy.load();

const pack = JSON.parse(await readFile(new URL("../app/packs/gws.json", import.meta.url)));
const sidecar = JSON.parse(await readFile(new URL("../app/packs/gws.values.json", import.meta.url)));
const observedFixture = JSON.parse(await readFile(new URL("./fixtures/gws-observed-columns.json", import.meta.url)));

test("gws pack validates against app/lib/packs.js", () => {
  assert.deepEqual(packs.validate(pack), []);
});

test("every Splunk binding names an observed column of its own container", () => {
  const byContainer = new Map(Object.entries(observedFixture.containers).map(([k, v]) => [k, new Set(v.columns)]));
  const splunk = pack.bindings.filter((b) => b.platform === "splunk");
  assert.ok(splunk.length > 20);
  for (const b of splunk) {
    const observed = byContainer.get(b.container);
    assert.ok(observed, `${b.container} has no observed-columns fixture`);
    assert.ok(observed.has(b.column), `${b.container}: ${b.column} is not an observed column`);
  }
});

test("login and admin share the nested Reports API concepts; drive binds its own flattened columns", () => {
  const columnsOf = (container) => new Set(pack.bindings.filter((b) => b.container === container).map((b) => b.column));
  assert.ok(columnsOf("gws:reports:login").has("id.time"));
  assert.ok(columnsOf("gws:reports:admin").has("id.time"));
  assert.ok(columnsOf("gws:reports:admin").has("actor.callerType"), "admin-only column");
  assert.ok(!columnsOf("gws:reports:login").has("actor.callerType"));
  assert.ok(columnsOf("gws:reports:drive").has("timestamp"));
  assert.ok(!columnsOf("gws:reports:drive").has("id.time"), "drive does not carry the nested id.time column");
});

test("both platforms are bound for login, admin and drive", () => {
  const containers = new Set(pack.bindings.map((b) => b.container));
  assert.ok(containers.has("gws:reports:login") && containers.has("GWorkspace_ReportsAPI_login_CL"));
  assert.ok(containers.has("gws:reports:admin") && containers.has("GWorkspace_ReportsAPI_admin_CL"));
  assert.ok(containers.has("gws:reports:drive") && containers.has("GWorkspace_ReportsAPI_drive_CL"));
});

test("the Sentinel container names are the solution's real per-application tables, not a single GoogleWorkspace table", () => {
  const sentinelContainers = new Set(pack.bindings.filter((b) => b.platform === "sentinel").map((b) => b.container));
  for (const c of sentinelContainers) assert.ok(c.startsWith("GWorkspace_ReportsAPI_"), c);
  assert.ok(!sentinelContainers.has("GoogleWorkspace"));
});

test("the values sidecar validates and every value entry names a concept the pack has", () => {
  const conceptIds = Object.keys(pack.concepts);
  const bindingKeys = new Set(pack.bindings.map((b) => `${b.platform}\0${b.container}\0${b.column}`));
  assert.deepEqual(values.validateDocument(sidecar, conceptIds, bindingKeys), []);
  for (const cid of Object.keys(sidecar.concepts)) assert.ok(conceptIds.includes(cid), cid);
});

test("the sidecar stays under the byte budget its index entry declares", async () => {
  const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url)));
  const entry = index.values.find((v) => v.pack === "gws");
  const text = await readFile(new URL("../app/packs/gws.values.json", import.meta.url), "utf8");
  assert.equal(Buffer.byteLength(text, "utf8"), entry.bytes);
  assert.ok(entry.bytes < values.BUDGET_BYTES);
});
