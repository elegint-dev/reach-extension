// The okta pack: every Splunk binding names a column the real System Log
// output carries (tests/fixtures/foreign-tables.json's own OktaIM2:log
// profile, 53 columns, otherwise used only as the proposer's negative
// fixture), the dictionary sidecar validates, and both platforms are bound.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as packs from "../app/lib/packs.js";
import * as values from "../app/lib/values.js";
import * as taxonomy from "../app/lib/taxonomy.js";

await taxonomy.load();

const pack = JSON.parse(await readFile(new URL("../app/packs/okta.json", import.meta.url)));
const sidecar = JSON.parse(await readFile(new URL("../app/packs/okta.values.json", import.meta.url)));
const foreign = JSON.parse(await readFile(new URL("./fixtures/foreign-tables.json", import.meta.url)));
const oktaTable = foreign.tables.find((t) => t.container === "OktaIM2:log");
const observed = new Set(oktaTable.columns.map((c) => c.column));

test("okta pack validates against app/lib/packs.js", () => {
  assert.deepEqual(packs.validate(pack), []);
});

test("every Splunk binding names a column the real OktaIM2:log output carries", () => {
  const splunk = pack.bindings.filter((b) => b.platform === "splunk" && b.container === "OktaIM2:log");
  assert.ok(splunk.length > 30, "the pack should bind most of the observed width");
  for (const b of splunk) {
    assert.ok(observed.has(b.column), `${b.column} is not an observed OktaIM2:log column`);
  }
});

test("Okta_CL (Sentinel) bindings are disjoint json_string sub-paths or real v1 columns", () => {
  const sentinel = pack.bindings.filter((b) => b.platform === "sentinel" && b.container === "Okta_CL");
  assert.ok(sentinel.length > 20);
  for (const b of sentinel) {
    if (b.encoding === "json_string") {
      assert.ok(b.column.startsWith("debugContext_debugData_s."), b.column);
    } else {
      assert.ok(/^[a-zA-Z_]+$/.test(b.column), b.column);
    }
  }
});

test("both platforms are bound for the core identity and outcome concepts", () => {
  const platformsOf = (cid) => new Set(pack.bindings.filter((b) => b.concept === cid).map((b) => b.platform));
  for (const cid of ["actor_alternate_id", "source_ip", "event_type", "outcome_result", "severity"]) {
    const p = platformsOf(cid);
    assert.ok(p.has("splunk") && p.has("sentinel"), `${cid} should bind both platforms`);
  }
});

test("the values sidecar validates and every value entry names a concept the pack has", () => {
  const conceptIds = Object.keys(pack.concepts);
  const bindingKeys = new Set(pack.bindings.map((b) => `${b.platform}\0${b.container}\0${b.column}`));
  assert.deepEqual(values.validateDocument(sidecar, conceptIds, bindingKeys), []);
  for (const cid of Object.keys(sidecar.concepts)) assert.ok(conceptIds.includes(cid), cid);
});

test("the sidecar stays under the byte budget its index entry declares", async () => {
  const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url)));
  const entry = index.values.find((v) => v.pack === "okta");
  const text = await readFile(new URL("../app/packs/okta.values.json", import.meta.url), "utf8");
  assert.equal(Buffer.byteLength(text, "utf8"), entry.bytes);
  assert.ok(entry.bytes < values.BUDGET_BYTES);
});

test("index.json lists okta.json without dropping any existing pack", async () => {
  const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url)));
  for (const p of ["aws-cloudtrail.json", "entra-signin.json", "crowdstrike-falcon.json", "reach-sentinel-samples.json", "okta.json"]) {
    assert.ok(index.packs.includes(p), p);
  }
});

test("neither okta sidecar claims a licence the source repository never granted", async () => {
  const inventory = JSON.parse(await readFile(new URL("../app/packs/okta-inventory.values.json", import.meta.url)));
  for (const doc of [sidecar, inventory]) {
    assert.notEqual(doc.licence.name, "Apache-2.0", "okta-management-openapi-spec ships no LICENSE file; the README badge is not a grant");
    assert.match(doc.licence.name, /no reuse licence stated/);
  }
});
