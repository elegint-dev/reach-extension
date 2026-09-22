// catalogue.js's precedence once a Falcon dictionary is imported
// (falcon-dictionary.js): the bundle's own text and decode table always
// win; the imported layer answers only where the bundle has nothing;
// nothing anywhere still reads as nothing (inferred).
import "./_splunk.js";
import "./_bundle.js";
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const catalogue = await import("../app/lib/catalogue.js");
const fd = await import("../app/lib/falcon-dictionary.js");

const ST = "crowdstrike:events:sensor";
const SAMPLE = JSON.parse(await readFile(new URL("./fixtures/falcon-dictionary.sample.json", import.meta.url), "utf8"));

before(async () => {
  await catalogue.load();
});

beforeEach(async () => {
  await store.remove(fd.KEY);
  fd._reset();
  await fd.load();
});

test("a bundled field's text and decode table stand even when the imported layer names the same field differently", async () => {
  const doc = JSON.parse(JSON.stringify(SAMPLE));
  doc.fields.AccessoryConnectionType = { description: "a made-up description that must never show", type: "string", values: { "0": "MADE UP" } };
  await fd.importDoc(doc);

  const view = catalogue.fieldOn(ST, "AccessoryConnectionType");
  assert.equal(view.meaning.source, "pack");
  assert.match(view.meaning.description, /Enumerated code/);

  const dec = catalogue.decodeOn(ST, "AccessoryConnectionType");
  assert.equal(dec.source, "pack");
  assert.equal(dec.values["0"], "BLUETOOTH"); // the TA's own table, not the layer's "MADE UP"
});

test("the imported layer answers a field the bundle does not carry: its type, its values and its meaning", async () => {
  const doc = JSON.parse(JSON.stringify(SAMPLE));
  doc.fields.MyTenantCustomField = { description: "A field only this tenant's FDR pull carries.", type: "string", values: { A: "state A", B: "state B" }, events: [{ name: "AidMaster", platforms: ["win"] }] };
  await fd.importDoc(doc);

  const view = catalogue.fieldOn(ST, "MyTenantCustomField");
  assert.ok(view, "the layer alone is enough for fieldOn to answer");
  assert.equal(view.meaning.source, "falcon");
  assert.equal(view.meaning.description, "A field only this tenant's FDR pull carries.");
  assert.equal(view.falcon.type, "string");
  assert.deepEqual(view.falcon.events, ["AidMaster"]);

  const dec = catalogue.decodeOn(ST, "MyTenantCustomField");
  assert.equal(dec.source, "falcon");
  assert.deepEqual(dec.values, { A: "state A", B: "state B" });
});

test("nothing anywhere is still nothing: no bundle, no layer entry, fieldOn answers null", async () => {
  await fd.importDoc(SAMPLE);
  assert.equal(catalogue.fieldOn(ST, "NoSuchFieldAnywhere"), null);
  assert.equal(catalogue.decodeOn(ST, "NoSuchFieldAnywhere"), null);
});

test("the layer never answers off a Falcon container: the same imported field name is invisible on an unrelated sourcetype", async () => {
  const doc = JSON.parse(JSON.stringify(SAMPLE));
  doc.fields.MyTenantCustomField = { description: "", type: "string", values: { A: "state A" }, events: [] };
  await fd.importDoc(doc);
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "MyTenantCustomField"), null);
});
