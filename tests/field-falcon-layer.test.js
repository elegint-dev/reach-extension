// The Falcon field page draws the imported layer's type, its value table
// as a decode, and "Rides on N events" with an event's own description,
// once the bundle (and any pack) has nothing better for the field.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { readFile } from "node:fs/promises";
import * as catalogue from "../app/lib/catalogue.js";
import * as fd from "../app/lib/falcon-dictionary.js";
import * as fields from "../app/lib/pack-fields.js";
import { render } from "../app/views/field.js";

const SAMPLE = JSON.parse(await readFile(new URL("./fixtures/falcon-dictionary.sample.json", import.meta.url), "utf8"));

// A field name neither the FDR bundle nor any pack binds, so the page's
// only source for it is the imported layer.
const FIELD = "MyTenantCustomField";
function layerDoc() {
  const doc = JSON.parse(JSON.stringify(SAMPLE));
  doc.fields[FIELD] = {
    description: "",
    type: "string",
    values: { open: "session opened", closed: "session closed" },
    events: [{ name: "AidMaster", platforms: ["win"] }],
  };
  return doc;
}

await catalogue.load();
dom.install();

function ctxFor(params) {
  return { fields, catalogue, params, drawer: { fill() {}, fail() {} }, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

test("crowdstrike:events:sensor draws the layer's type, values and Rides on N events, with the event's own description", async () => {
  await fd.importDoc(layerDoc());
  const el = render(ctxFor({ name: FIELD, st: "crowdstrike:events:sensor" }));
  document.body.replaceChildren(el);
  const text = dom.text(el);
  assert.match(text, /type/);
  assert.match(text, /string/);
  assert.match(text, /Rides on 1 event/);
  assert.match(text, /session opened/);
  assert.match(text, /Sensor identity and platform metadata/); // AidMaster's own description, from the layer
});

test("Clear all Reach data removes the layer: the field page falls back to nothing for it again", async () => {
  await fd.importDoc(layerDoc());
  const wipe = await import("../app/lib/wipe.js");
  await wipe.clearModule("catalogue");
  await fd.load({ force: true });
  const el = render(ctxFor({ name: FIELD, st: "crowdstrike:events:sensor" }));
  document.body.replaceChildren(el);
  assert.doesNotMatch(dom.text(el), /session opened/);
});
