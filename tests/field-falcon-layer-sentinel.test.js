// The same imported-layer fallback on a Sentinel Falcon table route: no
// FDR ledger exists there (fdrSourcetype is always false for a Sentinel
// table name), so the layer is the page's only source for a field the
// bundle and the packs do not bind.
import "./_sentinel.js";
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
const TABLE = "ReachCrowdStrike_CL"; // the sample pack's Falcon container on Sentinel
const FIELD = "MyTenantCustomField";

await catalogue.load();
dom.install();

test("a Sentinel Falcon table route draws Rides on N events and a value from the imported layer", async () => {
  const doc = JSON.parse(JSON.stringify(SAMPLE));
  doc.fields[FIELD] = { description: "", type: "string", values: { closed: "session closed" }, events: [{ name: "AidMaster", platforms: ["win"] }] };
  await fd.importDoc(doc);

  const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
  const el = render({ fields, catalogue, params: { name: FIELD, st: TABLE }, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
  document.body.replaceChildren(el);
  const text = dom.text(el);
  assert.match(text, /Rides on 1 event/);
  assert.match(text, /session closed/);
});
