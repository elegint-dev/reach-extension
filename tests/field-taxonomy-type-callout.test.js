// Meaning draws the bound concept's taxonomy type (head the type's label
// and description, body its first hazard) for the pid family, only once
// neither the unsafe-join banner nor the concept's own danger or caution
// already covers the ground; the title block's callout slot is unchanged.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { render } from "../app/views/field.js";

await catalogue.load();
dom.install();

const ST = "crowdstrike:events:sensor";

function draw(params) {
  const drawer = { fill() {}, fail() {} };
  const el = render({ fields, catalogue, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
  document.body.replaceChildren(el);
  return el;
}

test("a pid field with no stronger hazard draws the taxonomy type's head and first hazard in Meaning", () => {
  const el = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo", value: "936" });
  const meaning = el.querySelector(".r-meaning-section");
  const type = meaning.querySelector(".r-ann .r-callout");
  assert.ok(type, "the taxonomy type callout, first in the annotation block");
  const label = dom.text(type.querySelector(".r-callout__label"));
  assert.equal(label, "Sensor process id · A sensor's own unique id for a process, never recycled within a sensor session. Pivot on this, scoped by host id.");
  const body = dom.text(type.querySelector(".r-callout__body"));
  assert.equal(body, "Unique per host, not across hosts: always pair with the host id.");
  assert.equal(el.querySelector(".r-title__callout"), null, "the title block's callout slot stays empty");
});

test("the unsafe-join banner is unchanged on a pid field: the title slot as before, no taxonomy type head in Meaning", () => {
  const el = draw({ name: "RawProcessId", st: ST, on: "ProcessHandleOpDetectInfo", value: "936" });
  const slot = el.querySelector(".r-title__callout");
  assert.ok(slot, "the callout slot");
  assert.equal(dom.text(slot.querySelector(".r-callout__label")), "Not safe to join on");
  const meaning = el.querySelector(".r-meaning-section");
  assert.equal(meaning.querySelector(".r-ann .r-callout"), null, "no taxonomy type head once the join hazard already fired");
});

test("a non-pid field draws no taxonomy type callout in Meaning", () => {
  const el = draw({ name: "SHA256HashData", st: ST, on: "ProcessRollup2", value: "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4" });
  const meaning = el.querySelector(".r-meaning-section");
  assert.equal(meaning.querySelector(".r-ann .r-callout"), null, "no hazard, no type head");
  assert.equal(el.querySelector(".r-title__callout"), null);
});
