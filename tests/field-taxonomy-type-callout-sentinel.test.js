// The same taxonomy type head in Meaning on a Sentinel pid column: the
// field template is shared, so the gate holds on both platforms.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { render } from "../app/views/field.js";

await catalogue.load();
dom.install();

const TABLE = "ReachCrowdStrike_CL";

function draw(params) {
  const drawer = { fill() {}, fail() {} };
  const el = render({ fields, catalogue, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
  document.body.replaceChildren(el);
  return el;
}

test("a Sentinel pid column with no stronger hazard draws the taxonomy type head in Meaning", () => {
  const el = draw({ name: "TargetProcessId", st: TABLE, value: "936" });
  const meaning = el.querySelector(".r-meaning-section");
  const type = meaning.querySelector(".r-ann .r-callout");
  assert.ok(type, "the taxonomy type callout");
  const label = dom.text(type.querySelector(".r-callout__label"));
  assert.equal(label, "Sensor process id · A sensor's own unique id for a process, never recycled within a sensor session. Pivot on this, scoped by host id.");
});
