// The taxonomy type head is the field page's own addition (app/components/
// annotation.js, called only from app/views/field.js): app/lib/bands/
// meaning.js is untouched, so meaningBlock's callers, the value page and
// the popups, draw a pid value's Meaning exactly as they did before this
// branch, with no callout the field page did not ask for.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { meaningBlock } from "../app/lib/bands/meaning.js";

await catalogue.load();
const restore = dom.install();
const { render } = await import("../app/views/value.js");
test.after(() => restore());

const ST = "crowdstrike:events:sensor";
const TYPE_HEAD = "Sensor process id · A sensor's own unique id for a process, never recycled within a sensor session. Pivot on this, scoped by host id.";

test("meaningBlock on a pid field renders no taxonomy type callout: the field page's addition is its own, not meaning.js's", async () => {
  await catalogue.loadValues(ST);
  const view = catalogue.fieldOn(ST, "TargetProcessId");
  const el = meaningBlock({ view, sourcetype: ST, name: "TargetProcessId", catalogue, appUrl: (h) => h, scopeEl: null, value: "936", editable: false });
  assert.equal(el.querySelector(".r-callout"), null, "no callout element of any kind");
  assert.ok(!dom.text(el).includes(TYPE_HEAD), "the type head text is absent");
  assert.match(dom.text(el), /Target process id/, "the concept's own line still draws");
});

test("the value page's Meaning for a pid value draws no taxonomy type callout", async () => {
  await catalogue.loadValues(ST);
  const ctx = { fields, catalogue, params: { name: "TargetProcessId", st: ST, value: "936" }, openSettings: null, setUrl: () => {}, setDrawerParamHandler: () => {}, setDrawerCopyHandler: () => {} };
  const el = render(ctx);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(el.querySelector(".r-callout"), null, "no callout anywhere on the value page");
  assert.ok(!dom.text(el).includes(TYPE_HEAD));
});
