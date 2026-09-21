// A route that already names a field (st and name, as the field page's own
// arrow link sends) keeps the value page: classify()'s "name" reading is
// for a bare route with no field to consult, not a literal this route has
// already scoped, even when the literal also happens to read as a
// catalogue name.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { walk, text } from "./_dom.js";

await catalogue.load();
const restore = dom.install();
const { render } = await import("../app/views/value.js");
test.after(() => restore());

const flush = () => new Promise((r) => setTimeout(r, 0));

async function renderValue(params) {
  const ctx = { fields, catalogue, params, openSettings: null, setUrl: () => {}, setDrawerParamHandler: () => {}, setDrawerCopyHandler: () => {} };
  const el = render(ctx);
  await flush();
  await flush();
  return el;
}

test("a route with st and name renders the value page, not \"a name, not a value\"", async () => {
  const el = await renderValue({ value: "AwsApiCall", st: "aws:cloudtrail", name: "eventType" });
  assert.ok(!/a name, not a value/.test(text(el)), "the field page's own route keeps the value reading");
});

test("the field's listed meaning for the value draws in the Meaning band", async () => {
  const el = await renderValue({ value: "AwsApiCall", st: "aws:cloudtrail", name: "eventType" });
  assert.match(text(el), /AwsApiCall: An API was called/, "the pack's entry for eventType=AwsApiCall is listed");
});

test("the same literal with no route field still reads as a catalogue name", async () => {
  const el = await renderValue({ value: "eventType" });
  assert.match(text(el), /a name, not a value/, "a bare route with no field keeps classify()'s name reading");
});
