// A value page that names no field (#/v/936, a typed value or a search hit)
// still draws the title block's action row: Hold, which asks for the key
// the pin goes under and holds on the next click, as the Holding rail's
// Add form does. A page that names the field keeps the plain Hold.
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
const notebook = await import("../app/lib/notebook.js");
test.after(() => restore());

function flush() {
  return new Promise((r) => setTimeout(r, 0));
}

async function renderValue(params) {
  const ctx = { fields, catalogue, params, openSettings: null, setUrl: () => {}, setDrawerParamHandler: () => {}, setDrawerCopyHandler: () => {} };
  const el = render(ctx);
  await flush();
  await flush();
  return el;
}

function actionRow(el) {
  return walk(el, (n) => n.className && /\br-actions\b/.test(n.className))[0] || null;
}

test("a bare value page draws the title block's action row with Hold", async () => {
  const el = await renderValue({ value: "936" });
  const row = actionRow(el);
  assert.ok(row, "the title block has an action row");
  const labels = walk(row, (n) => n.tagName === "BUTTON").map((n) => text(n).trim());
  assert.deepEqual(labels, ["Hold"]);
});

test("the bare Hold asks for a key first and holds the value under it", async () => {
  await notebook.load({ force: true });
  const el = await renderValue({ value: "936" });
  const btn = walk(el, (n) => n.tagName === "BUTTON" && text(n).trim() === "Hold")[0];
  const key = walk(el, (n) => n.tagName === "INPUT" && n.getAttribute("aria-label") === "Fact key")[0];
  assert.ok(key, "the key input");
  assert.equal(key.parentNode.hidden, true, "the key input waits under the row");
  btn.click();
  await flush();
  assert.equal(key.parentNode.hidden, false, "the first click opens the key input");
  assert.equal(notebook.current(), null, "nothing held without a key");
  key.value = "RawProcessId";
  btn.click();
  await flush();
  await flush();
  const inv = notebook.current();
  assert.ok(inv, "an investigation started");
  const pin = inv.entries.find((e) => e.kind === "pin");
  assert.equal(pin.field, "RawProcessId");
  assert.equal(pin.value, "936");
  assert.equal(text(btn).trim(), "Held ✓");
});

test("a value page that names its field keeps the plain Hold and Mark benign", async () => {
  const el = await renderValue({ value: "4036", st: "crowdstrike:events:sensor", name: "RawProcessId" });
  const labels = walk(actionRow(el), (n) => n.tagName === "BUTTON").map((n) => text(n).trim());
  assert.deepEqual(labels, ["Hold", "Mark benign"]);
});
