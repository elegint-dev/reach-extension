import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { walk, text } from "./_dom.js";

await catalogue.load();
const restore = dom.install();
const { render } = await import("../app/views/value.js");
const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
test.after(() => restore());

const flush = () => new Promise((r) => setTimeout(r, 0));

async function renderValue(params) {
  const ctx = { fields, catalogue, params, openSettings: null, setUrl: () => {}, setDrawerParamHandler: () => {}, setDrawerCopyHandler: () => {} };
  const el = render(ctx);
  await flush();
  await flush();
  return el;
}

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  investigation.clear();
});

test("the value page's Hold row reads Held with a Release once held, same as the field page", async () => {
  const el = await renderValue({ value: "4036", st: "crowdstrike:events:sensor", name: "RawProcessId" });
  const btn = walk(el, (n) => n.tagName === "BUTTON" && text(n).trim() === "Hold")[0];
  assert.ok(btn, "the Hold button is drawn");
  btn.click();
  await flush();
  await flush();
  const status = walk(el, (n) => n.className === "reach-hold__status")[0];
  assert.match(text(status), /^Held · .* · Release$/, "the status reads Held ... Release, not \"Held · in ...\"");
  const rel = walk(el, (n) => n.tagName === "BUTTON" && text(n).trim() === "Release")[0];
  assert.ok(rel, "a Release control is drawn once held");
  rel.click();
  await flush();
  await flush();
  assert.equal(investigation.get("RawProcessId"), "", "the tab fact clears on release");
  const inv = notebook.current();
  assert.deepEqual(inv.entries, [], "the pin is gone from the notebook's investigation");
});
