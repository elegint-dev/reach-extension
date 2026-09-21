// The field page's title-block keep row (the Hold body) shows once Hold is
// clicked and hides again once Release empties it, the same rule the value
// and runbook pages share through value.js's keepRow(): a static row that
// only ever opens leaves a permanent gap once released.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { walk, text } from "./_dom.js";

await catalogue.load();
// keepRow() falls back to MutationObserver to catch the release status line
// emptying (nothing in the row's own click list covers Release, only Hold
// and Mark benign); this file opts a real one in to exercise that path.
const restore = dom.install({ mutationObserver: true });
const { render } = await import("../app/views/field.js");
const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
test.after(() => restore());

const flush = () => new Promise((r) => setTimeout(r, 0));

function ctxFor(params) {
  const drawer = { fill() {}, fail() {} };
  return { fields, catalogue, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

async function renderField(params) {
  const el = render(ctxFor(params));
  await flush();
  await flush();
  return el;
}

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  investigation.clear();
});

test("the field page's keep row hides again once Release empties it", async () => {
  const el = await renderField({ value: "4036", st: "crowdstrike:events:sensor", name: "RawProcessId" });
  const keep = walk(el, (n) => n.className === "r-title__keep")[0];
  assert.ok(keep, "the keep row is drawn");
  assert.equal(keep.hidden, true, "empty at first, before Hold");

  const btn = walk(el, (n) => n.tagName === "BUTTON" && text(n).trim() === "Hold")[0];
  assert.ok(btn, "the Hold button is drawn");
  btn.click();
  await flush();
  await flush();
  assert.equal(keep.hidden, false, "shows once Hold fills the status line");

  const rel = walk(el, (n) => n.tagName === "BUTTON" && text(n).trim() === "Release")[0];
  assert.ok(rel, "a Release control is drawn once held");
  rel.click();
  await flush();
  await flush();
  assert.equal(keep.hidden, true, "hides again once Release empties the status line");
});
