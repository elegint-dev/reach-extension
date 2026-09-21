// The same keep-row rule on the Sentinel field route: the title block's
// Hold body hides again once Release empties it, not just on Splunk.
import "./_sentinel.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { walk, text } from "./_dom.js";

await catalogue.load();
// keepRow() falls back to MutationObserver for Release (nothing in its own
// click list covers that button); this file opts a real one in.
const restore = dom.install({ mutationObserver: true });
const { render } = await import("../app/views/field.js");
const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
test.after(() => restore());

const flush = () => new Promise((r) => setTimeout(r, 0));
const TABLE = "ReachCrowdStrike_CL";

function ctxFor(params) {
  const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
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

test("the Sentinel field page's keep row hides again once Release empties it", async () => {
  const el = await renderField({ value: "4036", st: TABLE, name: "RawProcessId" });
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
