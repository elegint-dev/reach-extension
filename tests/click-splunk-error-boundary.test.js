// runControl's Run here action crosses the relay (appNamespace(), then
// live.dispatch): a rejection anywhere in that chain used to be an
// unhandled promise rejection out of an onClick handler (appNamespace()
// sat outside the try). It now renders as this row's status line, and
// the row (and the rest of the popup) stays mounted.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import { h } from "../app/components/h.js";
import * as spl from "../app/lib/spl.js";
import { runControl } from "../app/lib/click-splunk.js";

const restoreDom = dom.install();
const chromeFake = fakeChrome();
const restoreChrome = chromeFake.install();
test.after(() => {
  restoreChrome();
  restoreDom();
});

const FULL = { value: "x", aid: "a".repeat(32), earliest: "-24h", latest: "now", index: "main" };
const generateOk = () => ({ spl: "search index=main aid=" + "a".repeat(32), hazards: [], missing: [], sourcetype: "crowdstrike:events:sensor" });

function runButton(box) {
  for (const n of dom.walk(box, (x) => x.tagName === "BUTTON")) if (dom.text(n) === "Run here →") return n;
  return null;
}

test("a rejected relay promise on Run here renders as the row's status, not an unhandled rejection", async () => {
  const seen = [];
  const onUnhandled = (err) => seen.push(err);
  process.on("unhandledRejection", onUnhandled);

  // chrome.storage.local.get is what store.getLiteral (appNamespace) awaits.
  const originalGet = chrome.storage.local.get;
  chrome.storage.local.get = async () => {
    throw new Error("extension context invalidated");
  };

  const lib = { spl, live: { dispatch: async () => { throw new Error("must not reach dispatch"); } }, ui: {}, catalogue: { fieldsOn: () => [] }, notebook: { update: () => {} }, runtime: { localePrefix: () => "en-US", copyText: () => {} } };
  const box = runControl(lib, generateOk, FULL, {}, null);
  document.body.replaceChildren(box);

  const btn = runButton(box);
  assert.ok(btn, "Run here appears once every param is bound");
  dom.fire(btn, "click", { isTrusted: true });
  await new Promise((r) => setTimeout(r, 20));

  assert.ok(document.body.contains(box), "the row stays mounted");
  const status = box.el ? null : null; // status is the last row__body--muted node
  const statusEl = dom.walk(box, (n) => n.className === "reach-row__body reach-row__body--muted").pop();
  assert.ok(statusEl && dom.text(statusEl).includes("extension context invalidated"), `status line names the error, got: ${statusEl && dom.text(statusEl)}`);
  assert.equal(seen.length, 0, `no unhandled rejection escaped: ${seen.map((e) => e && e.message)}`);

  chrome.storage.local.get = originalGet;
  process.off("unhandledRejection", onUnhandled);
});
