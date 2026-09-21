// Where the search history is written (app/lib/searches.js): the editor
// bridge's apply, whichever editor or the clipboard takes the text, with
// the trace the caller names; the Splunk popup's Copy SPL and Open in
// Splunk, held or not; a render of the same control writes nothing.
// Runs on store.js's memory backend with no editor and no clipboard, so
// every hand-off falls to the clipboard notice.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";

const restore = dom.install();
test.after(async () => {
  await new Promise((r) => setTimeout(r, 1000)); // the copy button's flash restores its label before the document goes
  restore();
});

const store = await import("../app/lib/store.js");
const searches = await import("../app/lib/searches.js");
const bridge = await import("../app/lib/editor-bridge.js");
const runtime = await import("../app/lib/runtime.js");
const spl = await import("../app/lib/spl.js");
const ui = await import("../app/lib/popup-ui.js");
const { runControl } = await import("../app/lib/click-splunk.js");
assert.equal(store.backend(), "memory");

const settle = (ms = 10) => new Promise((r) => setTimeout(r, ms));

beforeEach(async () => {
  await store.remove(searches.KEY);
  await searches.load({ force: true });
});

test("bridge.apply writes one entry for the text handed on, source insert, with the trace's origin, container and name, even when only the clipboard takes it", async () => {
  const res = await bridge.apply({ text: 'NOT process="calc.exe"', form: "term", field: "process", mode: "append", platform: "splunk", trace: { origin: "exclusion", container: "wineventlog" } });
  assert.equal(res.how, null, "no editor and no clipboard here");
  const [e] = searches.list();
  assert.equal(e.text, 'NOT process="calc.exe"');
  assert.equal(e.source, "insert");
  assert.equal(e.origin, "exclusion");
  assert.equal(e.field, "process");
  assert.equal(e.container, "wineventlog");
  assert.equal(e.platform, "splunk");
  await bridge.apply({ text: "SigninLogs | take 10", mode: "set", form: "stage", platform: "sentinel", trace: { origin: "workflow", name: "the hunt", source: "run" } });
  const [k] = searches.list();
  assert.equal(k.platform, "sentinel");
  assert.equal(k.language, "kql");
  assert.equal(k.origin, "workflow");
  assert.equal(k.source, "run");
  assert.equal(k.name, "the hunt");
  await bridge.apply({ text: "", mode: "set", platform: "splunk" });
  assert.equal(searches.count(), 2, "an empty apply writes nothing");
});

test("the Splunk popup's Copy SPL and Open in Splunk write entries for a value that is not held; the render alone writes nothing", async () => {
  const lib = { spl, live: null, ui, runtime, catalogue: { fieldsOn: () => [] } };
  const text = 'search index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:x" | stats count by eventName';
  const edge = { hold: { field: "userIdentity.arn", value: "arn:x", container: "aws:cloudtrail", platform: "splunk" }, name: "what this identity did" };
  const box = runControl(lib, () => ({ spl: text, hazards: [], missing: [], sourcetype: "aws:cloudtrail" }), {}, {}, edge);
  await settle();
  assert.equal(searches.count(), 0, "drawing the control writes nothing");
  const copyBtn = dom.walk(box, (n) => n.tagName === "BUTTON" && dom.text(n) === "Copy SPL")[0];
  assert.ok(copyBtn);
  dom.fire(copyBtn, "click", { stopPropagation() {}, currentTarget: copyBtn });
  await settle();
  const [c] = searches.list();
  assert.equal(c.text, text);
  assert.equal(c.source, "copy");
  assert.equal(c.origin, "pivot");
  assert.equal(c.container, "aws:cloudtrail");
  assert.equal(c.field, "userIdentity.arn");
  assert.equal(c.value, "arn:x");
  assert.equal(c.name, "what this identity did");
  const open = dom.walk(box, (n) => n.tagName === "A" && dom.text(n).startsWith("Open in Splunk"))[0];
  assert.ok(open);
  dom.fire(open, "click", {});
  await settle();
  assert.equal(searches.count(), 1, "the same text as the newest entry moves it");
  assert.equal(searches.list()[0].source, "open");
});
