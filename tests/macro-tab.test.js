// it_aef7e874: the macro tab checks the CrowdStrike TA macros against what
// discovery found on the instance, greys Copy with a reason when one is
// really missing, and offers a one-line define hint. Pure logic only: the
// drawer and field.js build DOM (h.js needs `document`), which this suite
// has no harness for; that part is the served harness at 380 (panel-validator.md).
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { macroStateText, macrosBlocking, copyBlockReason } from "../app/components/drawer.js";
import { macroDefineHint, macroInfo } from "../app/views/field.js";

test("a macro never checked (no discovery run yet) reads as not-checked, not as missing", () => {
  const m = { name: "cs_index", defined: undefined };
  assert.equal(macroStateText(m, "https://splunk.example"), "not checked yet");
  assert.deepEqual(macrosBlocking([m]), [], "an unchecked macro never blocks Copy");
});

test("a macro discovery actually found absent reads as not defined, and blocks Copy", () => {
  const m = { name: "cs_index", defined: false };
  assert.equal(macroStateText(m, "https://splunk.example"), "not defined on https://splunk.example");
  assert.deepEqual(macrosBlocking([m]), [m]);
});

test("a macro discovery found present reads as defined, and never blocks Copy", () => {
  const m = { name: "cs_index", defined: true };
  assert.equal(macroStateText(m, "https://splunk.example"), "defined on https://splunk.example");
  assert.deepEqual(macrosBlocking([m]), []);
});

test("copyBlockReason names the missing macros, the environment, and the other tab as the way out", () => {
  const info = { env: "https://splunk.example", needed: [{ name: "cs_index", defined: false }, { name: "cs_trace_process", defined: true }] };
  const reason = copyBlockReason(info, "macro");
  assert.match(reason, /cs_index/);
  assert.doesNotMatch(reason, /cs_trace_process/, "only the missing one is named");
  assert.match(reason, /https:\/\/splunk\.example/);
  assert.match(reason, /Inline/, "points at the other tab as the way out");
});

test("copyBlockReason is empty when nothing needed is missing, checked or not", () => {
  assert.equal(copyBlockReason({ env: null, needed: [] }, "inline"), "");
  assert.equal(copyBlockReason({ env: "https://splunk.example", needed: [{ name: "cs_index", defined: true }] }, "inline"), "");
  assert.equal(copyBlockReason({ env: "https://splunk.example", needed: [{ name: "cs_index", defined: undefined }] }, "macro"), "");
});

test("macroDefineHint: cs_index's hint carries the resolved scope index, or a placeholder when none resolved", () => {
  assert.equal(macroDefineHint("cs_index", "crowdstrike_fdr"), "Settings > Advanced search > Search macros: name cs_index, definition index=crowdstrike_fdr.");
  assert.match(macroDefineHint("cs_index", ""), /index=<your index>/);
});

test("macroDefineHint: a TA macro other than cs_index is named, but Reach does not invent its definition", () => {
  const hint = macroDefineHint("cs_trace_process", "crowdstrike_fdr");
  assert.match(hint, /cs_trace_process/);
  assert.match(hint, /no definition to suggest/);
});

test("macroInfo: no discovered environment leaves every needed macro unchecked, never missing", () => {
  const info = macroInfo(["cs_index", "cs_trace_process"], null, "crowdstrike_fdr");
  assert.equal(info.env, null);
  assert.deepEqual(info.needed.map((m) => m.defined), [null, null]);
  assert.deepEqual(macrosBlocking(info.needed), []);
});

test("macroInfo: a discovered environment's record decides defined/not defined, and only the missing carry a hint", () => {
  const env = { origin: "https://splunk.example", macros: { cs_index: { defined: false }, cs_trace_process: { defined: true } } };
  const info = macroInfo(["cs_index", "cs_trace_process"], env, "crowdstrike_fdr");
  assert.equal(info.env, "https://splunk.example");
  const byName = Object.fromEntries(info.needed.map((m) => [m.name, m]));
  assert.equal(byName.cs_index.defined, false);
  assert.match(byName.cs_index.hint, /cs_index/);
  assert.equal(byName.cs_trace_process.defined, true);
  assert.equal(byName.cs_trace_process.hint, undefined, "a defined macro carries no hint");
});
