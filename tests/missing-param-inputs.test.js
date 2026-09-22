// popup-ui.js missingParamMeta / missingParamInputs: the inputs a pivot
// draws for the parameters it still needs, one table for both popups, with
// each platform's own words kept.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { MISSING_PARAM_META, missingParamMeta, missingParamInputs } from "../app/lib/popup-ui.js";
import * as notebook from "../app/lib/notebook.js";
import * as pinned from "../app/lib/pinned.js";

function withDom(fn) {
  const restore = dom.install();
  try {
    return fn();
  } finally {
    restore();
  }
}

test("a parameter no pack names gets the platform's own words: earliest/latest on Splunk, since/until on Sentinel", () => {
  assert.equal(missingParamMeta("earliest", {}, "splunk").label, "earliest");
  assert.equal(missingParamMeta("latest", {}, "splunk").label, "latest");
  assert.equal(missingParamMeta("aid", {}, "splunk").placeholder, "32-hex agent id");
  assert.equal(missingParamMeta("earliest", {}, "sentinel").label, "since");
  assert.equal(missingParamMeta("latest", {}, "sentinel").label, "until");
  assert.equal(missingParamMeta("aid", {}, "sentinel").placeholder, "32-hex sensor id");
  assert.deepEqual(Object.keys(MISSING_PARAM_META).sort(), ["sentinel", "splunk"]);
});

test("the pack's own words win over the platform's, and a parameter neither names falls back to its bare name", () => {
  const meta = { earliest: { label: "index time", placeholder: "-7d", hint: "the time the event was indexed" } };
  assert.deepEqual(missingParamMeta("earliest", meta, "sentinel"), meta.earliest);
  assert.deepEqual(missingParamMeta("session_id", {}, "splunk"), { placeholder: "session_id", label: "session_id" });
});

// A row per missing name (each with its own labelled input), a line
// naming them all, and a Preview button: found by content, not position,
// since the "needs …" summary line can move where the row list starts.
function findByText(els, text) {
  return els.find((el) => dom.text(el).trim() === text);
}
function findButton(els) {
  return els.find((el) => el.tagName === "BUTTON");
}
function inputRow(els, label) {
  return els.find((el) => dom.walk(el, (n) => n.tagName === "INPUT" && n.getAttribute("aria-label") === label).length);
}

test("missingParamInputs draws one labelled input per missing parameter, a summary line and a Preview button", () => {
  withDom(() => {
    const changes = [];
    let previews = 0;
    const els = missingParamInputs({ missing: ["earliest", "aid"], meta: {}, platform: "sentinel", onChange: (n, v) => changes.push([n, v]), onPreview: () => previews++ });
    assert.equal(els.length, 4, "a summary line, two rows, one button");
    assert.equal(findByText(els, "needs since, aid"), els[0]);
    const sinceRow = inputRow(els, "since");
    const aidRow = inputRow(els, "aid");
    const sinceInput = dom.walk(sinceRow, (n) => n.tagName === "INPUT")[0];
    const aidInput = dom.walk(aidRow, (n) => n.tagName === "INPUT")[0];
    assert.equal(sinceInput.getAttribute("placeholder"), "-24h");
    assert.equal(aidInput.getAttribute("placeholder"), "32-hex sensor id");
    assert.equal(dom.text(sinceRow).trim(), "since:");
    const btn = findButton(els);
    assert.equal(dom.text(btn), "Preview");
    assert.equal(btn.disabled, true, "nothing typed in yet");
    sinceInput.value = "-1h";
    dom.fire(sinceInput, "input", { target: sinceInput });
    aidInput.value = "0123456789abcdef0123456789abcdef";
    dom.fire(aidInput, "input", { target: aidInput });
    assert.deepEqual(changes, [["earliest", "-1h"], ["aid", "0123456789abcdef0123456789abcdef"]]);
    assert.equal(btn.disabled, false, "every listed name now has a value");
    dom.fire(btn, "click");
    assert.equal(previews, 1);
  });
});

test("typing a parameter and previewing holds nothing and pins nothing", async () => {
  const heldBefore = JSON.stringify(pinned.all());
  const investigationBefore = JSON.stringify(notebook.current());
  withDom(() => {
    const els = missingParamInputs({ missing: ["earliest"], platform: "splunk", onChange: () => {}, onPreview: () => {} });
    const row = inputRow(els, "earliest");
    const input = dom.walk(row, (n) => n.tagName === "INPUT")[0];
    input.value = "-1h";
    dom.fire(input, "input", { target: input });
    dom.fire(findButton(els), "click");
  });
  assert.equal(JSON.stringify(pinned.all()), heldBefore);
  assert.equal(JSON.stringify(notebook.current()), investigationBefore);
});
