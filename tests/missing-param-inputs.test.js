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

test("missingParamInputs draws one labelled input per missing parameter and a Preview button last", () => {
  withDom(() => {
    const changes = [];
    let previews = 0;
    const els = missingParamInputs({ missing: ["earliest", "aid"], meta: {}, platform: "sentinel", onChange: (n, v) => changes.push([n, v]), onPreview: () => previews++ });
    assert.equal(els.length, 3);
    const inputs = els.slice(0, 2).map((row) => dom.walk(row, (n) => n.tagName === "INPUT")[0]);
    assert.deepEqual(inputs.map((i) => i.getAttribute("aria-label")), ["since", "aid"]);
    assert.deepEqual(inputs.map((i) => i.getAttribute("placeholder")), ["-24h", "32-hex sensor id"]);
    assert.equal(dom.text(els[0]).trim(), "since:");
    inputs[1].value = "0123456789abcdef0123456789abcdef";
    dom.fire(inputs[1], "input", { target: inputs[1] });
    assert.deepEqual(changes, [["aid", "0123456789abcdef0123456789abcdef"]]);
    const btn = els[2];
    assert.equal(btn.tagName, "BUTTON");
    assert.equal(dom.text(btn), "Preview");
    dom.fire(btn, "click");
    assert.equal(previews, 1);
  });
});

test("typing a parameter and previewing holds nothing and pins nothing", async () => {
  const heldBefore = JSON.stringify(pinned.all());
  const investigationBefore = JSON.stringify(notebook.current());
  withDom(() => {
    const els = missingParamInputs({ missing: ["earliest"], platform: "splunk", onChange: () => {}, onPreview: () => {} });
    const input = dom.walk(els[0], (n) => n.tagName === "INPUT")[0];
    input.value = "-1h";
    dom.fire(input, "input", { target: input });
    dom.fire(els[1], "click");
  });
  assert.equal(JSON.stringify(pinned.all()), heldBefore);
  assert.equal(JSON.stringify(notebook.current()), investigationBefore);
});
