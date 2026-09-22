// missingParamInputs: the row that appears while a pivot still has an
// unbound $name$ names them, and Preview stays disabled until every
// listed input has something typed into it (there is otherwise nothing
// new for it to reveal).
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { missingParamInputs } from "../app/lib/popup-shell.js";

const restore = dom.install();
test.after(() => restore());

function build(missing) {
  const changed = {};
  const previewed = [];
  const els = missingParamInputs({ missing, onChange: (n, v) => { changed[n] = v; }, onPreview: () => previewed.push({ ...changed }) });
  const box = document.createElement("div");
  for (const el of els) box.appendChild(el);
  const inputs = dom.walk(box, (n) => n.tagName === "INPUT");
  const btn = dom.walk(box, (n) => n.tagName === "BUTTON").find((n) => dom.text(n) === "Preview");
  return { box, inputs, btn, previewed };
}

test("Preview is disabled until every unbound name has a typed value", () => {
  const { inputs, btn } = build(["earliest", "latest"]);
  assert.equal(btn.disabled, true, "nothing typed yet");
  inputs[0].value = "-24h";
  dom.fire(inputs[0], "input");
  assert.equal(btn.disabled, true, "still one unfilled");
  inputs[1].value = "now";
  dom.fire(inputs[1], "input");
  assert.equal(btn.disabled, false, "every listed name now has a value");
});

test("the row names the unbound parameters", () => {
  const { box } = build(["earliest", "aid"]);
  assert.match(dom.text(box), /needs earliest, aid/);
});

test("no missing names still offers a working, enabled Preview (an already-bound row re-checked)", () => {
  const { btn, previewed } = build([]);
  assert.equal(btn.disabled, false);
  dom.fire(btn, "click");
  assert.equal(previewed.length, 1);
});
