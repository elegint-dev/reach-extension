// hasUnsavedInput: the guard that stops the panel from closing itself over
// text the analyst has not saved yet, one case per surface it reads.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { hasUnsavedInput, UNSAVED_SELECTORS } from "../app/lib/panel-close.js";
import { h } from "../app/components/h.js";

const restore = dom.install();

test("nothing typed anywhere: clean", () => {
  const root = h("div", null, h("textarea", { class: "r-ann__form-holder" }));
  assert.equal(hasUnsavedInput(root), false);
});

test("an open Note or Describe editor with text is dirty", () => {
  const root = h("div", { class: "r-ann__form" }, h("textarea", { value: "a note" }));
  assert.equal(hasUnsavedInput(root), true);
});

test("a typed Hold reason is dirty", () => {
  const root = h("div", null, h("input", { class: "reach-hold__reason", value: "why I am holding it" }));
  assert.equal(hasUnsavedInput(root), true);
});

test("a typed drawer parameter is dirty", () => {
  const root = h("form", { class: "r-drawer__params" }, h("input", { value: "936" }));
  assert.equal(hasUnsavedInput(root), true);
});

test("the Holding rail's Add form with text is dirty", () => {
  const root = h("form", { class: "r-holding__add" }, h("input", { value: "aid" }), h("input", { value: "" }));
  assert.equal(hasUnsavedInput(root), true);
});

test("an empty field on every watched surface is clean", () => {
  const root = h(
    "div",
    null,
    h("div", { class: "r-ann__form" }, h("textarea", { value: "" })),
    h("input", { class: "reach-hold__reason", value: "" }),
    h("form", { class: "r-drawer__params" }, h("input", { value: "" })),
    h("form", { class: "r-holding__add" }, h("input", { value: "" }), h("input", { value: "" })),
  );
  assert.equal(hasUnsavedInput(root), false);
});

test("with no root and no document, nothing is dirty", () => {
  assert.equal(hasUnsavedInput(null), false);
});

test("the selector list is frozen and shaped as simple descendant compounds", () => {
  assert.ok(Object.isFrozen(UNSAVED_SELECTORS));
  for (const s of UNSAVED_SELECTORS) assert.doesNotMatch(s, /[[\]:]/, s);
});

test.after(() => restore());
