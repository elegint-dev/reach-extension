// app/lib/coverage-model.js is the Coverage page's pure model: it builds no
// DOM, runs no query, and the view re-exports every one of its names, so a
// caller of either module sees the same functions.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as model from "../app/lib/coverage-model.js";
import * as view from "../app/views/coverage.js";

test("the model imports no component, no layer read and no query runner", async () => {
  const src = await readFile(new URL("../app/lib/coverage-model.js", import.meta.url), "utf8");
  assert.ok(!/components\//.test(src), "no component import");
  assert.ok(!/\bh\(/.test(src), "no element built");
  assert.ok(!/from "[^"]*(recipe|discovery|layer)\.js"/.test(src), "no query runner or layer read imported");
  assert.ok(!src.includes(String.fromCharCode(0x2014)), "no em dashes");
});

test("the view re-exports the model's names and its default export carries them beside render", () => {
  const names = Object.keys(model).filter((k) => k !== "default");
  assert.ok(names.includes("rowsFor") && names.includes("envStats") && names.includes("STATE_CHIP"));
  for (const n of names) assert.equal(view[n], model[n], `${n} re-exported unchanged`);
  for (const n of names) assert.equal(view.default[n], model[n], `${n} on the default export`);
  assert.equal(typeof view.default.render, "function");
  assert.equal(typeof model.render, "undefined", "the model does not render");
});
