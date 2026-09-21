// boot.js, the classic script index.html runs before first paint: the
// extension's own copy of the page refuses to show anything when another
// page has framed it, and the served copy (the width harness frames it on
// purpose) and every top-level extension document are left alone. boot.js
// is evaluated as popup.test.js evaluates popup.js: the source, one
// function body, fake globals.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const src = await readFile(new URL("../boot.js", import.meta.url), "utf8");

function boot({ protocol, framed }) {
  const page = { hidden: false };
  const box = { hidden: true, innerHTML: "" };
  const listeners = [];
  const window = { REACH_APP: undefined, REACH_FRAMED: undefined };
  window.top = framed ? {} : window;
  const document = {
    documentElement: { setAttribute() {} },
    addEventListener: (name, fn) => listeners.push([name, fn]),
    getElementById: (id) => ({ page, "boot-error": box })[id],
  };
  const globals = { window, document, location: { protocol }, localStorage: { getItem: () => null } };
  new Function(...Object.keys(globals), src)(...Object.values(globals));
  for (const [name, fn] of listeners) if (name === "DOMContentLoaded") fn();
  return { window, page, box };
}

test("the extension page framed by another document hides the app and says so", () => {
  const r = boot({ protocol: "chrome-extension:", framed: true });
  assert.equal(r.window.REACH_FRAMED, true);
  assert.equal(r.page.hidden, true);
  assert.equal(r.box.hidden, false);
  assert.match(r.box.innerHTML, /does not run inside another page/);
});

test("the extension page as a top-level document runs as before", () => {
  const r = boot({ protocol: "chrome-extension:", framed: false });
  assert.equal(r.window.REACH_APP, true);
  assert.equal(r.window.REACH_FRAMED, undefined);
  assert.equal(r.page.hidden, false);
  assert.equal(r.box.hidden, true);
});

test("the served page may be framed: the guard keys on the extension protocol", () => {
  const r = boot({ protocol: "http:", framed: true });
  assert.equal(r.window.REACH_FRAMED, undefined);
  assert.equal(r.page.hidden, false);
  assert.equal(r.box.hidden, true);
});

test("a file:// open still gets the serve-it message, framed or not", () => {
  const r = boot({ protocol: "file:", framed: true });
  assert.equal(r.window.REACH_FRAMED, undefined);
  assert.equal(r.page.hidden, true);
  assert.match(r.box.innerHTML, /has to be served/);
});
