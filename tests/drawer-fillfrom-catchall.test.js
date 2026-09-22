// fillFrom(el, spec, generate): without spec.catchAll, only a named query
// error (SplError, PivotError) fails the drawer in place; anything else
// used to throw past the caller. value.js's FDR ledger fill and field.js's
// fdrLedger fill both now pass catchAll: true, so a row select never
// throws past its own click handler on either page.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fillFrom } from "../app/components/drawer.js";

function fakeDrawer() {
  const calls = { fill: [], fail: [] };
  return { el: { fill: (s) => calls.fill.push(s), fail: (s) => calls.fail.push(s) }, calls };
}

test("without catchAll, an unnamed generator error still throws past fillFrom", () => {
  const { el } = fakeDrawer();
  assert.throws(() => fillFrom(el, { title: "t" }, () => { throw new TypeError("bug"); }), /bug/);
});

test("with catchAll, the same error fails the drawer in place instead of throwing", () => {
  const { el, calls } = fakeDrawer();
  assert.doesNotThrow(() => fillFrom(el, { title: "t", catchAll: true }, () => { throw new TypeError("bug"); }));
  assert.equal(calls.fail.length, 1);
  assert.match(calls.fail[0].error.text, /bug/);
});

test("a rejected generate() promise is the caller's to await; a thrown one inside is what catchAll guards", async () => {
  const { el, calls } = fakeDrawer();
  // fillFrom's generate() is called synchronously (drawer fills read the
  // result back the same tick); a generator that itself awaits a relay
  // call and rejects reports through its own throw, same as any other.
  assert.doesNotThrow(() => fillFrom(el, { title: "t", catchAll: true }, () => { throw new Error("relay rejected"); }));
  assert.equal(calls.fail.length, 1);
});

// The two pages' own FDR ledger fill() calls this exercises indirectly
// (a live selectRow needs a mounted route and a real catalogue): the
// direct check that each one opted in is the regression for this diff.
test("the value page's and the field page's FDR ledger fill() both opt into catchAll", () => {
  for (const path of ["app/views/value.js", "app/views/field.js"]) {
    const text = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
    assert.match(text, /catchAll: true/, `${path} fills its ledger drawer with catchAll: true`);
  }
});
