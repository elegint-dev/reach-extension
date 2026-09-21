// The paste's fold under the title block: a page's own render fills it
// closed; a fill after the analyst acted on the page opens it and scrolls it
// into view; a refill of the same title leaves it where it is.

import { test } from "node:test";
import assert from "node:assert/strict";
import { foldMove } from "../app/lib/paste-fold.js";

test("a fill during render leaves the fold closed and the page unscrolled", () => {
  assert.equal(foldMove({ title: "See ProcessRollup2 on real data", lastTitle: "", acted: false, inFold: true }), null);
});

test("a fill after a click on the page opens the fold and scrolls to it", () => {
  assert.deepEqual(foldMove({ title: "Everywhere this binary ran", lastTitle: "", acted: true, inFold: true }), { open: true, scroll: true });
});

test("a refill under the same title after a parameter edit moves nothing", () => {
  assert.equal(foldMove({ title: "Everywhere this binary ran", lastTitle: "Everywhere this binary ran", acted: true, inFold: true }), null);
});

test("a second row picked after the first opens the fold on its new title", () => {
  assert.deepEqual(foldMove({ title: "Same hash on other hosts", lastTitle: "Everywhere this binary ran", acted: true, inFold: true }), { open: true, scroll: true });
});

test("clearing the title closes the fold", () => {
  assert.deepEqual(foldMove({ title: "", lastTitle: "Everywhere this binary ran", acted: true, inFold: true }), { open: false, scroll: false });
});

test("on the wide surface the drawer is not in the fold and nothing moves", () => {
  assert.equal(foldMove({ title: "Everywhere this binary ran", lastTitle: "", acted: true, inFold: false }), null);
});
