// pivotControl.draw() used to rethrow any generator error that was not a
// PivotError; a bug elsewhere in pivot.js (not a template mistake) would
// then escape the click handler uncaught. It now renders in the row.
import "./_dom.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { pivotControl } from "../app/lib/click-sentinel.js";

const restore = dom.install();
test.after(() => restore());

test("a thrown, non-PivotError generator failure renders as the row's warning, not an uncaught exception", () => {
  const edge = { packId: "x", id: "e1", label: "test edge" };
  const lib = {
    pivot: { generate: () => { throw new TypeError("bug: cannot read property of undefined"); } },
    packs: { pack: () => null },
    kql: {},
    runtime: { copyText: () => {} },
    ui: {},
  };
  let box;
  assert.doesNotThrow(() => {
    box = pivotControl(lib, edge, {}, {}, null, null);
  });
  assert.match(dom.text(box), /cannot read property of undefined/);
});
