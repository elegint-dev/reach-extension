// enrich.js self-registers the four G2 technique bundles (ATT&CK, Sigma,
// ESCU, Sentinel rules) on import, with no explicit register() call from
// a caller: value.js, value-popup.js and sentinel-grid.js each only
// import and register kev and virustotal by name, so a new bundled
// source has to make itself known from within enrich.js. This file
// carries no beforeEach/reset: a hook anywhere in a node:test file
// applies to every test in that file, including ones declared before
// it, so this check has to live alone to see the registry's state right
// after module load.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as enrich from "../app/lib/enrich.js";

test("enrich.js self-registers all four technique bundles without an explicit register() call", () => {
  const ids = enrich.list("technique").map((s) => s.id).sort();
  assert.deepEqual(ids, ["attack", "escu", "sentinel-rules", "sigma"]);
});
