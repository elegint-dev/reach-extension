// packEdgeRows' onToggle used to call control(edge, params, pmeta)
// unguarded: a thrown error there (a bug in the row's own render, not the
// generator error runControl/pivotControl already catch) escaped the
// toggle handler uncaught, on both platforms (they share this function).
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import { packEdgeRows } from "../app/lib/click-section.js";

await catalogue.load();
const restore = dom.install();
test.after(() => restore());

test("a control() that throws leaves the row's disclosure open with an inline failure, not an uncaught exception", () => {
  const edge = { id: "e1", label: "broken row", packId: "crowdstrike-falcon", src: { field: "x", sourcetype: "crowdstrike:events:sensor" }, dst: { field: "y", sourcetype: "crowdstrike:events:sensor" } };
  const m = { lib: { packs }, ctx: { event: { time: "" }, read: () => null }, edges: [edge], value: "v", container: "crowdstrike:events:sensor" };
  const rows = packEdgeRows(m, () => { throw new Error("bug in this row's own render"); });
  const details = rows[0];
  document.body.replaceChildren(details);
  assert.doesNotThrow(() => dom.fire(details, "toggle", { target: { ...details, open: true } }));
});
