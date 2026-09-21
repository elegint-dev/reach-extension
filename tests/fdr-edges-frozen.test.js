// The FDR join graph and the order the ledger draws it in are frozen in
// tests/fixtures: the nine edges byte for byte, and for every event and
// every field on it the edge ids edgeRowsFor() answers, in order (a
// leading * marks a row the field itself is the key of). The fixtures are
// not regenerated from the code under test; a move of the data must leave
// both equal.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as fields from "../app/lib/pack-fields.js";
import * as catalogue from "../app/lib/catalogue.js";
import { edgeRowsFor } from "../app/lib/reachability.js";

await catalogue.load();

const EDGES = JSON.parse(readFileSync(new URL("./fixtures/fdr-edges.json", import.meta.url), "utf8"));
const ORDER = JSON.parse(readFileSync(new URL("./fixtures/fdr-ledger-order.json", import.meta.url), "utf8"));

test("the nine bundle edges equal the frozen fixture, in order", () => {
  assert.deepEqual(fields.edges(), EDGES);
  for (const e of EDGES) assert.deepEqual(fields.edge(e.id), e);
});

test("the ledger orders edges for every event and field as the fixture says", () => {
  const got = {};
  for (const ev of fields.searchIndex().events) {
    const rec = fields.event(ev);
    const groups = {};
    for (const f of rec.fields) {
      const rows = edgeRowsFor(fields.edges(), rec, f);
      if (!rows.length) continue;
      const k = rows.map((r) => (r.viaSelf ? "*" : "") + r.edge.id).join(" ");
      (groups[k] = groups[k] || []).push(f);
    }
    if (Object.keys(groups).length) got[ev] = groups;
  }
  assert.deepEqual(got, ORDER);
  assert.equal(Object.keys(got).length, 274);
});
