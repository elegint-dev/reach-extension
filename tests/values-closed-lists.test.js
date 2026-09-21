// The dictionary-closed marker (values.js `closed`) beyond the enum-type
// concepts it originally shipped on: a pack-spec sweep marked the vendor
// enumerations a values table fully documents, leaving samples, ids, free
// text and growing catalogues open. Both invariants are computed from the
// bundled sidecars themselves, never typed in by hand.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";
import { valueEntry } from "../app/lib/bands/value.js";

await catalogue.load();

async function closedConcepts() {
  const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url), "utf8"));
  const out = [];
  for (const e of index.values) {
    const doc = JSON.parse(await readFile(new URL(`../app/packs/${e.file}`, import.meta.url), "utf8"));
    const p = packs.pack(e.pack);
    for (const [cid, rec] of Object.entries(doc.concepts || {})) {
      if (rec.closed === true) out.push({ pack: e.pack, concept: cid, type: p && p.concepts[cid] && p.concepts[cid].type, hasValues: Boolean(rec.values && Object.keys(rec.values).length) });
    }
  }
  return out;
}

test("closed: true marks non-enum concepts, each with a values table that is the whole set, and there is more than the enum-type baseline of none", async () => {
  const closed = await closedConcepts();
  assert.ok(closed.length > 0, "the sweep left at least one sidecar entry closed");
  for (const c of closed) {
    assert.notEqual(c.type, "enum", `${c.pack}/${c.concept}: an enum concept never needs closed: true`);
    assert.ok(c.hasValues, `${c.pack}/${c.concept}: closed: true with no values table to close`);
  }
});

test("catalogue.loadValues(aws:cloudtrail) then valueEntry reads an unlisted cim_status value as closed", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const view = catalogue.fieldOn("aws:cloudtrail", "status");
  assert.equal(view.concept && view.concept.id, "cim_status");
  const row = valueEntry({ catalogue, container: "aws:cloudtrail", field: "status", value: "nonexistent", view });
  assert.equal(row.kind, "closed");
  assert.equal(row.count, 2);
});
