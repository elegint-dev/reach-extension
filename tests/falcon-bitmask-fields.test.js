// Every field the fields sidecar's cim_targets name a crowdstrike_ta_bitmask_lookup_*
// lookup for (enumerated here, not hand-listed, so a new lookup in a future
// bundle trips the test) resolves on crowdstrike:events:sensor to a Falcon
// pack concept that either carries decode.flags (a sourced bit table) or an
// undecoded meaning ending in the not-public sentence: a field never falls
// through to "the name is all there is" once this bundle names its lookup.
// ProcessParameterFlags on ProcessRollup2 (24577) is the field the brief
// names as the repro: three flags, zero remainder. code_signing_flags is a
// bitmask concept too but cites no crowdstrike_ta_bitmask_lookup_* (its bits
// are prose, hand-authored before this pack sidecar existed), so the walk
// below does not expect it to carry decode.flags.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as packs from "../app/lib/packs.js";
import * as values from "../app/lib/values.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";

await catalogue.load();

const ST = "crowdstrike:events:sensor";
const NOT_PUBLIC = /bit names are not public/;
const LOOKUP_RE = /crowdstrike_ta_bitmask_lookup_[A-Za-z0-9]+/;

await catalogue.loadFields(ST);

function bitmaskLookupFields() {
  const out = [];
  for (const [name, rec] of Object.entries(fields.fields())) {
    const cited = (rec.cim_targets || []).some((t) => LOOKUP_RE.test(t.statement || ""));
    if (cited) out.push(name);
  }
  return out.sort();
}

test("every field the fields sidecar cites a crowdstrike_ta_bitmask_lookup_* for is enumerated as 27", () => {
  const found = bitmaskLookupFields();
  assert.equal(found.length, 27, found.join(", "));
  assert.ok(found.includes("ProcessParameterFlags"));
});

test("each of those fields binds to a Falcon concept with a bit table or the not-public meaning, counted found/decoded/not-public", () => {
  const found = bitmaskLookupFields();
  let decoded = 0;
  let notPublic = 0;
  for (const name of found) {
    const view = catalogue.fieldOn(ST, name);
    assert.ok(view && view.concept, `${name}: no concept bound on ${ST}`);
    const concept = packs.pack("crowdstrike-falcon").concepts[view.concept.key.split("/")[1]];
    assert.equal(concept.type, "bitmask", `${name}: concept type`);
    const hasFlags = concept.decode && concept.decode.flags && Object.keys(concept.decode.flags).length;
    if (hasFlags) decoded += 1;
    else {
      assert.match(concept.description, NOT_PUBLIC, `${name}: undecoded field needs the not-public sentence`);
      notPublic += 1;
    }
  }
  assert.equal(decoded, 5, "sourced bit tables");
  assert.equal(notPublic, 22, "undecoded, not-public fields");
  assert.equal(decoded + notPublic, found.length);
});

test("code_signing_flags is a bitmask concept outside the lookup-citing set and is not required to carry decode.flags", () => {
  assert.ok(!bitmaskLookupFields().includes("CodeSigningFlags"));
  const csf = packs.pack("crowdstrike-falcon").concepts.code_signing_flags;
  assert.equal(csf.type, "bitmask");
  assert.equal(csf.decode, undefined);
});

test("ProcessParameterFlags decodes 24577 to its three named flags with zero remainder", () => {
  const concept = packs.pack("crowdstrike-falcon").concepts.process_parameter_flags;
  assert.equal(
    values.decodeBitmask(concept.decode, "24577"),
    "RTL_USER_PROC_PARAMS_NORMALIZED | RTL_USER_PROC_APP_MANIFEST_PRESENT | RTL_USER_PROC_IMAGE_KEY_MISSING",
  );
  const parts = values.bitmaskParts(concept.decode, "24577");
  assert.equal(parts.rest, null, "no bits outside the three named flags");
  assert.equal(catalogue.valueOn(ST, "ProcessParameterFlags", "24577").meaning, values.decodeBitmask(concept.decode, "24577"));
});
