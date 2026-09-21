// The pure word helpers behind the field page's dictionary block and the
// sourcetype page's one-liners (app/components/dictionary.js,
// app/lib/values.js), and one import of each view so a broken module
// chain cannot hide behind the helper tests.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import { valuesSummary } from "../app/components/dictionary.js";
import * as fields from "../app/lib/pack-fields.js";
import { roleProvenance } from "../app/views/field.js";
import { oneLiner } from "../app/lib/values.js";

await catalogue.load();

test("valuesSummary: the fold's line names the count, the provenance or the lookup", async () => {
  assert.equal(valuesSummary(null), "");
  assert.equal(valuesSummary({ count: 1, source: "values", provenance: "documented" }), "1 value · documented");
  assert.equal(valuesSummary({ count: 6, source: "values", provenance: null }), "6 values");
  assert.equal(valuesSummary({ count: 5, source: "decode", lookup: "cloudtrail-event-type" }), "5 values via cloudtrail-event-type");
  assert.equal(valuesSummary({ count: 2, source: "decode", lookup: null }), "2 values from the pack's decode table");
  // Before the sidecar: the decode table's line. After: the dictionary's.
  const before = catalogue.fieldOn("aws:cloudtrail", "eventType").dictionary;
  assert.equal(valuesSummary(before), "5 values via cloudtrail-event-type");
  await catalogue.loadValues("aws:cloudtrail");
  assert.equal(valuesSummary(catalogue.fieldOn("aws:cloudtrail", "eventType").dictionary), "6 values · documented");
});

test("the sourcetype page's one-liners come from the concept descriptions, first sentence only", () => {
  const seen = [];
  for (const f of catalogue.fieldsOn("aws:cloudtrail")) {
    const v = catalogue.fieldOn("aws:cloudtrail", f);
    const d = v && v.meaning.description;
    if (!d) continue;
    const line = oneLiner(d);
    assert.ok(line.length > 0 && line.length <= 121, `${f}: ${line}`);
    assert.ok(!/[.!?]\s\S/.test(line), `${f}: one sentence: ${line}`);
    seen.push(line);
  }
  assert.ok(seen.length >= 80, `${seen.length} described fields`);
  assert.equal(oneLiner(catalogue.fieldOn("aws:cloudtrail", "eventType").meaning.description), "Kind of event");
});

test("the field and sourcetype views import with the dictionary block wired in", async () => {
  const field = await import("../app/views/field.js");
  const st = await import("../app/views/sourcetype.js");
  assert.equal(typeof field.render, "function");
  assert.equal(typeof st.render, "function");
});

test("the role line credits the pack when a concept is bound on the sourcetype, the note when the user set one, the bundle's inference otherwise", () => {
  const rec = fields.field("TargetProcessId");
  assert.equal(rec.role_basis, "name_convention", "the bundle's own basis is an inference");
  const view = catalogue.fieldOn("crowdstrike:events:sensor", "TargetProcessId");
  assert.ok(view && view.concept, "the Falcon pack binds it");
  const p = roleProvenance(rec, view);
  assert.equal(p.inferred, false);
  assert.match(p.from, /^the CrowdStrike Falcon .* pack$/);
  assert.equal(p.role, view.taxonomy.role);
  const yours = roleProvenance(rec, { ...view, taxonomy: { ...view.taxonomy, role: "identifier", roleSource: "user" } });
  assert.deepEqual(yours, { role: "identifier", from: "your note", inferred: false });
  const bare = roleProvenance(rec, null);
  assert.equal(bare.from, "the name convention");
  assert.equal(bare.inferred, true);
});
