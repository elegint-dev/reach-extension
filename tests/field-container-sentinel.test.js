// The same container-aware lead on Sentinel: Okta_CL and AWSCloudTrail sort
// AWSCloudTrail first (default catalogue order), so a naive pick still gets
// this wrong unless the hint is honoured. The bundled packs use disjoint
// column names on these two tables, so a shared name is written through the
// user layer the way a discovered or hand-described column would arrive.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import { resolveContainer } from "../app/views/field.js";

await catalogue.load();
await catalogue.annotate("AWSCloudTrail", "recordKind", { description: "CloudTrail's record kind" });
await catalogue.annotate("Okta_CL", "recordKind", { description: "Okta's record kind" });

test("recordKind on Okta_CL leads with Okta's note, not AWSCloudTrail's default-order win", () => {
  const { st } = resolveContainer("recordKind", { on: "Okta_CL" }, catalogue);
  assert.equal(st, "Okta_CL");
  assert.equal(catalogue.fieldOn(st, "recordKind").meaning.description, "Okta's record kind");
});

test("recordKind on AWSCloudTrail leads with CloudTrail's own note", () => {
  const { st } = resolveContainer("recordKind", { st: "AWSCloudTrail" }, catalogue);
  assert.equal(st, "AWSCloudTrail");
  assert.equal(catalogue.fieldOn(st, "recordKind").meaning.description, "CloudTrail's record kind");
});
