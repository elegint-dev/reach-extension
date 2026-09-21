// Which container leads a field page when more than one pack binds the same
// column name (app/lib/catalogue.js leadingContainer, app/views/field.js
// resolveContainer): the container an on= or st= link actually names wins
// the heading, meaning and dictionary; everything else falls to also-on.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import { resolveContainer } from "../app/views/field.js";

await catalogue.load();

test("leadingContainer: a hint that names a container this field is bound on wins", () => {
  assert.equal(catalogue.leadingContainer("eventType", ["OktaIM2:log"]), "OktaIM2:log");
  assert.equal(catalogue.leadingContainer("eventType", ["aws:cloudtrail"]), "aws:cloudtrail");
});

test("leadingContainer: a hint that names no container for this field falls through", () => {
  assert.equal(catalogue.leadingContainer("eventType", ["ProcessRollup2"]), null, "an FDR event, not a container");
  assert.equal(catalogue.leadingContainer("eventType", [null, undefined, "nope"]), null);
});

test("field on OktaIM2:log (via on=) leads with Okta's own meaning, CloudTrail dropping to also-on", () => {
  const { st, knownOn } = resolveContainer("eventType", { on: "OktaIM2:log" }, catalogue);
  assert.equal(st, "OktaIM2:log");
  const view = catalogue.fieldOn(st, "eventType");
  assert.equal(view.meaning.packId, "okta");
  assert.ok(knownOn.includes("aws:cloudtrail"), "still a candidate, for also-on");
  const alsoOn = catalogue.fieldEverywhere("eventType").filter((r) => r.sourcetype !== st);
  assert.ok(alsoOn.some((r) => r.sourcetype === "aws:cloudtrail" && r.packId === "aws-cloudtrail"));
});

test("field on aws:cloudtrail (via st=) leads with CloudTrail's own meaning", () => {
  const { st } = resolveContainer("eventType", { st: "aws:cloudtrail" }, catalogue);
  assert.equal(st, "aws:cloudtrail");
  const view = catalogue.fieldOn(st, "eventType");
  assert.equal(view.meaning.packId, "aws-cloudtrail");
});

test("a column bound in only one pack resolves there regardless of an unrelated hint", () => {
  const { st } = resolveContainer("actor.alternateId", { on: "aws:cloudtrail" }, catalogue);
  assert.equal(st, "OktaIM2:log", "the hint names no container for this column, so the catalogue's only one stands");
  assert.equal(catalogue.fieldOn(st, "actor.alternateId").meaning.packId, "okta");
});
