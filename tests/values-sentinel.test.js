// The dictionary is concept-level, so the Sentinel table reads the same
// entries through its own bindings: AWSCloudTrail's EventTypeName is
// event_type, and its binding provenance is the connector column the
// Azure Monitor reference lists. Platform is pinned by the first import.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as values from "../app/lib/values.js";
import * as catalogue from "../app/lib/catalogue.js";
import { PLATFORM } from "../app/lib/platform.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

test("AWSCloudTrail columns carry the CloudTrail dictionary once the container's sidecar is loaded", async () => {
  assert.equal(catalogue.valuesReady("AWSCloudTrail"), false);
  assert.deepEqual(values.packsOn("AWSCloudTrail"), ["aws-cloudtrail"]);
  await catalogue.loadValues("AWSCloudTrail");
  assert.equal(catalogue.valuesReady("AWSCloudTrail"), true);
  const et = catalogue.fieldOn("AWSCloudTrail", "EventTypeName");
  assert.equal(et.concept.key, "aws-cloudtrail/event_type");
  assert.equal(et.dictionary.source, "values");
  assert.equal(et.dictionary.count, 6);
  assert.equal(et.dictionary.values.AwsConsoleSignIn.provenance, "documented");
  assert.equal(et.binding.provenance.kind, "connector");
  assert.equal(et.binding.provenance.cite.title, "Azure Monitor Logs reference: AWSCloudTrail");
  for (const [col, id] of [["UserIdentityType", "identity_type"], ["ErrorCode", "error_code"], ["SessionIssuerType", "session_issuer_type"]]) {
    const v = catalogue.fieldOn("AWSCloudTrail", col);
    assert.equal(v.concept.key, `aws-cloudtrail/${id}`, col);
    assert.equal(v.dictionary.source, "values", col);
    assert.equal(v.binding.provenance.kind, "connector", col);
  }
  const r = catalogue.valueOn("AWSCloudTrail", "ErrorCode", "AccessDenied");
  assert.equal(r.source, "pack");
  assert.equal(r.concept, "aws-cloudtrail/error_code");
  assert.equal(catalogue.valueOn("AWSCloudTrail", "ErrorCode", "SomethingElse"), null);
  // The dev sample table binds CloudTrail's concepts by qualified reference and reads the same table.
  assert.ok(values.packsOn("ReachCloudTrail_CL").includes("aws-cloudtrail"), "the feed pack behind the sample table's qualified bindings");
  await catalogue.loadValues("ReachCloudTrail_CL");
  const sample = catalogue.fieldOn("ReachCloudTrail_CL", "UserIdentity.type");
  assert.equal(sample.concept.key, "aws-cloudtrail/identity_type");
  assert.equal(sample.dictionary.values.AssumedRole.provenance, "documented");
  assert.equal(sample.binding.provenance, null, "the samples pack claims nothing about its columns");
});

test("every AWSCloudTrail column bound to a CloudTrail concept reads that concept's full entry, the same table Splunk's aws:cloudtrail reads", async () => {
  await catalogue.loadValues("AWSCloudTrail");
  let n = 0;
  for (const col of catalogue.fieldsOn("AWSCloudTrail")) {
    const v = catalogue.fieldOn("AWSCloudTrail", col);
    if (!v || !v.concept || !v.concept.key.startsWith("aws-cloudtrail/")) continue;
    const id = v.concept.key.split("/")[1];
    assert.ok(v.dictionary && v.dictionary.source === "values", `${col} (${id})`);
    assert.deepEqual(v.dictionary, values.dictionary("aws-cloudtrail", id), col);
    n += 1;
  }
  assert.ok(n >= 40, `${n} bound columns carry the dictionary`);
  const ua = catalogue.fieldOn("AWSCloudTrail", "UserAgent").dictionary;
  assert.equal(ua.provenance, "documented");
  assert.match(ua.cite.url, /cloudtrail-event-reference-record-contents/);
});
