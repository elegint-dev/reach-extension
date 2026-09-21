// The clicked value's row is concept-level, so the Sentinel table reads
// the same dictionary entry the Splunk sourcetype does: AWSCloudTrail's
// EventTypeName resolves to aws-cloudtrail/event_type and its values table.
// Platform is pinned by the first import.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import { PLATFORM } from "../app/lib/platform.js";
import { valueEntry } from "../app/lib/popup-ui.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

test("AWSCloudTrail.EventTypeName reads the entry aws:cloudtrail.eventType reads, once the table's sidecar is loaded", async () => {
  assert.equal(catalogue.valuesReady("AWSCloudTrail"), false);
  await catalogue.loadValues("AWSCloudTrail");
  const view = catalogue.fieldOn("AWSCloudTrail", "EventTypeName");
  const row = valueEntry({ catalogue, container: "AWSCloudTrail", field: "EventTypeName", value: "AwsConsoleSignIn", view });
  assert.equal(row.kind, "entry");
  assert.equal(row.source, "pack");
  assert.equal(row.concept, "aws-cloudtrail/event_type");
  assert.match(row.meaning, /^A sign-in to the AWS Management Console/);
  assert.equal(row.provenance, "documented");
  assert.match(row.cite.title, /^CloudTrail record contents/);
  // A value no table names, on a closed enum: the miss is itself signal.
  const f = valueEntry({ catalogue, container: "AWSCloudTrail", field: "EventTypeName", value: "NotAType", view });
  assert.equal(f.kind, "closed");
  assert.equal(f.count, 6);
  // A watchlist discovery read is the fallback, marked as yours.
  const w = valueEntry({ catalogue, container: "AWSCloudTrail", field: "EventTypeName", value: "Custom", view: { ...view, decode: { source: "discovered", lookup: "MyWatchlist", values: { Custom: "ours" } } } });
  assert.equal(w.source, "discovered");
  assert.equal(w.lookup, "MyWatchlist");
});
