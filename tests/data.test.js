import "./_splunk.js"; // Splunk-only code under test: the FDR bundle, SPL packs
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fields from "../app/lib/pack-fields.js";
import * as catalogue from "../app/lib/catalogue.js";

await catalogue.load();

test("index lists the pack's sourcetypes", () => {
  const sts = fields.sourcetypes();
  assert.ok(sts.includes("crowdstrike:events:sensor"));
  assert.ok(sts.includes("crowdstrike:inventory:aidmaster"));
  assert.ok(!sts.includes("aws:cloudtrail"));
});

test("sourcetypesFor: a sensor field rides on the sensor sourcetype", () => {
  assert.deepEqual(fields.sourcetypesFor("TargetProcessId"), ["crowdstrike:events:sensor"]);
});

test("fieldOn: scoped hit, definite miss, unscoped", async () => {
  const hit = fields.fieldOn("crowdstrike:events:sensor", "TargetProcessId");
  assert.equal(hit.scope, "sourcetype");
  assert.equal(hit.rec.name, "TargetProcessId");

  // The CloudTrail collision case: UserName exists in the FDR catalogue but
  // is not on aws:cloudtrail, so the scoped answer is null, not FDR's record.
  assert.equal(fields.fieldOn("aws:cloudtrail", "UserName"), null);
  assert.equal(fields.fieldOn("aws:cloudtrail", "TargetProcessId"), null);

  // A field never observed on any event cannot be placed anywhere.
  const unobserved = fields.searchIndex().fields.map((n) => fields.field(n))
    .find((r) => !(r.events || []).length && !(r.cim_targets || []).length);
  if (unobserved) {
    const u = fields.fieldOn("aws:cloudtrail", unobserved.name);
    assert.equal(u && u.scope, "unscoped");
  }
});

test("discriminators: the pack binds event_simpleName on the sensor sourcetype; inventory has none", async () => {
  const packs = await import("../app/lib/packs.js");
  await packs.load();
  const d = packs.discriminators();
  assert.equal(d["crowdstrike:events:sensor"], "event_simpleName");
  assert.equal(d["crowdstrike:inventory:aidmaster"], undefined);
});

test("eventsOn lists record types on a sourcetype", () => {
  const evs = fields.eventsOn("crowdstrike:events:sensor");
  assert.ok(evs.includes("ProcessRollup2"));
  assert.ok(evs.includes("DnsRequest"));
});
