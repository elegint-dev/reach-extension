import { test } from "node:test";
import assert from "node:assert/strict";
import { inventorySpl, profileSpl, recordTypesSpl, evalRefs } from "../app/lib/discovery.js";

test("inventory SPL is the fixed tstats shape", () => {
  assert.equal(inventorySpl(), "| tstats count, min(_time) as first_seen, max(_time) as last_seen where index=* by index, sourcetype");
  assert.equal(inventorySpl({ index: "main" }), "| tstats count, min(_time) as first_seen, max(_time) as last_seen where index=main by index, sourcetype");
});

test("profile SPL quotes anything unsafe and clamps the sample", () => {
  assert.equal(profileSpl({ sourcetype: "aws:cloudtrail", index: "main" }), "search index=main sourcetype=aws:cloudtrail | head 5000 | eval reach_total=1 | fieldsummary maxvals=10");
  const evil = profileSpl({ sourcetype: 'x" | delete', index: "main", sample: 10 ** 9 });
  assert.ok(evil.includes('sourcetype="x\\" | delete"'));
  assert.ok(evil.includes("| head 100000 |"));
});

test("profile and record-types SPL span every index the sourcetype lives in", () => {
  assert.equal(profileSpl({ sourcetype: "crowdstrike:events:sensor", index: ["main", "crowdstrike"] }), "search (index=main OR index=crowdstrike) sourcetype=crowdstrike:events:sensor | head 5000 | eval reach_total=1 | fieldsummary maxvals=10");
  assert.ok(recordTypesSpl({ sourcetype: "x", field: "f", index: ["a", "b"] }).startsWith("search (index=a OR index=b) sourcetype=x"));
});

test("record-types SPL", () => {
  assert.equal(recordTypesSpl({ sourcetype: "crowdstrike:events:sensor", field: "event_simpleName", index: "main" }), "search index=main sourcetype=crowdstrike:events:sensor | head 20000 | stats count by event_simpleName | sort - count");
});

test("evalRefs finds quoted and bare field references, not functions or strings", () => {
  const refs = evalRefs(`if('userIdentity.type'="AWSAccount" OR 'userIdentity.type'="AWSService", recipientAccountId, 'userIdentity.accountId')`);
  assert.deepEqual(refs.sort(), ["recipientAccountId", "userIdentity.accountId", "userIdentity.type"]);
  assert.deepEqual(evalRefs(`coalesce(errorCode, "success")`), ["errorCode"]);
});
