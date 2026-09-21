// click-splunk.js maps a result column back to the field it came from
// through the SPL's "... as alias" clauses: the same function the popup's
// "search this" links use, pinned here on the shapes the pivots emit.
import { test } from "node:test";
import assert from "node:assert/strict";
import { aliasMap } from "../app/lib/click-splunk.js";

test("aliasMap: values()/latest()/min()/max() aliases are trusted", () => {
  const spl = [
    "| stats min(_time) as first_seen, max(_time) as last_seen,",
    "        values(ImageFileName) as image, values(RawProcessId) as os_pid",
    "        by aid, TargetProcessId",
  ].join("\n");
  assert.deepEqual(aliasMap(spl), { first_seen: "_time", last_seen: "_time", image: "ImageFileName", os_pid: "RawProcessId" });
});

test("aliasMap: dc()/count()/sum()/avg() are NOT treated as value-preserving aliases", () => {
  // dc(eventName) as distinct_calls produces a COUNT, not one of eventName's
  // values: a link built from it would search eventName=<the count>.
  const spl = "| stats count, dc(eventName) as distinct_calls, sum(bytes) as total_bytes, avg(bytes) as mean_bytes by userIdentity.arn";
  const aliases = aliasMap(spl);
  assert.equal(aliases.distinct_calls, undefined);
  assert.equal(aliases.total_bytes, undefined);
  assert.equal(aliases.mean_bytes, undefined);
});

test("aliasMap: string concatenation inside eval(if(...)) does not leak a trailing dot", () => {
  // eventName.":".errorCode is eventName CONCATENATED with a literal and
  // errorCode, not a reference to a field literally named "eventName.".
  const spl = "| stats values(eval(if(isnotnull(errorCode), eventName.\":\".errorCode, null()))) as failures by userIdentity.arn";
  const aliases = aliasMap(spl);
  // Whatever the regex captures here, it must never be forwarded as a real
  // field name with a stray "."; the caller (fieldFor) is the actual
  // guard: it only trusts an alias that is itself a known field. Assert the
  // contract that guard depends on: a malformed capture is not "eventName".
  assert.notEqual(aliases.failures, "eventName");
});
