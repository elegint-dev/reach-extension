// The unknown-tier verdict's next-step hint, on both platforms
// (app/lib/bands/verdict.js verdictModel): docs/SPEC.md scenario 1's Shows
// clause names the sentence exactly, without a hash on the event.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verdictModel } from "../app/lib/bands/verdict.js";

test("the unknown tier's hint with no hash on the event reads the SPEC sentence", () => {
  const m = verdictModel({ verdict: { tier: "unknown", evidence: [], corpus: null }, input: { signing_id: "com.example.tool", path: "/tmp/x" } });
  assert.equal(m.hint, "Next: click the event's SHA256HashData for a hash check.");
});

test("the unknown tier's hint with a hash on the event points at the VirusTotal row and the pivots", () => {
  const m = verdictModel({ verdict: { tier: "unknown", evidence: [], corpus: null }, input: { sha256: "a".repeat(64) } });
  assert.equal(m.hint, "Next: the VirusTotal row, or the hash across your hosts through the pivots below.");
});
