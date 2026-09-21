// The notebook export (app/lib/notebook-md.js) carries the rule an
// investigation started from and how it closed: a Rule line and an Outcome
// line under Trigger in the Markdown and the plain text, the same fields in
// the machine copy so the Markdown imports back with them, and neither line
// when there is nothing to say.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const md = await import("../app/lib/notebook-md.js");
assert.equal(store.backend(), "memory");

const from = (over = {}) => ({ platform: "splunk", container: "stash", scope: "main", ...over });
const pin = (field, value) => ({ field, value, from: from({ column: field }) });
const ORIGIN = { ruleKey: "escu:name:disabled kerberos preauthentication discovery with getaduser", ruleName: "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser", platform: "splunk" };

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("Markdown and plain text carry Rule and Outcome lines under Trigger, with the evidence and the reason", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"), { origin: ORIGIN });
  const inv = notebook.current();
  await notebook.setTrigger(inv.id, "notable on WIN-DC01");
  await notebook.close(inv.id, { outcome: "escalated", evidence: { entry: p.id }, reason: "no false-positive condition applied" });
  const text = notebook.exportMarkdown(inv.id);
  const lines = text.split("\n");
  const i = lines.findIndex((l) => l.startsWith("Trigger: "));
  assert.equal(lines[i + 1], "Rule: Disabled Kerberos Pre-Authentication Discovery With Get-ADUser (escu:name:disabled kerberos preauthentication discovery with getaduser, Splunk)  ");
  assert.equal(lines[i + 2], "Outcome: escalated, on Hold of dest = WIN-DC01, reason: no false-positive condition applied  ");
  assert.match(lines[i + 3], /^Started .* Status: closed /);
  const plain = notebook.exportText(inv.id);
  assert.match(plain, /\nRule: Disabled Kerberos Pre-Authentication Discovery With Get-ADUser \(escu:name:[^)]+, Splunk\)\nOutcome: escalated, on Hold of dest = WIN-DC01, reason: no false-positive condition applied\n/);
  assert.ok(!text.includes(String.fromCharCode(8212)), "plain punctuation only");
});

test("a benign close on a Mark benign reads as such; a rule with no name prints its key", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"), { origin: { ruleKey: "sentinel:name:gitlab - brute-force attempts", platform: "sentinel" } });
  const inv = notebook.current();
  const b = await notebook.add({ kind: "benign", on: p.id, field: "dest", value: "WIN-DC01", from: from({ column: "dest" }) });
  await notebook.close(inv.id, { outcome: "benign", evidence: { entry: b.id } });
  const text = notebook.exportMarkdown(inv.id);
  assert.match(text, /\nRule: sentinel:name:gitlab - brute-force attempts \(Sentinel\)  \n/);
  assert.match(text, /\nOutcome: benign, on Mark benign of dest = WIN-DC01  \n/);
});

test("the Markdown imports back with the origin and the outcome; an investigation with neither prints neither line", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"), { origin: ORIGIN });
  const inv = notebook.current();
  await notebook.close(inv.id, { outcome: "inconclusive", evidence: { entry: p.id } });
  const text = notebook.exportMarkdown(inv.id);
  await notebook.remove(inv.id);
  const back = await notebook.importDoc(text);
  assert.deepEqual(back.origin, inv.origin);
  assert.deepEqual(back.outcome, notebook.get(back.id).outcome);
  assert.equal(back.outcome.result, "inconclusive");
  const bare = await notebook.start({ title: "bare", trigger: "a hunch" });
  assert.ok(!/^Rule: |^Outcome: /m.test(notebook.exportMarkdown(bare.id)));
  assert.ok(!/^Rule: |^Outcome: /m.test(notebook.exportText(bare.id)));
  assert.equal(md.originWords(null), "");
  assert.equal(md.outcomeWords({ result: "benign" }), "benign");
});
