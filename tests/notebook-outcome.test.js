// How an investigation closed (app/lib/notebook.js close): the outcome is
// one of benign, escalated, inconclusive, its evidence is a Hold or a Mark
// benign already in the investigation, a plain close records none, an
// unknown outcome rejects, reopen clears it, closing writes no pin and
// nothing to the held store, and the outcome survives the store's reload.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
assert.equal(store.backend(), "memory");
// The held (this tab) and pinned (this browser) stores: empty here, and
// they stay so.
const investigation = await import("../app/lib/investigation.js");
const pinned = await import("../app/lib/pinned.js");

const from = (over = {}) => ({ platform: "splunk", container: "stash", scope: "main", ...over });
const pin = (field, value) => ({ field, value, from: from({ column: field }) });
const ORIGIN = { ruleKey: "escu:name:disabled kerberos preauthentication discovery with getaduser", ruleName: "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser", platform: "splunk" };

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("close(id, { outcome, evidence }) records the outcome with the pin it closed on as a Hold, and when", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"), { origin: ORIGIN });
  const inv = notebook.current();
  const closed = await notebook.close(inv.id, { outcome: "escalated", evidence: { entry: p.id }, reason: "the trigger is confirmed" });
  assert.equal(closed.status, "closed");
  assert.equal(closed.outcome.result, "escalated");
  assert.equal(closed.outcome.at, closed.closed);
  assert.deepEqual(closed.outcome.evidence, { kind: "hold", entry: p.id, field: "dest", value: "WIN-DC01" });
  assert.equal(closed.outcome.reason, "the trigger is confirmed");
  assert.equal(notebook.currentId(), null);
});

test("a Mark benign entry is benign evidence; an entry not in the investigation is not evidence", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"));
  const inv = notebook.current();
  const b = await notebook.add({ kind: "benign", on: p.id, field: "dest", value: "WIN-DC01", reason: "the DC's own scan", from: from({ column: "dest" }) });
  const closed = await notebook.close(inv.id, { outcome: "benign", evidence: { entry: b.id } });
  assert.deepEqual(closed.outcome.evidence, { kind: "benign", entry: b.id, field: "dest", value: "WIN-DC01" });
  const other = await notebook.start({ title: "other" });
  const c2 = await notebook.close(other.id, { outcome: "inconclusive", evidence: { entry: p.id } });
  assert.equal(c2.outcome.result, "inconclusive");
  assert.equal(c2.outcome.evidence, undefined, "evidence must be an entry of the closing investigation");
});

test("a plain close(id) records no outcome, an outcome outside the set rejects and leaves it open", async () => {
  const inv = await notebook.start({ title: "plain" });
  const closed = await notebook.close(inv.id);
  assert.equal(closed.status, "closed");
  assert.equal(closed.outcome, undefined);
  const inv2 = await notebook.start({ title: "bad" });
  await assert.rejects(notebook.close(inv2.id, { outcome: "true positive" }), /benign, escalated, inconclusive/);
  assert.equal(notebook.get(inv2.id).status, "open");
});

test("reopen clears the outcome; closing again records the new one", async () => {
  const inv = await notebook.start({ title: "again" });
  await notebook.close(inv.id, { outcome: "benign" });
  assert.equal(notebook.get(inv.id).outcome.result, "benign");
  await notebook.reopen(inv.id);
  assert.equal(notebook.get(inv.id).outcome, undefined);
  assert.equal(notebook.get(inv.id).status, "open");
  await notebook.close(inv.id, { outcome: "escalated" });
  assert.equal(notebook.get(inv.id).outcome.result, "escalated");
});

test("closing with an outcome adds no pin and writes nothing to the held store", async () => {
  const p = await notebook.record(pin("dest", "WIN-DC01"));
  const inv = notebook.current();
  await notebook.close(inv.id, { outcome: "escalated", evidence: { entry: p.id } });
  assert.equal(notebook.get(inv.id).entries.length, 1, "the pin that was there, nothing more");
  assert.deepEqual(investigation.all(), {});
  assert.deepEqual(pinned.all(), {});
});

test("the outcome survives a forced reload and an import; an outcome on an open investigation is dropped", async () => {
  const inv = await notebook.start({ title: "kept" });
  await notebook.close(inv.id, { outcome: "benign", reason: "scanner" });
  await notebook.load({ force: true });
  assert.equal(notebook.get(inv.id).outcome.reason, "scanner");
  const doc = notebook.exportJSON(inv.id);
  doc.investigation.status = "open";
  await notebook.remove(inv.id);
  const back = await notebook.importDoc(doc);
  assert.equal(back.outcome, undefined);
});
