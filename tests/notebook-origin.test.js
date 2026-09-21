// An investigation's origin (app/lib/notebook.js): the alert rule it
// started from. It lands when start() or the Hold that starts an
// investigation carries one, never on an investigation already open, it
// carries only the rule key, name and platform (no scope fact), it survives
// the store's reload and an import, and list({ rule }) and byRule() read it
// back.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const md = await import("../app/lib/notebook-md.js");
const runbooks = await import("../app/lib/runbooks.js");
assert.equal(store.backend(), "memory");

const from = (over = {}) => ({ platform: "splunk", container: "stash", scope: "main", ...over });
const pin = (field, value, over = {}) => ({ field, value, from: from({ column: field, ...over }) });
const tick = () => new Promise((r) => setTimeout(r, 2));
const ORIGIN = { ruleKey: "escu:name:disabled kerberos preauthentication discovery with getaduser", ruleName: "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser", platform: "splunk" };

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("start() with an origin keeps the rule key, name and platform and stamps when; start() without one leaves it null", async () => {
  const a = await notebook.start({ title: "a", origin: ORIGIN });
  assert.equal(a.origin.ruleKey, ORIGIN.ruleKey);
  assert.equal(a.origin.ruleName, ORIGIN.ruleName);
  assert.equal(a.origin.platform, "splunk");
  assert.ok(a.origin.at > 0);
  const b = await notebook.start({ title: "b" });
  assert.equal(b.origin ?? null, null);
});

test("the Hold that starts an investigation stamps the origin; a Hold into an open investigation does not touch it", async () => {
  assert.equal(notebook.current(), null);
  const e1 = await notebook.record(pin("dest", "WIN-DC01"), { origin: ORIGIN });
  const inv = notebook.current();
  assert.ok(inv.entries.some((e) => e.id === e1.id));
  assert.equal(inv.origin.ruleKey, ORIGIN.ruleKey);
  await notebook.record(pin("user", "jdoe"), { origin: { ...ORIGIN, ruleKey: "escu:name:another rule", ruleName: "Another" } });
  assert.equal(notebook.current().id, inv.id, "the second Hold lands in the same investigation");
  assert.equal(notebook.current().origin.ruleKey, ORIGIN.ruleKey, "the origin is the one it started from");
  assert.equal(notebook.current().entries.length, 2);
  await notebook.close(inv.id);
  await notebook.record(pin("src", "10.1.2.3"));
  assert.equal(notebook.current().origin ?? null, null, "a Hold with no rule starts an investigation with no origin");
});

test("setOrigin() sets and clears it; a scope fact in the origin is dropped, a foreign platform too", async () => {
  const inv = await notebook.start({ title: "x" });
  await notebook.setOrigin(inv.id, { ...ORIGIN, index: "main", workspace: "soc-prod", platform: "qradar" });
  const o = notebook.get(inv.id).origin;
  assert.deepEqual(Object.keys(o).sort(), ["at", "ruleKey", "ruleName"]);
  assert.equal(o.platform, undefined);
  await notebook.setOrigin(inv.id, null);
  assert.equal(notebook.get(inv.id).origin, undefined);
  await notebook.setOrigin(inv.id, { ruleName: "no key" });
  assert.equal(notebook.get(inv.id).origin, undefined, "an origin needs a rule key");
});

test("the origin survives a forced reload and an export-import round trip", async () => {
  const inv = await notebook.start({ title: "kept", origin: ORIGIN });
  await notebook.load({ force: true });
  assert.equal(notebook.get(inv.id).origin.ruleKey, ORIGIN.ruleKey);
  const doc = notebook.exportJSON(inv.id);
  await notebook.remove(inv.id);
  const back = await notebook.importDoc(JSON.stringify(doc));
  assert.deepEqual(back.origin, inv.origin);
  assert.deepEqual(md.sanitize({ id: "z", entries: [], origin: { ruleKey: " k ", ruleName: "", platform: "sentinel", at: "12" } }).origin, { ruleKey: "k", platform: "sentinel", at: 12 });
});

test("list({ rule }) narrows to one origin and byRule() groups newest group first with the unattributed last", async () => {
  const a = await notebook.start({ title: "a", origin: ORIGIN });
  await tick();
  const b = await notebook.start({ title: "b", origin: { ruleKey: "sentinel:name:gitlab - brute-force attempts", ruleName: "GitLab - Brute-force Attempts", platform: "sentinel" } });
  await tick();
  const c = await notebook.start({ title: "c" });
  await tick();
  const d = await notebook.start({ title: "d", origin: ORIGIN });
  assert.deepEqual(notebook.list({ rule: ORIGIN.ruleKey }).map((i) => i.id), [d.id, a.id]);
  const groups = notebook.byRule();
  assert.deepEqual(groups.map((g) => g.ruleKey), [ORIGIN.ruleKey, "sentinel:name:gitlab - brute-force attempts", null]);
  assert.deepEqual(groups[0].investigations.map((i) => i.id), [d.id, a.id]);
  assert.equal(groups[0].ruleName, ORIGIN.ruleName);
  assert.equal(groups[1].platform, "sentinel");
  assert.deepEqual(groups[2].investigations.map((i) => i.id), [c.id]);
  assert.deepEqual(notebook.byRule({ status: "closed" }), []);
  void b;
});

test("runbooks.originOf() turns a rule key into the origin a Hold carries: the key, the name, the platform, nothing from the row", () => {
  const rk = runbooks.ruleKeyFor({ search_name: "ESCU - Disabled Kerberos Pre-Authentication Discovery With Get-ADUser - Rule", dest: "WIN-DC01", index: "main" }, "splunk");
  const o = runbooks.originOf(rk, "splunk");
  assert.deepEqual(o, { ruleKey: rk.key, ruleName: rk.name, platform: "splunk" });
  assert.deepEqual(runbooks.originOf("sentinel:name:x", "sentinel"), { ruleKey: "sentinel:name:x", ruleName: null, platform: "sentinel" });
  assert.equal(runbooks.originOf(null, "splunk"), null);
});
