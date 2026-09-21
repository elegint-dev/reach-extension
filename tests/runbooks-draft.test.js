// A runbook drafted from the notebook (app/lib/runbooks-store.js
// draftFrom, adoptDraft): only closed investigations that started from the
// rule count, a draft is ready at three of them and not before, a pivot run
// in at least a third of them is a step (three of nine in, two of nine
// out) in median order, a named pivot binds to the pack edge with that
// label, a query-only pivot is a check step with the origin's value
// replaced by its field, the modal outcome and its reasons come with it,
// the draft is never written until Adopt, and Adopt puts the missing steps
// before the close step with learned_from stamped and the runbook edited.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const catalogue = await import("../app/lib/catalogue.js");
const runbooks = await import("../app/lib/runbooks.js");
const rb = await import("../app/lib/runbooks-store.js");
const notebook = await import("../app/lib/notebook.js");
await catalogue.load();
assert.equal(store.backend(), "memory");

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.splunk.notable_search_name;
const ruleKey = runbooks.ruleKeyFor(row, "splunk");
const KEY = ruleKey.key;
const HOST = "Sensors that reported under this hostname";
const USER = "Everything done to this IAM user";
const TRIED = "Which users this address tried";
const T = Date.UTC(2026, 8, 18, 14, 0, 0);

// One closed investigation of the rule: a pin on dest, the pivots named
// (or { query }) in order, an outcome with a reason.
function inv(i, { pivots = [], outcome = null, reason = null, rule = KEY, status = "closed", host = `HOST-${i}` } = {}) {
  const entries = [{ id: `p${i}`, kind: "pin", at: T + i * 1000, field: "dest", value: host, from: { platform: "splunk", container: "stash", column: "dest" } }];
  pivots.forEach((p, j) => {
    const e = { id: `v${i}-${j}`, kind: "pivot", at: T + i * 1000 + j + 1, origin: `p${i}` };
    if (typeof p === "string") e.name = p;
    else e.query = { text: p.query.replace("$host", host), language: "SPL" };
    entries.push(e);
  });
  const out = { id: `inv${i}`, title: `inv ${i}`, created: T + i * 1000, updated: T + i * 1000 + 100, closed: T + i * 1000 + 100, trigger: "", status, entries };
  if (rule) out.origin = { ruleKey: rule, ruleName: ruleKey.name, platform: "splunk", at: T };
  if (outcome) out.outcome = { result: outcome, at: out.closed, ...(reason ? { reason } : {}) };
  return out;
}

const draft = (investigations) => rb.draftFrom(KEY, { row, platform: "splunk", investigations });

beforeEach(async () => {
  await store.remove(rb.KEY);
  await store.remove(notebook.KEY);
  rb._reset();
  await rb.load();
  await notebook.load({ force: true });
});

test("a draft is not ready under three closed investigations of the rule; open ones and other rules do not count", async () => {
  const two = await draft([inv(1, { pivots: [HOST] }), inv(2, { pivots: [HOST] })]);
  assert.equal(two.ready, false);
  assert.equal(two.investigations, 2);
  assert.equal(two.needed, 3);
  assert.equal(two.label, "from your last 2 investigations");
  const padded = await draft([inv(1, { pivots: [HOST] }), inv(2, { pivots: [HOST] }), inv(3, { pivots: [HOST], status: "open" }), inv(4, { pivots: [HOST], rule: "escu:name:other" })]);
  assert.equal(padded.investigations, 2);
  assert.equal(padded.ready, false);
  const three = await draft([inv(1, { pivots: [HOST] }), inv(2, { pivots: [HOST] }), inv(3, { pivots: [HOST] })]);
  assert.equal(three.ready, true);
  assert.equal(three.label, "from your last 3 investigations");
  assert.equal(await rb.draftFrom(null), null);
});

test("a pivot run in a third of the investigations is a step, one run in fewer is not: three of nine in, two of nine out", async () => {
  const list = [];
  for (let i = 1; i <= 9; i++) list.push(inv(i, { pivots: [...(i <= 3 ? [HOST] : []), ...(i <= 2 ? [USER] : [])] }));
  const d = await draft(list);
  assert.equal(d.investigations, 9);
  assert.deepEqual(d.steps.map((s) => s.question), [HOST]);
  assert.equal(d.steps[0].count, 3);
  assert.equal(d.steps[0].of, 9);
  assert.equal(d.steps[0].why, "Run in 3 of 9 investigations, from dest.");
});

test("steps come in median order; a named pivot binds to the pack edge with that label, a query-only pivot is a check step with the value replaced by its field", async () => {
  const q = { query: 'index=main sourcetype=stash dest="$host" | stats count by user' };
  const list = [inv(1, { pivots: [USER, HOST, q] }), inv(2, { pivots: [HOST, USER, q] }), inv(3, { pivots: [HOST, q, USER] }), inv(4, { pivots: [q, HOST] })];
  const d = await draft(list);
  assert.deepEqual(d.steps.map((s) => s.question), [HOST, USER, 'Run index=main sourcetype=stash dest="$dest" | stats count by user']);
  const host = d.steps[0];
  assert.equal(host.kind, "pivot");
  // Every pack input the row carries a column for is bound from it (aid, and the workflow inputs named as columns).
  assert.deepEqual(host.pivot, { packId: "crowdstrike-falcon", edge: "cs_host_by_name", container: "crowdstrike:events:sensor", type: "hostname", binds: { value: "dest", aid: "aid", hostname: "ComputerName", pid: "RawProcessId", sha256: "SHA256String", tpid: "TargetProcessId" } });
  assert.equal(d.steps[1].pivot.edge, "ct_iam_target_user");
  const check = d.steps[2];
  assert.equal(check.kind, "check");
  assert.equal(check.pivot, null);
  assert.equal(check.query.text, 'index=main sourcetype=stash dest="$dest" | stats count by user');
  assert.equal(check.count, 4);
  assert.ok(!JSON.stringify(d).includes("HOST-1"), "no investigation's own value in the draft");
});

test("the most common outcome comes with its reasons as conditions; a tie goes to benign before escalated before inconclusive", async () => {
  const d = await draft([
    inv(1, { outcome: "benign", reason: "the DC's own scan" }),
    inv(2, { outcome: "benign", reason: "the DC's own scan" }),
    inv(3, { outcome: "escalated", reason: "an unknown source" }),
    inv(4, { outcome: "benign", reason: "the vulnerability scanner" }),
    inv(5),
  ]);
  assert.deepEqual(d.outcome, { result: "benign", count: 3, of: 5 });
  assert.deepEqual(d.benign_when, [{ text: "the DC's own scan", count: 2 }, { text: "the vulnerability scanner", count: 1 }]);
  assert.deepEqual(d.escalate_when, [{ text: "an unknown source", count: 1 }]);
  const tie = await draft([inv(1, { outcome: "inconclusive" }), inv(2, { outcome: "escalated" }), inv(3, { outcome: "inconclusive" }), inv(4, { outcome: "escalated" })]);
  assert.equal(tie.outcome.result, "escalated");
  const none = await draft([inv(1), inv(2), inv(3)]);
  assert.equal(none.outcome, null);
});

test("draftFrom(ruleKey) reads the notebook's closed investigations of the rule, the last MAX_LEARN of them, and writes nothing", async () => {
  for (let i = 1; i <= 4; i++) {
    const p = await notebook.record({ field: "dest", value: `H${i}`, from: { platform: "splunk", container: "stash", column: "dest" } }, { origin: runbooks.originOf(ruleKey, "splunk") });
    await notebook.pivot({ origin: p.id, query: { text: "x", language: "SPL" }, name: HOST });
    if (i < 4) await notebook.close(notebook.currentId(), { outcome: "escalated", evidence: { entry: p.id } });
  }
  const d = await rb.draftFrom(KEY, { row, platform: "splunk" });
  assert.equal(d.investigations, 3, "the open one does not count");
  assert.equal(d.ready, true);
  assert.deepEqual(d.steps.map((s) => [s.question, s.count]), [[HOST, 3]]);
  assert.equal(d.outcome.result, "escalated");
  assert.equal(rb.has(KEY), false, "a draft is never written");
  assert.equal(rb.MAX_LEARN, 20);
  const many = [];
  for (let i = 1; i <= 25; i++) many.push(inv(i, { pivots: i > 5 ? [] : [USER] }));
  const capped = await draft(many);
  assert.equal(capped.investigations, 20, "the last 20 by close time");
  assert.deepEqual(capped.steps, [], "the five oldest fell off the window");
});

test("Adopt puts the draft's missing steps before the close step and its conditions on the lists, stamps learned_from and marks the runbook edited; a second Adopt adds nothing twice", async () => {
  const seed = await runbooks.seedFor(ruleKey, { row, platform: "splunk" });
  const stored = await rb.seed(seed);
  const q = { query: 'index=main dest="$host" | stats count by user' };
  const d = await draft([inv(1, { pivots: [HOST, TRIED, q], outcome: "benign", reason: "the DC's own scan" }), inv(2, { pivots: [HOST, TRIED, q], outcome: "benign", reason: "the DC's own scan" }), inv(3, { pivots: [TRIED, q], outcome: "escalated", reason: "an unknown source" })]);
  const host = d.steps.find((s) => s.question === HOST);
  assert.equal(host.present, true, "the seed already runs this pivot");
  assert.equal(d.steps.find((s) => s.question === TRIED).present, false);
  const before = stored.steps.length;
  const after = await rb.adoptDraft(KEY, d);
  assert.equal(after.origin, "edited");
  assert.deepEqual(after.learned_from.investigations, 3);
  assert.ok(after.learned_from.at > 0);
  assert.equal(after.steps.length, before + 2);
  const closeAt = after.steps.findIndex((s) => s.kind === "close");
  assert.equal(closeAt, after.steps.length - 1, "close stays last");
  const tried = after.steps.find((s) => s.pivot && s.pivot.edge === "aad_ip_users");
  assert.ok(tried);
  assert.deepEqual(tried.pivot.binds, { value: "src" });
  assert.ok(after.steps.indexOf(tried) < closeAt);
  const check = after.steps.find((s) => s.kind === "check" && s.question.startsWith("Run index=main"));
  assert.match(check.why, /Run in 3 of 3 investigations, from dest\. index=main dest="\$dest"/);
  assert.ok(after.benign_when.some((c) => c.text === "the DC's own scan"));
  assert.ok(after.escalate_when.some((c) => c.text === "an unknown source"));
  const again = await rb.adoptDraft(KEY, d);
  assert.equal(again.steps.length, after.steps.length);
  assert.equal(again.benign_when.length, after.benign_when.length);
  const kept = rb.check(JSON.parse(JSON.stringify(again)));
  assert.deepEqual(kept.learned_from, again.learned_from, "learned_from survives the import check");
  const d2 = await rb.draftFrom(KEY, { row, platform: "splunk", investigations: [inv(1, { pivots: [TRIED] }), inv(2, { pivots: [TRIED] }), inv(3, { pivots: [TRIED] })] });
  assert.equal(d2.steps[0].present, true, "an adopted step reads as present next time");
});
