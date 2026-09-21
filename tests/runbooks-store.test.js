// The runbooks store (app/lib/runbooks-store.js): the seed is written once
// on the first open and left alone after, a stored step carries the row
// field it binds from and never a value, the edit operations mark the
// runbook edited by you, reset puts the seed back, pruning past the bound
// drops unedited seeds first, and writes from two callers serialise.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const catalogue = await import("../app/lib/catalogue.js");
const runbooks = await import("../app/lib/runbooks.js");
const rb = await import("../app/lib/runbooks-store.js");
await catalogue.load();
assert.equal(store.backend(), "memory");

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.splunk.notable_search_name;
const ruleKey = runbooks.ruleKeyFor(row, "splunk");
const seedFor = () => runbooks.seedFor(ruleKey, { row, platform: "splunk" });

beforeEach(async () => {
  await store.remove(rb.KEY);
  rb._reset();
  await rb.load();
});

test("fromSeed keeps the pack edge and the row field per parameter, never the row's value", async () => {
  const seed = await seedFor();
  const doc = rb.fromSeed(seed);
  assert.equal(doc.format, "reach-runbook");
  assert.equal(doc.id, ruleKey.key);
  assert.equal(doc.origin, "seed");
  assert.equal(doc.seeded_from.source, "escu");
  assert.deepEqual(doc.steps.map((s) => s.kind), seed.steps.map((s) => s.kind));
  const pivots = doc.steps.filter((s) => s.pivot);
  assert.ok(pivots.length >= 3);
  const host = pivots.find((s) => s.pivot.type === "hostname");
  assert.deepEqual(host.pivot, { packId: "crowdstrike-falcon", edge: "cs_host_by_name", container: "crowdstrike:events:sensor", type: "hostname", binds: { value: "dest", aid: "aid" } });
  assert.equal(host.question, "Sensors that reported under this hostname for dest");
  assert.equal(JSON.stringify(doc).includes("WIN-DC01"), false, "no row value in the stored runbook");
  assert.equal(JSON.stringify(doc).includes(row.aid), false);
});

test("seed() writes the seed on the first open and returns the stored one after, untouched", async () => {
  const seed = await seedFor();
  assert.equal(rb.has(seed.id), false);
  const first = await rb.seed(seed);
  assert.equal(rb.has(seed.id), true);
  await rb.update(seed.id, { notes: "mine" });
  const again = await rb.seed(await seedFor());
  assert.equal(again.notes, "mine", "a second open does not overwrite the analyst's runbook");
  assert.equal(again.created, first.created);
  assert.equal(rb.list().length, 1);
});

test("bind() fills a stored runbook from the row in hand: the first row's host, then another row's, spelled dest_host", async () => {
  const stored = await rb.seed(await seedFor());
  const a = rb.bind(stored, row, { platform: "splunk" });
  const hostA = a.steps.find((s) => s.pivot && s.pivot.type === "hostname");
  assert.equal(hostA.pivot.edge.id, "cs_host_by_name");
  assert.deepEqual(hostA.pivot.params, { value: "WIN-DC01", aid: row.aid });
  assert.deepEqual(hostA.pivot.bound, ["value", "aid"]);
  assert.deepEqual(hostA.pivot.missing, []);
  const b = rb.bind(stored, { dest_host: "SRV-02" }, { platform: "splunk" });
  const hostB = b.steps.find((s) => s.pivot && s.pivot.type === "hostname");
  assert.deepEqual(hostB.pivot.params, { value: "SRV-02" }, "the same type on another field name binds");
  assert.deepEqual(hostB.pivot.missing, [{ param: "aid", field: "aid" }]);
  assert.equal(b.bound, 1);
  assert.ok(a.bound > b.bound);
});

test("the edit operations: add, rename, note, pivot, move, remove; each marks the runbook edited by you", async () => {
  const seed = await seedFor();
  const id = seed.id;
  await rb.seed(seed);
  assert.equal(rb.get(id).origin, "seed");
  const added = await rb.addStep(id, { question: "Was the account created in the last day?" });
  assert.equal(added.kind, "check");
  assert.equal(rb.get(id).origin, "edited");
  assert.ok(rb.get(id).edited_at > 0);
  assert.equal(rb.get(id).steps.at(-1).id, added.id);
  await rb.updateStep(id, added.id, { question: "Account age?", why: "New accounts are the usual false positive." });
  const s = rb.get(id).steps.find((x) => x.id === added.id);
  assert.equal(s.question, "Account age?");
  assert.equal(s.why, "New accounts are the usual false positive.");
  const option = runbooks.pivotOptions(row, "splunk").find((o) => o.type === "user_name");
  await rb.updateStep(id, added.id, { pivot: option.pivot });
  assert.equal(rb.get(id).steps.find((x) => x.id === added.id).kind, "pivot");
  await rb.updateStep(id, added.id, { pivot: null });
  assert.equal(rb.get(id).steps.find((x) => x.id === added.id).kind, "check");
  const n = rb.get(id).steps.length;
  await rb.moveStep(id, added.id, -1);
  assert.equal(rb.get(id).steps[n - 2].id, added.id);
  await rb.moveStep(id, added.id, -100);
  assert.equal(rb.get(id).steps[0].id, added.id, "a move past the ends clamps");
  await rb.removeStep(id, added.id);
  assert.equal(rb.get(id).steps.length, n - 1);
  await rb.update(id, { benign_when: ["Admins running Get-ADUser from the tier-0 jump host", ""], escalate_when: [{ text: "Any other host" }], notes: "Ask IAM first." });
  const cur = rb.get(id);
  assert.deepEqual(cur.benign_when, [{ text: "Admins running Get-ADUser from the tier-0 jump host" }]);
  assert.deepEqual(cur.escalate_when, [{ text: "Any other host" }]);
  assert.equal(cur.notes, "Ask IAM first.");
  await assert.rejects(() => rb.removeStep(id, "nosuch"), /No step nosuch/);
  await assert.rejects(() => rb.updateStep("escu:id:nosuch", "x", {}), /No runbook/);
});

test("a runbook keeps at least one step", async () => {
  const seed = await seedFor();
  await rb.seed(seed);
  const ids = rb.get(seed.id).steps.map((s) => s.id);
  for (const sid of ids.slice(1)) await rb.removeStep(seed.id, sid);
  await assert.rejects(() => rb.removeStep(seed.id, ids[0]), /at least one step/);
});

test("reset() puts the seed back over the edits, keeps the creation time and drops the edited label", async () => {
  const seed = await seedFor();
  const stored = await rb.seed(seed);
  await rb.update(seed.id, { notes: "gone after reset" });
  await rb.addStep(seed.id, { question: "extra" });
  const back = await rb.reset(seed.id, await seedFor());
  assert.equal(back.origin, "seed");
  assert.equal(back.notes, "");
  assert.equal(back.created, stored.created);
  assert.equal("edited_at" in back, false);
  assert.deepEqual(back.steps.map((s) => s.id), stored.steps.map((s) => s.id));
  assert.throws(() => rb.reset("escu:id:other", seed), /is for/);
});

test("writes from two callers serialise on one chain and both land", async () => {
  const seed = await seedFor();
  await rb.seed(seed);
  await Promise.all([rb.addStep(seed.id, { question: "one" }), rb.addStep(seed.id, { question: "two" }), rb.update(seed.id, { notes: "three" })]);
  const cur = rb.get(seed.id);
  assert.deepEqual(cur.steps.slice(-2).map((s) => s.question), ["one", "two"]);
  assert.equal(cur.notes, "three");
  assert.deepEqual(JSON.parse(JSON.stringify(await store.get(rb.KEY))).runbooks[seed.id].notes, "three");
});

test("past the size bound the oldest unedited seeds go first, never an edited runbook while a seed remains", async () => {
  const seed = await seedFor();
  // 40 steps of 4,000 characters: about 160 KB per runbook, so the fourth crosses the bound.
  const steps = Array.from({ length: 40 }, (_, i) => ({ id: `s${i}`, kind: "check", question: `step ${i}`, why: "x".repeat(4000) }));
  const mk = (i, edited) => ({ ...rb.fromSeed(seed), id: `escu:id:${String(i).padStart(8, "0")}-0000-4000-8000-000000000000`, steps, origin: edited ? "edited" : "seed", updated: 1000 + i, created: 1000 + i });
  for (const [i, edited] of [[0, false], [1, true], [2, false]]) await rb.importDoc({ runbooks: [mk(i, edited)] });
  assert.equal(rb.list().length, 3);
  const events = [];
  const off = rb.subscribe((ev) => events.push(ev));
  await rb.importDoc({ runbooks: [mk(3, true)] });
  off();
  const left = rb.list();
  assert.ok(rb.bytes() <= rb.MAX_BYTES);
  assert.deepEqual(left.map((r) => r.id.slice(8, 16)).sort(), ["00000001", "00000002", "00000003"], "the oldest seed went, the older edited runbook stayed");
  const pruned = events.find((e) => e.type === "pruned");
  assert.deepEqual(pruned.pruned.map((p) => p.origin), ["seed"]);
  assert.match(pruned.warning, /over their 500 KB bound/);
});

test("a damaged document in the store becomes an empty one, and a foreign runbook inside it is dropped", async () => {
  await store.set(rb.KEY, { v: 1, runbooks: { "escu:id:x": { format: "nope" }, "not-a-key": {} } });
  await rb.load({ force: true });
  assert.deepEqual(rb.list(), []);
  await store.set(rb.KEY, "garbage");
  await rb.load({ force: true });
  assert.deepEqual(rb.list(), []);
});
