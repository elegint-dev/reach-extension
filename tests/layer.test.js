// The discovered layer's store (app/lib/layer.js): one key per environment
// plus an index, one write chain for both platforms, a byte budget that
// prunes cheapest-to-recover data first and says what it dropped, and the
// index reconciled on load. The Splunk side is a stub
// answering the relay; the Sentinel side pastes envelopes through recipe.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

let answer = () => ({ rows: [] });
fakeChrome({ answer: (msg) => answer(msg), storage: false }).install();

const store = await import("../app/lib/store.js");
const layer = await import("../app/lib/layer.js");
const discovery = await import("../app/lib/discovery.js");
const recipe = await import("../app/lib/recipe.js");
const { parse } = await import("../app/lib/intake.js");
assert.equal(store.backend(), "memory");

const ORIGIN = "https://splunk.test";
const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
const summary = (fields) => ({ rows: [{ field: "reach_total", count: "100" }, ...fields.map(([field, count]) => ({ field, count: String(count), distinct_count: "3", is_exact: "1", numeric_count: "0", values: "[]" }))] });

async function clear() {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.remove(recipe.WORKSPACES_KEY);
}

beforeEach(clear);

// A decode table of `rows` entries, stamped read_at.
function table(lookup, rows, read_at, pad = "") {
  const values = {};
  for (let i = 0; i < rows; i++) values[`code-${i}`] = `meaning number ${i} for ${lookup}${pad}`;
  return { lookup, meaning_field: "label", values, rows, read_at };
}

function top(n) {
  return Array.from({ length: n }, (_, i) => ({ value: `value-${i}-${"x".repeat(20)}`, count: n - i }));
}

test("one write chain: a Splunk profile and a Sentinel import in flight together both land, in separate keys", async () => {
  answer = (msg) => (/fieldsummary/.test(msg.spl) ? summary([["user", 90]]) : { rows: [] });
  const inv = recipe.steps(null, { packTables: [] }).find((s) => s.step === "inventory");
  const paste = JSON.stringify({ meta: { v: 1, step: "inventory", env: "dev", q: inv.q }, params: inv.params, rows: [{ DataType: "SigninLogs", mb: 12, Solution: "LogManagement", billable: true }] });
  const [a, b, c] = await Promise.all([
    discovery.profile(ORIGIN, "a:feed", { index: "main" }),
    recipe.apply(RID, parse(paste), { expect: inv }),
    discovery.profile(ORIGIN, "b:feed", { index: "main" }),
  ]);
  assert.ok(a.env.sourcetypes["a:feed"] && c.env.sourcetypes["b:feed"]);
  assert.equal(a.notice, "");
  assert.equal(b.notice, "");
  const all = await layer.readAll();
  assert.deepEqual(Object.keys(all).sort(), [RID, ORIGIN].sort());
  assert.deepEqual(Object.keys(all[ORIGIN].sourcetypes).sort(), ["a:feed", "b:feed"]);
  assert.ok(all[RID].sourcetypes.SigninLogs);
  assert.equal(all[RID].resourceId, RID);
  assert.ok(await store.get(layer.PREFIX + ORIGIN), "the Splunk environment has its own key");
  assert.ok(await store.get(layer.PREFIX + RID), "so does the workspace");
  const index = await store.get(layer.INDEX_KEY);
  assert.equal(index.version, layer.INDEX_VERSION);
  assert.deepEqual(Object.keys(index.envs).sort(), [RID, ORIGIN].sort());
  assert.equal(index.envs[ORIGIN].bytes, layer.bytes(all[ORIGIN]));
  assert.equal(index.envs[ORIGIN].discovered_at, all[ORIGIN].discovered_at);
  // The recipe's readers see the workspace and not the origin.
  assert.deepEqual((await recipe.environments()).map((e) => e.key), [RID]);
  assert.equal((await recipe.environment(RID)).sourcetypes.SigninLogs.mb, 12);
  assert.equal(await recipe.environment("nope"), null);
});

test("concurrent updates to one environment never drop a record; a rejected write does not block the next", async () => {
  await Promise.all(Array.from({ length: 8 }, (_, i) => layer.update(ORIGIN, (e) => (e.sourcetypes[`st${i}`] = { indexes: [], count: i, fields: {} }))));
  assert.equal(Object.keys((await layer.read(ORIGIN)).sourcetypes).length, 8);
  await assert.rejects(() => layer.update(ORIGIN, () => { throw new Error("bad write"); }), /bad write/);
  await layer.update(ORIGIN, (e) => (e.sourcetypes.after = {}));
  assert.ok((await layer.read(ORIGIN)).sourcetypes.after);
  assert.equal(Object.keys((await layer.read(ORIGIN)).sourcetypes).length, 9, "the failed write changed nothing");
});

test("a write to one environment leaves the other's stored value byte-identical, and the index tracks both", async () => {
  await layer.update(ORIGIN, (e) => (e.sourcetypes.a = { indexes: ["main"], count: 1, fields: {} }));
  const before = JSON.stringify(await store.get(layer.PREFIX + ORIGIN));
  await layer.update(RID, (e) => (e.sourcetypes.SigninLogs = { indexes: [], count: 2, fields: {} }));
  await layer.update(RID, (e) => (e.sourcetypes.AuditLogs = { indexes: [], count: 3, fields: {} }));
  assert.equal(JSON.stringify(await store.get(layer.PREFIX + ORIGIN)), before);
  const index = await store.get(layer.INDEX_KEY);
  assert.equal(index.envs[RID].bytes, layer.bytes(await store.get(layer.PREFIX + RID)));
  await layer.forget(RID);
  assert.equal(await layer.read(RID), null);
  assert.equal((await store.get(layer.INDEX_KEY)).envs[RID], undefined);
  assert.equal(JSON.stringify(await store.get(layer.PREFIX + ORIGIN)), before);
});

test("subscribe fires once per environment written or forgotten, with its key, never for the index", async () => {
  const seen = [];
  const off = layer.subscribe((k, env) => seen.push([k, env ? Object.keys(env.sourcetypes).length : env]));
  await layer.update(ORIGIN, (e) => (e.sourcetypes.a = {}));
  await layer.update(RID, (e) => (e.sourcetypes.b = {}));
  await layer.forget(ORIGIN);
  off();
  await layer.update(ORIGIN, (e) => (e.sourcetypes.c = {}));
  assert.deepEqual(seen, [[ORIGIN, 1], [RID, 1], [ORIGIN, undefined]]);
});

test("over the environment bound: decode tables go oldest first, then top values of the least recently profiled, then run history; the notice names them and the button", async () => {
  const opts = { envMaxBytes: 1_200 };
  const seed = (e) => {
    e.sourcetypes["a:feed"] = {
      indexes: ["main"], count: 1, profiled_at: "2026-09-01T00:00:00Z",
      fields: { user: { profile: { count: 1, top: top(50) } }, code: { profile: { count: 1, top: top(50) } } },
      decodes: { code: table("codes", 60, "2026-09-10T00:00:00Z"), kind: table("kinds", 60, "2026-09-12T00:00:00Z") },
      runs: Array.from({ length: 12 }, (_, i) => ({ kind: "profile", at: `2026-09-${String(i + 1).padStart(2, "0")}T00:00:00Z`, sample: 5000, fields: 40 })),
    };
    e.sourcetypes["b:feed"] = {
      indexes: ["main"], count: 1, profiled_at: "2026-09-15T00:00:00Z",
      fields: { user: { profile: { count: 1, top: top(50) } } },
      decodes: { status: table("statuses", 60, "2026-09-05T00:00:00Z") },
      runs: Array.from({ length: 5 }, (_, i) => ({ kind: "inventory", at: `2026-09-0${i + 1}T00:00:00Z` })),
    };
  };
  // Well within a generous bound: nothing goes.
  let r = await layer.update(ORIGIN, seed, { envMaxBytes: 1_000_000 });
  assert.equal(r.notice, "");
  const full = layer.bytes(r.env);
  assert.ok(full > 12_000 && full < 30_000, `fixture size ${full}`);

  // Just over the bound: the oldest decode table alone brings it under.
  r = await layer.update(ORIGIN, seed, { envMaxBytes: full - 1000 });
  assert.equal(r.env.sourcetypes["b:feed"].decodes.status, undefined, "statuses (read 09-05) is the oldest table");
  assert.ok(r.env.sourcetypes["a:feed"].decodes.code && r.env.sourcetypes["a:feed"].decodes.kind, "the newer tables stay");
  assert.equal(r.env.sourcetypes["a:feed"].fields.user.profile.top.length, 50, "top values untouched while a table suffices");
  assert.equal(r.notice, `${ORIGIN} was over its ${Math.round((full - 1000) / 100000) / 10} MB bound: dropped decode table statuses on b:feed ("re-read structure" on the sourcetype reads them again).`);

  // Far over: every table, then a:feed's top values (profiled before b:feed's), then runs.
  r = await layer.update(ORIGIN, seed, opts);
  assert.equal(Object.keys(r.env.sourcetypes["a:feed"].decodes).length, 0);
  assert.equal(Object.keys(r.env.sourcetypes["b:feed"].decodes).length, 0);
  assert.deepEqual(r.env.sourcetypes["a:feed"].fields.user.profile.top, []);
  assert.deepEqual(r.env.sourcetypes["a:feed"].fields.code.profile.top, []);
  assert.equal(r.env.sourcetypes["a:feed"].runs.length, layer.RUNS_AFTER_PRUNE);
  assert.equal(r.env.sourcetypes["b:feed"].runs.length, layer.RUNS_AFTER_PRUNE);
  assert.ok(layer.bytes(r.env) < full / 4, `pruned to ${layer.bytes(r.env)}`);
  assert.match(r.notice, /^https:\/\/splunk\.test was over its 0 MB bound: dropped decode tables statuses on b:feed, codes on a:feed, kinds on a:feed \("re-read structure" on the sourcetype reads them again\), dropped the top values of a:feed(, b:feed)? \("re-profile" measures them again\), trimmed run history to the last 3\.$/);
  assert.equal(r.notice.split(". ").length, 1, "one sentence");
  assert.ok(!r.notice.includes(String.fromCharCode(0x2014)), "no em dashes");
  // What the index says matches what is stored.
  assert.equal((await store.get(layer.INDEX_KEY)).envs[ORIGIN].bytes, layer.bytes(await store.get(layer.PREFIX + ORIGIN)));
});

test("a Sentinel workspace's notice names the recipe steps, and its workspace-level watchlist tables are pruned too", async () => {
  const r = await layer.update(RID, (e) => {
    e.resourceId = RID;
    e.decodes = { codes: { ...table("codes", 40, "2026-09-01T00:00:00Z"), key_field: "k" }, kinds: { ...table("kinds", 40, "2026-09-02T00:00:00Z"), key_field: "k" } };
    e.sourcetypes.SigninLogs = { indexes: [], count: 1, profiled_at: "2026-09-03T00:00:00Z", fields: { ResultType: { profile: { count: 1, top: top(30) } } } };
  }, { envMaxBytes: 1200 });
  assert.equal(r.env.decodes.codes, undefined);
  assert.equal(r.env.decodes.kinds, undefined);
  assert.deepEqual(r.env.sourcetypes.SigninLogs.fields.ResultType.profile.top, []);
  assert.equal(r.notice, `${RID} was over its 0 MB bound: dropped decode tables codes, kinds (importing the decode step's result again reads them back), dropped the top values of SigninLogs (importing the profile step's result again measures them).`);
});

test("over the layer bound: the environment with the oldest discovered_at goes, never the one being written", async () => {
  const big = (e) => (e.sourcetypes.x = { indexes: [], count: 1, fields: {}, decodes: { code: table("codes", 30, "2026-09-01T00:00:00Z") } });
  await layer.update("https://old.test", big);
  await layer.update("https://mid.test", big);
  const sizes = Object.values((await store.get(layer.INDEX_KEY)).envs).map((e) => e.bytes);
  const one = sizes[0];
  const r = await layer.update(RID, (e) => {
    e.resourceId = RID;
    big(e);
  }, { maxBytes: Math.round(one * 2.5) });
  assert.deepEqual(Object.keys(await layer.readAll()).sort(), ["https://mid.test", RID].sort());
  assert.equal(await store.get(layer.PREFIX + "https://old.test"), undefined, "the key is gone, not just the index entry");
  assert.match(r.notice, /^The discovered layer was over its 0 MB bound: forgot https:\/\/old\.test \(last discovered \d{4}-\d{2}-\d{2}\); "Inventory sourcetypes" there starts it again\.$/);
  // Written again, the forgotten environment is simply new.
  const back = await layer.update("https://old.test", (e) => (e.sourcetypes.y = {}));
  assert.equal(back.notice, "");
  assert.equal(Object.keys(await layer.readAll()).length, 3);
});

test("the shipped bounds apply by default: a 3 MB environment loses its oldest decode tables and nothing else", async () => {
  const r = await layer.update(ORIGIN, (e) => {
    e.sourcetypes["big:feed"] = { indexes: ["main"], count: 1, profiled_at: "2026-09-01T00:00:00Z", fields: { user: { profile: { count: 1, top: top(10) } } }, decodes: {}, runs: [{ kind: "profile", at: "2026-09-01T00:00:00Z" }] };
    for (let i = 0; i < 20; i++) e.sourcetypes["big:feed"].decodes[`f${i}`] = table(`lookup${i}`, 2000, `2026-09-${String(i + 1).padStart(2, "0")}T00:00:00Z`, "x".repeat(80));
  });
  assert.ok(layer.bytes(r.env) <= layer.ENV_MAX_BYTES);
  const left = Object.keys(r.env.sourcetypes["big:feed"].decodes);
  assert.ok(left.length > 0 && left.length < 20, `dropped some tables, kept ${left.length}`);
  assert.ok(!left.includes("f0") && left.includes("f19"), "oldest first");
  assert.equal(r.env.sourcetypes["big:feed"].fields.user.profile.top.length, 10);
  assert.match(r.notice, /was over its 3 MB bound: dropped decode tables lookup0 on big:feed, lookup1 on big:feed/);
  assert.match(r.notice, /and \d+ more/);
});

test("load reconciles the index: an orphaned environment key is picked up, a stale entry is dropped", async () => {
  await layer.update(ORIGIN, (e) => (e.sourcetypes.a = {}));
  await store.set(layer.PREFIX + "https://orphan.test", { sourcetypes: { z: {} }, discovered_at: "2026-09-01T00:00:00Z" });
  const idx = await store.get(layer.INDEX_KEY);
  idx.envs["https://gone.test"] = { discovered_at: "2026-01-01T00:00:00Z", bytes: 10 };
  await store.set(layer.INDEX_KEY, idx);
  assert.deepEqual(Object.keys(await layer.readAll()).sort(), [ORIGIN], "readAll before the reconcile follows the index");
  const index = await layer.load();
  assert.deepEqual(Object.keys(index.envs).sort(), ["https://orphan.test", ORIGIN].sort());
  assert.equal(index.envs["https://orphan.test"].discovered_at, "2026-09-01T00:00:00Z");
  assert.ok((await layer.readAll())["https://orphan.test"]);
});

test("bytes measures the stored JSON", () => {
  assert.equal(layer.bytes({ a: 1 }), 7);
  assert.equal(layer.bytes({ a: "é" }), 10);
  assert.equal(layer.bytes(null), 4);
});
