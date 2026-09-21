// Discovery keeps runs: last_seen follows the latest inventory, a sourcetype
// the latest inventory did not return is marked missing, and a re-profile
// records what moved. The Splunk side is a stub answering the relay.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

let answer = () => ({ rows: [] });
fakeChrome({ answer: (msg) => answer(msg), storage: false }).install();

const discovery = await import("../app/lib/discovery.js");
const layer = await import("../app/lib/layer.js");
const store = await import("../app/lib/store.js");
assert.equal(store.backend(), "memory");

const ORIGIN = "https://splunk.test";
const T0 = 1_700_000_000;

beforeEach(async () => {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
});

test("inventory: last_seen is this run's, first_seen is cumulative, a vanished sourcetype is marked missing", async () => {
  answer = () => ({ rows: [
    { index: "main", sourcetype: "a:feed", count: "10", first_seen: String(T0), last_seen: String(T0 + 1000) },
    { index: "sec", sourcetype: "a:feed", count: "5", first_seen: String(T0 - 500), last_seen: String(T0 + 2000) },
    { index: "main", sourcetype: "b:feed", count: "1", first_seen: String(T0), last_seen: String(T0 + 100) },
  ] });
  let r = await discovery.inventory(ORIGIN, { index: "*", earliest: "-7d" });
  let a = r.env.sourcetypes["a:feed"];
  assert.deepEqual(a.indexes.sort(), ["main", "sec"]);
  assert.equal(a.count, 15);
  assert.equal(a.first_seen, T0 - 500);
  assert.equal(a.last_seen, T0 + 2000);
  assert.equal(a.runs.length, 1);
  assert.equal(r.env.inventory.window, "-7d");

  // Second run: a:feed's newest event is older than before (nothing new
  // arrived), b:feed is gone entirely.
  answer = () => ({ rows: [{ index: "main", sourcetype: "a:feed", count: "3", first_seen: String(T0 + 100), last_seen: String(T0 + 1500) }] });
  r = await discovery.inventory(ORIGIN, { index: "*", earliest: "-7d" });
  a = r.env.sourcetypes["a:feed"];
  assert.equal(a.last_seen, T0 + 1500, "last_seen follows the latest run, not the max ever");
  assert.equal(a.first_seen, T0 - 500, "first_seen stays the earliest ever known");
  assert.equal(a.runs.length, 2);
  assert.equal(a.missing_since, undefined);
  const b = r.env.sourcetypes["b:feed"];
  assert.ok(b, "a missing sourcetype is kept");
  assert.ok(b.missing_since, "and marked missing from its first miss");
  assert.equal(b.runs[0].missing, true);
  assert.equal(discovery.health(b).missing, true);

  // An inventory scoped to an index b:feed never lived in says nothing about it.
  const since = b.missing_since;
  answer = () => ({ rows: [] });
  r = await discovery.inventory(ORIGIN, { index: "other", earliest: "-7d" });
  assert.equal(r.env.sourcetypes["b:feed"].missing_since, since);
  assert.equal(r.env.sourcetypes["b:feed"].runs.length, 2, "still the two runs from before: none recorded for a scope that did not cover it");

  // a:feed lives in main and sec. A run over main alone that returns
  // nothing has not looked in sec, not a miss.
  answer = () => ({ rows: [] });
  r = await discovery.inventory(ORIGIN, { index: "main", earliest: "-7d" });
  assert.equal(r.env.sourcetypes["a:feed"].missing_since, undefined, "partial coverage is not a miss");
  // Over both of them, it is.
  answer = () => ({ rows: [] });
  r = await discovery.inventory(ORIGIN, { index: ["main", "sec"], earliest: "-7d" });
  assert.ok(r.env.sourcetypes["a:feed"].missing_since, "full coverage and no rows is a miss");

  // It comes back: the mark clears.
  answer = () => ({ rows: [{ index: "main", sourcetype: "b:feed", count: "1", first_seen: String(T0), last_seen: String(T0 + 9000) }] });
  r = await discovery.inventory(ORIGIN, { index: "main", earliest: "-7d" });
  assert.equal(r.env.sourcetypes["b:feed"].missing_since, undefined);
});

test("profile: a re-run records new, gone and shifted fields, and drops numbers this sample did not make", async () => {
  const summary = (fields) => ({ rows: [{ field: "reach_total", count: "100" }, ...fields.map(([field, count]) => ({ field, count: String(count), distinct_count: "3", is_exact: "1", numeric_count: "0", values: "[]" }))] });
  answer = () => summary([["user", 90], ["src", 50], ["legacy", 10]]);
  let r = await discovery.profile(ORIGIN, "a:feed", { index: "main", earliest: "-24h" });
  let rec = r.env.sourcetypes["a:feed"];
  assert.equal(rec.profile_delta, null, "first profile has nothing to compare to");
  assert.equal(rec.runs[0].kind, "profile");

  answer = () => summary([["user", 88], ["src", 5], ["fresh", 40]]);
  r = await discovery.profile(ORIGIN, "a:feed", { index: "main", earliest: "-24h" });
  rec = r.env.sourcetypes["a:feed"];
  assert.deepEqual(rec.profile_delta.added, ["fresh"]);
  assert.deepEqual(rec.profile_delta.gone, ["legacy"]);
  assert.deepEqual(rec.profile_delta.fill.map((f) => f.field), ["src"], "user moved 2 points, under the shift threshold");
  assert.equal(rec.profile_delta.fill[0].from, 0.5);
  assert.equal(rec.profile_delta.fill[0].to, 0.05);
  assert.equal(rec.fields.legacy, undefined, "a field this sample did not see has no profile left");
  assert.equal(rec.runs.length, 2);
  assert.ok(discovery.health(rec).delta);
});

test("profileDelta and ageLabel are pure", () => {
  const d = discovery.profileDelta({ a: { fill: 1 }, b: { fill: 0.5 }, c: { fill: null } }, { a: { fill: 0.85 }, b: { fill: 0.55 }, c: { fill: 0.9 }, d: { fill: 1 } });
  assert.deepEqual(d, { added: ["d"], gone: [], fill: [{ field: "a", from: 1, to: 0.85 }] });
  assert.equal(discovery.ageLabel(30), "just now");
  assert.equal(discovery.ageLabel(3600 * 5), "5h ago");
  assert.equal(discovery.ageLabel(86400 * 3), "3d ago");
  assert.equal(discovery.ageLabel(null), "");
});

test("inventory: a sourcetype only ever profiled or imported is marked missing when a run over every index does not return it", async () => {
  await layer.update(ORIGIN, (e) => {
    e.sourcetypes["zzdiag_eval_st"] = { indexes: [], count: 0, fields: {}, profiled_at: "2026-09-01T00:00:00Z" };
    e.sourcetypes["ts_diag_var_b"] = { indexes: ["main"], count: 3, fields: {} };
  });
  answer = () => ({ rows: [{ index: "main", sourcetype: "a:feed", count: "3", first_seen: String(T0), last_seen: String(T0 + 10) }] });
  let r = await discovery.inventory(ORIGIN, { index: "*", earliest: "0" });
  assert.ok(r.env.sourcetypes["zzdiag_eval_st"].missing_since, "no index recorded: a run over * still covers it");
  assert.ok(r.env.sourcetypes["ts_diag_var_b"].missing_since, "never inventoried: the run over its index is the authority");
  assert.equal(r.env.sourcetypes["a:feed"].missing_since, undefined);
  // A run over one index says nothing about a record with no index at all.
  await layer.update(ORIGIN, (e) => {
    e.sourcetypes["fresh:feed"] = { indexes: [], count: 0, fields: {} };
  });
  answer = () => ({ rows: [] });
  r = await discovery.inventory(ORIGIN, { index: "main", earliest: "0" });
  assert.equal(r.env.sourcetypes["fresh:feed"].missing_since, undefined);
});
