// Full discovery (app/lib/discovery-sweep.js): the plan leaves out fresh
// and missing sourcetypes, the runner re-runs the inventory first and then
// each sourcetype's steps one at a time through discovery.js, a failing
// sourcetype does not stop the rest, progress is persisted per sourcetype,
// cancel stops before the next step, and a resume skips what was done.
// The Splunk side is a stub answering the relay by the shape of the SPL or
// REST path. Also: the layer's writer under concurrent writers, and the
// Sentinel "copy all recipe queries" text.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

let answer = () => ({ rows: [] });
const fake = fakeChrome({ answer: (msg) => answer(msg), storage: false });
fake.install();
const calls = fake.messages;

const discovery = await import("../app/lib/discovery.js");
const layer = await import("../app/lib/layer.js");
const sweep = await import("../app/lib/discovery-sweep.js");
const store = await import("../app/lib/store.js");
const recipe = await import("../app/lib/recipe.js");
const sentinelView = await import("../app/views/discover-sentinel.js");
assert.equal(store.backend(), "memory");

const ORIGIN = "https://splunk.test";
const T0 = 1_700_000_000;

const inventoryRows = (names) => names.map((st) => ({ index: "main", sourcetype: st, count: "10", first_seen: String(T0), last_seen: String(T0 + 100) }));
const summary = (fields) => [{ field: "reach_total", count: "100" }, ...fields.map(([field, count]) => ({ field, count: String(count), distinct_count: "3", is_exact: "1", numeric_count: "0", values: "[]" }))];

// A stub Splunk: which sourcetypes the inventory returns, which have a
// lookup stanza, and which sourcetype's profile throws.
function splunk({ sourcetypes = [], lookupsOn = [], failProfile = [], failWith = null } = {}) {
  return (msg) => {
    if (msg.type === "reach:discover:run") {
      const spl = msg.spl;
      if (/^\| tstats/.test(spl)) return { rows: inventoryRows(sourcetypes) };
      if (/fieldsummary/.test(spl)) {
        const st = /sourcetype=(\S+)/.exec(spl)[1];
        if (failProfile.includes(st)) {
          if (failWith) throw failWith;
          throw new Error(`Splunk job failed: no such sourcetype ${st}`);
        }
        return { rows: summary([["user", 90], ["code", 50]]) };
      }
      if (/stats count by/.test(spl)) return { rows: [{ eventName: "ConsoleLogin", count: "5" }] };
      if (/inputlookup/.test(spl)) return { rows: [{ code: "1", label: "one" }, { code: "2", label: "two" }] };
      throw new Error(`unexpected SPL: ${spl}`);
    }
    if (msg.type === "reach:discover:rest") {
      const st = /stanza=(\S+)/.exec(msg.search || "");
      if (msg.path.endsWith("props/lookups") && st && lookupsOn.includes(st[1])) {
        return { entries: [{ name: "LOOKUP-codes", app: "search", content: { attribute: "LOOKUP-codes", transform: "codes", value: "codes code OUTPUT label", "lookup.field.input.code": "", "lookup.field.output.0.label": "" } }] };
      }
      return { entries: [] };
    }
    throw new Error(`unexpected message ${msg.type}`);
  };
}

const spls = () => calls.filter((m) => m.type === "reach:discover:run").map((m) => m.spl);
const stOf = (spl) => (/sourcetype=(\S+)/.exec(spl) || [])[1];

beforeEach(async () => {
  calls.length = 0;
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.set(sweep.KEY, {});
});

test("plan: fresh and missing sourcetypes are left out, sorted, and the switches turn that off", () => {
  const now = Date.parse("2026-09-18T12:00:00Z");
  const env = {
    sourcetypes: {
      "z:old": { profiled_at: new Date(now - 10 * 86400 * 1000).toISOString() },
      "a:fresh": { profiled_at: new Date(now - 86400 * 1000).toISOString() },
      "m:gone": { missing_since: new Date(now - 3600 * 1000).toISOString() },
      "b:new": {},
    },
  };
  const p = sweep.plan(env, { now });
  assert.deepEqual(p.run, ["b:new", "z:old"]);
  assert.deepEqual(p.skipped, [
    { sourcetype: "a:fresh", reason: "fresh" },
    { sourcetype: "m:gone", reason: "missing" },
  ]);
  assert.deepEqual(sweep.plan(env, { now, skipFresh: false, skipMissing: false }).run, ["a:fresh", "b:new", "m:gone", "z:old"]);
  assert.deepEqual(sweep.plan(null).run, []);
});

test("a sweep runs the inventory first, then each sourcetype's steps in order, one sourcetype at a time", async () => {
  answer = splunk({ sourcetypes: ["b:feed", "a:feed"], lookupsOn: ["a:feed"] });
  const seen = [];
  const off = sweep.subscribe((s) => seen.push(`${s.done}/${s.total}`));
  const final = await sweep.start(ORIGIN, { index: "*", earliest: "-7d", discriminatorFor: (st) => (st === "a:feed" ? "eventName" : null) });
  off();
  assert.equal(final.running, false);
  assert.equal(final.done, 2);
  assert.equal(final.total, 2);
  assert.equal(final.cancelled, false);
  assert.equal(final.abort, null);
  assert.deepEqual(final.errors, []);
  const order = spls();
  assert.match(order[0], /^\| tstats/, "inventory first");
  // a:feed (sorted first): profile, record types (it has a discriminator), then its one lookup; b:feed: profile only.
  assert.deepEqual(order.slice(1).map((s) => `${stOf(s) || "lookup"}:${/fieldsummary/.test(s) ? "profile" : /stats count by/.test(s) ? "structure" : "decode"}`), ["a:feed:profile", "a:feed:structure", "lookup:decode", "b:feed:profile"]);
  const rests = calls.filter((m) => m.type === "reach:discover:rest").map((m) => m.search);
  assert.equal(rests.filter((s) => s === "stanza=a:feed").length, 5, "provenance: five props reads per sourcetype (fieldaliases, calcfields, lookups, extractions, conf-props)");
  // The records are what the row buttons would have written.
  const env = (await layer.read(ORIGIN));
  assert.equal(env.sourcetypes["a:feed"].discriminator, "eventName");
  assert.deepEqual(env.sourcetypes["a:feed"].record_types, [{ value: "ConsoleLogin", count: 5 }]);
  assert.equal(env.sourcetypes["a:feed"].decodes.code.lookup, "codes");
  assert.equal(env.sourcetypes["b:feed"].record_types, undefined, "no discriminator: no record types search");
  assert.equal(env.sourcetypes["b:feed"].decodes_at, undefined, "no lookups: no decodes step");
  assert.ok(env.sourcetypes["b:feed"].provenance_at);
  assert.deepEqual(env.sweep, { at: final.finished_at, total: 2, done: 2 });
  // Progress is monotone, n of N.
  const nums = seen.map((s) => Number(s.split("/")[0]));
  for (let i = 1; i < nums.length; i++) assert.ok(nums[i] >= nums[i - 1], `monotone at ${i}: ${seen.join(" ")}`);
  assert.equal(seen[seen.length - 1], "2/2");
  // And persisted.
  const rec = await sweep.load(ORIGIN);
  assert.equal(rec.done, 2);
  assert.equal(rec.total, 2);
  assert.equal(rec.running, undefined);
  assert.equal(sweep.incomplete(rec), false);
});

test("a sourcetype whose profile throws is recorded and the rest still run", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed", "c:feed"], failProfile: ["b:feed"] });
  const final = await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(final.done, 3, "a failed step does not lose the sourcetype's slot in the count");
  assert.equal(final.errors.length, 1);
  assert.equal(final.errors[0].sourcetype, "b:feed");
  assert.equal(final.errors[0].step, "profile");
  assert.match(final.errors[0].error, /no such sourcetype/);
  assert.deepEqual(spls().filter((s) => /fieldsummary/.test(s)).map(stOf), ["a:feed", "b:feed", "c:feed"]);
  const env = (await layer.read(ORIGIN));
  assert.ok(env.sourcetypes["c:feed"].profiled_at, "c:feed ran after b:feed failed");
  assert.ok(env.sourcetypes["b:feed"].provenance_at, "b:feed's later steps still ran");
  assert.equal(sweep.progressLine(final), "3 of 3, 0 skipped, 1 failed");
  const rec = await sweep.load(ORIGIN);
  assert.equal(rec.errors.length, 1);
});

test("three relay failures in a row stop the sweep; it is persisted as incomplete", async () => {
  const gone = new Error("No open Splunk tab on https://splunk.test. Open one (and keep it open) so the request can run with your session.");
  assert.equal(sweep.isRelayError(gone), true);
  assert.equal(sweep.isRelayError(Object.assign(new Error("Your Splunk session needs a refresh."), { status: 401 })), true);
  assert.equal(sweep.isRelayError(new Error("Splunk job failed: Unknown search command")), false);
  const base = splunk({ sourcetypes: ["a:feed", "b:feed", "c:feed"] });
  answer = (msg) => {
    if (msg.type === "reach:discover:run" && /^\| tstats/.test(msg.spl)) return base(msg);
    throw gone;
  };
  const final = await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.match(final.abort, /Stopped after 3 relay failures/);
  assert.deepEqual(final.errors.map((e) => `${e.sourcetype}:${e.step}`), ["a:feed:profile", "a:feed:provenance", "b:feed:profile"], "then it stops");
  assert.equal(final.done, 1, "a:feed counted: every step of it ran, they just failed");
  assert.equal(final.current.sourcetype, "b:feed");
  const rec = await sweep.load(ORIGIN);
  assert.equal(sweep.incomplete(rec), true);
});

test("cancel stops dispatching after the step in flight, and the persisted record says where", async () => {
  const base = splunk({ sourcetypes: ["a:feed", "b:feed"], lookupsOn: ["a:feed", "b:feed"] });
  answer = (msg) => {
    const out = base(msg);
    if (msg.type === "reach:discover:run" && /fieldsummary/.test(msg.spl)) sweep.cancel(); // mid-job
    return out;
  };
  const p = sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(sweep.state().running, true);
  const final = await p;
  assert.equal(final.cancelled, true);
  assert.equal(final.running, false);
  assert.equal(final.done, 0);
  assert.deepEqual(spls().map((s) => (/^\| tstats/.test(s) ? "inventory" : `${stOf(s)}:profile`)), ["inventory", "a:feed:profile"], "nothing after the job that was in flight");
  const env = (await layer.read(ORIGIN));
  assert.ok(env.sourcetypes["a:feed"].profiled_at, "the job in flight finished and was written");
  assert.equal(env.sourcetypes["a:feed"].provenance_at, undefined);
  assert.equal(env.sweep, undefined, "not a completed sweep");
  const rec = await sweep.load(ORIGIN);
  assert.equal(rec.cancelled, true);
  assert.deepEqual(rec.current, { sourcetype: "a:feed", step: "profile" });
  assert.equal(sweep.incomplete(rec), true);
  assert.equal(sweep.progressLine(rec), "0 of 2: a:feed (profile), 0 skipped, 0 failed");
  sweep.cancel(); // not running: a no-op
});

test("resume skips what the stopped sweep already profiled and keeps its start time", async () => {
  const base = splunk({ sourcetypes: ["a:feed", "b:feed", "c:feed"] });
  let profiles = 0;
  answer = (msg) => {
    const out = base(msg);
    if (msg.type === "reach:discover:run" && /fieldsummary/.test(msg.spl) && ++profiles === 2) sweep.cancel();
    return out;
  };
  const first = await sweep.start(ORIGIN, { index: "main", earliest: "-24h" });
  assert.equal(first.done, 1);
  assert.equal(first.cancelled, true);
  calls.length = 0;
  answer = base;
  const again = await sweep.start(ORIGIN, { index: "*", earliest: "-7d", resume: true });
  assert.equal(again.started_at, first.started_at);
  assert.equal(again.index, "main", "the snapshot from the first run, not the page's box");
  assert.equal(again.window, "-24h");
  assert.match(spls()[0], /^\| tstats/, "the inventory runs again on resume");
  assert.deepEqual(spls().filter((s) => /fieldsummary/.test(s)).map(stOf), ["c:feed"], "a:feed and b:feed were profiled since started_at");
  assert.equal(again.total, 3);
  assert.equal(again.done, 3);
  assert.equal(again.cancelled, false);
  assert.ok(((await layer.read(ORIGIN))).sweep);
});

test("skipFresh leaves a recently profiled sourcetype alone and counts it as skipped", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed"] });
  await discovery.profile(ORIGIN, "a:feed", { index: "main" });
  calls.length = 0;
  const final = await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(final.skipped, 1);
  assert.equal(final.total, 1);
  assert.deepEqual(spls().filter((s) => /fieldsummary/.test(s)).map(stOf), ["b:feed"]);
  calls.length = 0;
  const all = await sweep.start(ORIGIN, { index: "*", earliest: "-7d", skipFresh: false });
  assert.equal(all.total, 2);
  const stamp = (await layer.read(ORIGIN)).sweep;
  assert.deepEqual(stamp, { at: all.finished_at, total: 2, done: 2 });
  // Everything is fresh now: a third click runs nothing and leaves the stamp alone.
  const none = await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(none.total, 0);
  assert.deepEqual((await layer.read(ORIGIN)).sweep, stamp, "a sweep that computed nothing does not move the stamp");
});

test("start refuses a second sweep while one runs", async () => {
  answer = splunk({ sourcetypes: ["a:feed"] });
  const p = sweep.start(ORIGIN, {});
  await assert.rejects(() => sweep.start(ORIGIN, {}), /already running/);
  await p;
});

test("progressLine carries the layer's storage notice after the counts, without its full stop", () => {
  const notice = 'https://splunk.test was over its 3 MB bound: dropped decode table codes on a:feed ("re-read structure" on the sourcetype reads them again).';
  const s = { started_at: "2026-09-18T12:00:00Z", done: 1, total: 2, current: null, skipped: 0, errors: [], notices: [notice] };
  assert.equal(sweep.progressLine(s), `1 of 2, 0 skipped, 0 failed; storage: ${notice.slice(0, -1)}`);
  assert.equal(sweep.progressLine({ ...s, notices: [] }), "1 of 2, 0 skipped, 0 failed");
  assert.deepEqual(sweep.state().notices, [], "the live state carries the list");
});

test("discovery: concurrent writers do not drop each other's record", async () => {
  answer = (msg) => {
    if (/fieldsummary/.test(msg.spl)) return { rows: summary([["user", 90]]) };
    return { rows: [] };
  };
  await Promise.all([
    discovery.profile(ORIGIN, "a:feed", { index: "main" }),
    discovery.profile(ORIGIN, "b:feed", { index: "main" }),
    discovery.profile(ORIGIN, "c:feed", { index: "main" }),
  ]);
  const env = (await layer.read(ORIGIN));
  assert.deepEqual(Object.keys(env.sourcetypes).sort(), ["a:feed", "b:feed", "c:feed"]);
  // A rejected write does not block the next one.
  answer = () => {
    throw new Error("Splunk job failed");
  };
  await assert.rejects(() => discovery.profile(ORIGIN, "d:feed", { index: "main" }));
  answer = (msg) => ({ rows: /fieldsummary/.test(msg.spl) ? summary([["user", 1]]) : [] });
  await discovery.profile(ORIGIN, "e:feed", { index: "main" });
  assert.ok((await layer.read(ORIGIN)).sourcetypes["e:feed"]);
});

test("discovery: timeoutMs rides the relay message only when given", async () => {
  answer = () => ({ rows: [] });
  await discovery.inventory(ORIGIN, { index: "*", earliest: "-7d", timeoutMs: 1234 });
  assert.equal(calls[0].timeoutMs, 1234);
  await discovery.inventory(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal("timeoutMs" in calls[1], false);
});

test("Sentinel: copy all recipe queries is one text, a comment header per step, blank-line separated", () => {
  const env = { label: "dev", sourcetypes: { AWSCloudTrail: { discriminator: "EventName" } } };
  const steps = [...recipe.steps(env, { packTables: [] }), ...recipe.tableSteps(env, "AWSCloudTrail", { discriminator: "EventName" })];
  const text = sentinelView.copyAllText(steps, env, { label: "dev" });
  const blocks = text.split(/\n\n+/);
  assert.equal(blocks.length, steps.length, "one block per step");
  steps.forEach((s, i) => {
    const lines = blocks[i].split("\n");
    assert.equal(lines[0], `// ${i + 1}. ${s.label}`);
    assert.equal(lines[1], `// reach step: ${s.id}`);
    const noGen = (kql) => kql.replace(/"gen", "[^"]+"/, '"gen", "T"'); // stamped at call time
    assert.equal(noGen(lines.slice(2).join("\n")), noGen(recipe.queryFor(s, env, { label: "dev" }).kql), "the wrapped query the single copy button gives");
  });
  assert.ok(/\| project reach = tostring\(pack\("meta"/.test(text));
  assert.equal(sentinelView.copyAllText([], env), "");
});
