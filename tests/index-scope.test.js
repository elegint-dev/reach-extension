// The index is scope, not a held value (app/lib/scope.js): resolved per
// sourcetype when a pivot is generated, kept under Settings, never listed
// by the Holding rail.
import "./_splunk.js";
import { test } from "node:test";
import { fakeChrome } from "./_chrome.js";
import assert from "node:assert/strict";

function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });

const scope = await import("../app/lib/scope.js");

const tick = () => new Promise((r) => queueMicrotask(r));

test("resolve: derived when discovery found the sourcetype in one index", () => {
  assert.deepEqual(scope.resolve({ indexes: ["aws"] }), { index: "aws", state: "derived", choices: ["aws"] });
  assert.deepEqual(scope.resolve({ indexes: ["*", " aws ", "aws"] }), { index: "aws", state: "derived", choices: ["aws"] }, "wildcards and repeats are not indexes");
});

test("resolve: the Settings value overrides whatever is known", () => {
  assert.deepEqual(scope.resolve({ indexes: ["aws"], override: "main" }), { index: "main", state: "override", choices: ["aws"] });
  assert.deepEqual(scope.resolve({ indexes: ["aws", "sec"], override: "main", remembered: "sec" }), { index: "main", state: "override", choices: ["aws", "sec"] });
  assert.deepEqual(scope.resolve({ indexes: [], override: "main" }), { index: "main", state: "override", choices: [] });
});

test("resolve: several indexes and no choice is a prompt; a remembered choice answers it", () => {
  assert.deepEqual(scope.resolve({ indexes: ["aws", "sec"] }), { index: "", state: "ambiguous", choices: ["aws", "sec"] });
  assert.deepEqual(scope.resolve({ indexes: ["aws", "sec"], remembered: "sec" }), { index: "sec", state: "remembered", choices: ["aws", "sec"] });
});

test("resolve: nothing known falls back to the search's own default", () => {
  assert.deepEqual(scope.resolve({}), { index: "", state: "unknown", choices: [] });
  assert.deepEqual(scope.resolve({ indexes: ["*"] }), { index: "", state: "unknown", choices: [] });
});

test("indexFor and bind: from the stores, with the catalogue's answer for the sourcetype", async () => {
  const known = { "aws:cloudtrail": ["aws"], "crowdstrike:events:sensor": ["fdr", "fdr_archive"], "okta:system": [] };
  scope.use({ indexesFor: (st) => known[st] || [] });
  scope.setIndex("");
  for (const st of Object.keys(known)) scope.forget(st);
  scope.clearPending();

  assert.equal(scope.indexFor("aws:cloudtrail").state, "derived");
  assert.deepEqual(scope.bind({ value: "x" }, "aws:cloudtrail"), { value: "x", index: "aws" });
  assert.deepEqual(scope.bind({ value: "x", index: "typed" }, "aws:cloudtrail"), { value: "x", index: "typed" }, "an index the caller bound wins");
  const same = { value: "x" };
  assert.equal(scope.bind(same, "okta:system"), same, "unknown: the params come back untouched");
  assert.equal(scope.bind(same, "crowdstrike:events:sensor"), same, "ambiguous: untouched, and the question is raised");
  await tick(); // the announcement of that question

  let calls = 0;
  const off = scope.subscribe(() => (calls += 1));
  assert.deepEqual(scope.pending(), [{ sourcetype: "crowdstrike:events:sensor", choices: ["fdr", "fdr_archive"] }]);
  assert.equal(scope.notes("crowdstrike:events:sensor").length, 1, "the drawer gets the prompt as a note");
  assert.deepEqual(scope.notes("aws:cloudtrail"), []);
  scope.indexFor("crowdstrike:events:sensor");
  await tick();
  assert.equal(calls, 0, "asking again for the same sourcetype is silent");

  scope.remember("crowdstrike:events:sensor", "fdr");
  assert.deepEqual(scope.pending(), [], "answered");
  assert.equal(calls, 1);
  assert.deepEqual(scope.bind({}, "crowdstrike:events:sensor"), { index: "fdr" });
  assert.equal(scope.indexFor("crowdstrike:events:sensor").state, "remembered");
  assert.equal(JSON.parse(globalThis.localStorage.getItem("reach.scope")).bySourcetype["crowdstrike:events:sensor"], "fdr", "kept across sessions");

  scope.setIndex("main");
  assert.equal(scope.indexFor("crowdstrike:events:sensor").index, "main", "the Settings value overrides the choice");
  assert.equal(scope.indexFor("okta:system").index, "main", "and stands in where nothing is known");
  scope.setIndex("");
  scope.forget("crowdstrike:events:sensor");
  off();
});

test("the question is announced after the render that raised it, not inside", async () => {
  scope.use({ indexesFor: () => ["a", "b"] });
  scope.clearPending();
  let calls = 0;
  const off = scope.subscribe(() => (calls += 1));
  scope.bind({}, "two:homes");
  assert.equal(calls, 0);
  await tick();
  assert.equal(calls, 1);
  scope.clearPending();
  assert.equal(calls, 2);
  off();
});

test("learn: the clicked event's index is kept for its sourcetype; wildcards are not indexes", () => {
  scope.use({ indexesFor: () => [] });
  scope.learn("aws:cloudtrail", "aws_prod");
  assert.equal(scope.remembered("aws:cloudtrail"), "aws_prod");
  assert.deepEqual(scope.bind({}, "aws:cloudtrail"), { index: "aws_prod" });
  scope.learn("aws:cloudtrail", "*");
  scope.learn("", "other");
  assert.equal(scope.remembered("aws:cloudtrail"), "aws_prod");
  scope.forget("aws:cloudtrail");
  assert.equal(scope.remembered("aws:cloudtrail"), "");
  assert.deepEqual(scope.choices(), {});
});

// The Holding rail renders both stores as they are (app/components/holding.js
// walks Object.entries of each), so what the stores hand over is what it lists.
test("neither store lists a scope key, however it got into storage", async () => {
  assert.ok(scope.isScopeKey("index") && scope.isScopeKey("Workspace") && !scope.isScopeKey("tenant"));
  globalThis.localStorage.setItem("reach.pinned", JSON.stringify({ index: "main", workspace: "w0", tenant: "t1" }));
  globalThis.sessionStorage.setItem("reach.investigation", JSON.stringify({ index: "fdr", Workspace: "w1", aid: "abc" }));
  const pinned = await import("../app/lib/pinned.js");
  const investigation = await import("../app/lib/investigation.js");
  const facts = await import("../app/lib/facts.js");
  assert.deepEqual(pinned.all(), { tenant: "t1" });
  assert.deepEqual(investigation.all(), { aid: "abc" });
  for (const store of [pinned, investigation]) {
    store.set("index", "typed");
    store.set("workspace", "typed");
  }
  assert.deepEqual(facts.compose(pinned.all(), investigation.all()), { tenant: "t1", aid: "abc" });
  assert.deepEqual(facts.shadows(pinned.all(), investigation.all()), []);
  pinned.clear();
  investigation.clear();
});

// Inside the extension the Settings value has a second home,
// chrome.storage.local "csIndex" (the options page, the Splunk-page
// popups). The fake store is installed only here.
test("the Settings value is mirrored with chrome.storage.local csIndex", async () => {
  scope.setIndex("from_settings"); // an earlier session's value, before the shared store is in reach
  const fake = fakeChrome();
  const { local } = fake;
  local.set("csIndex", "from_options");
  const restore = fake.install();
  try {
    let calls = 0;
    const off = scope.subscribe(() => (calls += 1));
    await scope.hydrate();
    assert.equal(scope.index(), "from_options", "the shared value wins at boot");
    assert.equal(calls, 1);

    scope.setIndex("from_settings_2");
    assert.equal(local.get("csIndex"), "from_settings_2", "a change here writes through");
    assert.equal(calls, 2, "our own echo does not notify twice");

    await chrome.storage.local.set({ csIndex: "from_options_2" }); // the options page
    assert.equal(scope.index(), "from_options_2", "a change elsewhere is followed");
    assert.equal(calls, 3);

    scope.setIndex("");
    assert.equal(local.get("csIndex"), "", "clearing clears the shared copy");
    off();
  } finally {
    restore();
  }
});

test("the served app with no chrome.storage falls back to localStorage alone", async () => {
  assert.equal(typeof globalThis.chrome, "undefined");
  const fresh = await import("../app/lib/scope.js?served-app-fallback");
  await fresh.hydrate();
  fresh.setIndex("served_only");
  assert.equal(fresh.index(), "served_only");
  assert.equal(JSON.parse(globalThis.localStorage.getItem("reach.scope")).index, "served_only");
  fresh.setIndex("");
  assert.equal(fresh.index(), "");
});

