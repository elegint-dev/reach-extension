import { test } from "node:test";
import assert from "node:assert/strict";

// A store-free double for the two facts stores, installed before the modules
// load: pinned.js reads localStorage and investigation.js sessionStorage at
// import time, and node has neither.
function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}
// defineProperty, not assignment: node's own localStorage global is an
// accessor that warns when touched without --localstorage-file.
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });
// A tenant pinned by hand; the index is scope (Settings), never a pin.
globalThis.localStorage.setItem("reach.pinned", JSON.stringify({ tenant: "t0" }));

const facts = await import("../app/lib/facts.js");
const pinned = await import("../app/lib/pinned.js");
const investigation = await import("../app/lib/investigation.js");
const scope = await import("../app/lib/scope.js");

test("compose: pinned under held, held under nothing else", () => {
  assert.deepEqual(facts.compose({ tenant: "t1", region: "eu" }, { tenant: "t2", aid: "abc" }), { tenant: "t2", region: "eu", aid: "abc" });
  assert.deepEqual(facts.compose(null, { aid: "abc" }), { aid: "abc" });
  assert.deepEqual(facts.compose({ tenant: "t1" }, undefined), { tenant: "t1" });
});

test("investigation: the index and the workspace are scope, never held", () => {
  investigation.clear();
  let calls = 0;
  const off = investigation.subscribe(() => (calls += 1));
  investigation.set("index", "main");
  investigation.set("Workspace", "w1");
  assert.deepEqual(investigation.all(), {});
  assert.equal(calls, 0);
  investigation.set("aid", "abc");
  assert.equal("index" in JSON.parse(globalThis.sessionStorage.getItem("reach.investigation")), false);
  off();
  investigation.clear();
});

test("investigation: a document from an earlier build loads without its index and workspace", async () => {
  globalThis.sessionStorage.setItem("reach.investigation", JSON.stringify({ index: "fdr", workspace: "w1", aid: "abc" }));
  const fresh = await import("../app/lib/investigation.js?stale-scope");
  assert.deepEqual(fresh.all(), { aid: "abc" });
  assert.equal(fresh.get("index"), "");
  fresh.clear();
});

test("shadows: only the pins the tab overrides with a different value", () => {
  assert.deepEqual(facts.shadows({ tenant: "t1", region: "eu", host: "h" }, { tenant: "t2", host: "h", aid: "abc" }), [{ key: "tenant", pinned: "t1", held: "t2" }]);
  assert.deepEqual(facts.shadows({}, { aid: "abc" }), []);
  assert.deepEqual(facts.shadows(null, undefined), []);
});

test("pinned: a stored pin is read back; the index is never one", () => {
  assert.equal(pinned.get("index"), "");
  assert.equal(pinned.get("tenant"), "t0");
  assert.equal(scope.index(), "");
  pinned.remove("tenant");
});

test("pinned: keys are case-insensitive, empty value removes, listeners fire", () => {
  let calls = 0;
  const off = pinned.subscribe(() => (calls += 1));
  pinned.set("Tenant", " t1 ");
  assert.equal(pinned.get("tenant"), "t1");
  assert.equal(pinned.get("TENANT"), "t1");
  pinned.set("tenant", "");
  assert.equal(pinned.get("tenant"), "");
  assert.equal(calls, 2);
  off();
  pinned.set("tenant", "t2");
  assert.equal(calls, 2);
  pinned.remove("tenant");
});

test("pinned: a scope key cannot be pinned", () => {
  let calls = 0;
  const off = pinned.subscribe(() => (calls += 1));
  pinned.set("index", "main");
  pinned.set("Workspace", "w1");
  assert.deepEqual(pinned.all(), {});
  assert.equal(calls, 0);
  off();
});

test("bound: the store-backed composition, held over pinned, never the index", () => {
  pinned.set("tenant", "t1");
  investigation.clear();
  assert.deepEqual(facts.bound(), { tenant: "t1" });
  investigation.set("tenant", "t2");
  investigation.set("aid", "abc");
  investigation.set("index", "main"); // refused by the store, not filtered here
  assert.deepEqual(facts.bound(), { tenant: "t2", aid: "abc" });
  assert.deepEqual(facts.shadowed(), [{ key: "tenant", pinned: "t1", held: "t2" }]);
  investigation.remove("tenant");
  assert.deepEqual(facts.shadowed(), []);
  assert.equal(facts.bound().tenant, "t1");
  investigation.clear();
  pinned.remove("tenant");
});

test("subscribe: one listener, either store", () => {
  let calls = 0;
  const off = facts.subscribe(() => (calls += 1));
  pinned.set("x", "1");
  investigation.set("y", "2");
  assert.equal(calls, 2);
  off();
  pinned.remove("x");
  investigation.remove("y");
  assert.equal(calls, 2);
});

test("bound() hands a held fact back under every alias, and a fact set under an alias is one fact in the store", async () => {
  const held = await import("../app/lib/held.js");
  held.setAliases([["pid", "rawprocessid"]]);
  investigation.clear();
  investigation.set("RawProcessId", "936");
  investigation.set("pid", "936");
  assert.deepEqual(investigation.all(), { rawprocessid: "936" });
  const b = facts.bound();
  assert.equal(b.pid, "936");
  assert.equal(b.rawprocessid, "936");
  assert.deepEqual(facts.expand({ rawprocessid: "1", other: "2" }), { rawprocessid: "1", other: "2", pid: "1" });
  held.setAliases([]);
  investigation.clear();
});
