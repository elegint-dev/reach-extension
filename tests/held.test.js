// app/lib/held.js: the store both facts stores are instances of. The
// scope-key guard lives here, on write and on read, so a caller that
// stores an `index` (the Holding add form, a Hold on an index column, an
// unpin) stores nothing and a document written by an earlier build loads
// without it.
import { test } from "node:test";
import assert from "node:assert/strict";

function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    has: (k) => m.has(k),
  };
}
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });

const { heldStore, normalizeKey, setAliases, canonicalKey, aliasesOf, aliasPairs } = await import("../app/lib/held.js");

function fresh(seed) {
  const storage = memoryStorage();
  if (seed) storage.setItem("k", JSON.stringify(seed));
  return { storage, store: heldStore({ storage: () => storage, key: "k" }) };
}

test("keys are trimmed and lowercased; an empty value removes; listeners fire once per change", () => {
  const { storage, store } = fresh();
  let calls = 0;
  const off = store.subscribe(() => (calls += 1));
  store.set(" Aid ", " abc ");
  assert.equal(store.get("AID"), "abc");
  assert.deepEqual(store.all(), { aid: "abc" });
  assert.deepEqual(JSON.parse(storage.getItem("k")), { aid: "abc" });
  store.set("aid", "");
  assert.equal(store.get("aid"), "");
  assert.equal(storage.has("k"), false, "an empty map leaves no document behind");
  assert.equal(calls, 2);
  store.set("", "x");
  assert.equal(calls, 2, "a blank key is not a change");
  off();
  store.set("aid", "again");
  assert.equal(calls, 2);
  assert.equal(normalizeKey(" X "), "x");
  assert.equal(store.normalizeKey, normalizeKey);
});

test("all() is a copy: mutating it does not reach the store", () => {
  const { store } = fresh({ aid: "abc" });
  const snap = store.all();
  snap.aid = "changed";
  snap.extra = "x";
  assert.deepEqual(store.all(), { aid: "abc" });
});

test("set() of a scope key writes nothing and notifies nobody", () => {
  const { storage, store } = fresh();
  let calls = 0;
  store.subscribe(() => (calls += 1));
  store.set("index", "main");
  store.set("Workspace", "w1");
  store.set(" INDEX ", "main");
  assert.deepEqual(store.all(), {});
  assert.equal(storage.has("k"), false);
  assert.equal(calls, 0);
  store.set("tenant", "t1");
  assert.equal(calls, 1);
  assert.deepEqual(JSON.parse(storage.getItem("k")), { tenant: "t1" });
});

test("a scope key already in storage never comes back on read", () => {
  const { storage, store } = fresh({ index: "fdr", workspace: "w1", tenant: "t1" });
  assert.deepEqual(store.all(), { tenant: "t1" });
  assert.equal(store.get("index"), "");
  assert.equal(store.get("workspace"), "");
  // Dropped from the cache, left in storage until the next write.
  assert.equal("index" in JSON.parse(storage.getItem("k")), true);
  store.set("aid", "abc");
  assert.deepEqual(JSON.parse(storage.getItem("k")), { tenant: "t1", aid: "abc" }, "the next write leaves it out");
  store.remove("index");
  assert.deepEqual(store.all(), { tenant: "t1", aid: "abc" }, "removing a scope key is a no-op, not a write");
});

test("a damaged or non-object document loads as empty", () => {
  for (const raw of ["not json", '"a string"', "42", "null", "[1]"]) {
    const storage = memoryStorage();
    storage.setItem("k", raw);
    const store = heldStore({ storage: () => storage, key: "k" });
    assert.deepEqual(store.all(), {}, raw);
  }
});

test("a storage thunk that throws leaves the store working for the render", () => {
  const store = heldStore({
    storage: () => {
      throw new Error("blocked");
    },
    key: "k",
  });
  let calls = 0;
  store.subscribe(() => (calls += 1));
  assert.deepEqual(store.all(), {});
  store.set("aid", "abc");
  assert.equal(store.get("aid"), "abc");
  assert.equal(calls, 1);
  store.clear();
  assert.deepEqual(store.all(), {});
  assert.equal(calls, 2);
});

test("clear() empties the map, removes the document and notifies", () => {
  const { storage, store } = fresh({ tenant: "t1", aid: "abc" });
  let calls = 0;
  store.subscribe(() => (calls += 1));
  store.clear();
  assert.deepEqual(store.all(), {});
  assert.equal(storage.has("k"), false);
  assert.equal(calls, 1);
});

test("the two instances: pinned on localStorage, investigation on sessionStorage, each guarded", async () => {
  globalThis.localStorage.setItem("reach.pinned", JSON.stringify({ tenant: "t0", workspace: "w0" }));
  globalThis.sessionStorage.setItem("reach.investigation", JSON.stringify({ aid: "a0", index: "stale" }));
  const pinned = await import("../app/lib/pinned.js");
  const investigation = await import("../app/lib/investigation.js");

  assert.deepEqual(pinned.all(), { tenant: "t0" });
  assert.deepEqual(investigation.all(), { aid: "a0" });

  pinned.set("region", "eu");
  investigation.set("host", "h1");
  assert.deepEqual(JSON.parse(globalThis.localStorage.getItem("reach.pinned")), { tenant: "t0", region: "eu" });
  assert.deepEqual(JSON.parse(globalThis.sessionStorage.getItem("reach.investigation")), { aid: "a0", host: "h1" });
  assert.equal(investigation.get("region"), "", "the two maps do not share");
  assert.equal(pinned.get("host"), "");

  // The call sites that hand a held name to the tab store (Hold's onHeld,
  // the Holding add form, an unpin), with the name a Splunk event or a
  // Sentinel row carries.
  const sites = {
    onHeld: (pin) => investigation.set(pin.field, pin.value),
    addForm: (name, value) => investigation.set(name, value),
    unpin: (name, value) => investigation.set(name, value),
  };
  let calls = 0;
  const off = investigation.subscribe(() => (calls += 1));
  sites.onHeld({ field: "index", value: "main" });
  sites.addForm("workspace", "w1");
  sites.unpin("Index", "fdr");
  assert.deepEqual(investigation.all(), { aid: "a0", host: "h1" });
  assert.equal(calls, 0);
  assert.equal("index" in JSON.parse(globalThis.sessionStorage.getItem("reach.investigation")), false);
  off();

  investigation.clear();
  pinned.clear();
  assert.equal(globalThis.localStorage.getItem("reach.pinned"), null);
  assert.equal(globalThis.sessionStorage.getItem("reach.investigation"), null);
});

test("aliasPairs: a workflow input named for a column, a concept-bound input and a second column on one concept all resolve to the concept's first column", () => {
  const bindings = [
    { concept: "falcon/aid", column: "aid" },
    { concept: "falcon/aid", column: "AgentIdString" },
    { concept: "falcon/raw_process_id", column: "RawProcessId" },
    { concept: "falcon/user", column: "user" },
    { concept: "cloudtrail/user", column: "user" },
    { concept: "cloudtrail/user", column: "userName" },
  ];
  const params = [{ name: "pid", column: "RawProcessId" }, { name: "aid", concept: "falcon/aid" }, { name: "host", concept: "nowhere/host" }, { name: "agent", column: "AgentIdString" }];
  const pairs = aliasPairs({ bindings, params });
  assert.deepEqual(pairs.sort(), [["agent", "aid"], ["agentidstring", "aid"], ["pid", "rawprocessid"]].sort());
  assert.ok(!pairs.some(([a]) => a === "user" || a === "username"), "a column bound to two concepts aliases nothing through it");
  assert.deepEqual(aliasPairs(), []);
});

test("setAliases: set, get and all resolve through the map; a document written before it folds on read", () => {
  setAliases([["pid", "RawProcessId"], ["tpid", "targetprocessid"], ["index", "x"], ["self", "self"]]);
  assert.equal(canonicalKey("PID"), "rawprocessid");
  assert.equal(canonicalKey("index"), "index", "a scope key is never aliased");
  assert.deepEqual(aliasesOf("RawProcessId"), ["pid"]);
  assert.deepEqual(aliasesOf("nothing"), []);
  const { storage, store } = fresh({ rawprocessid: "936", pid: "936", tpid: "77" });
  assert.deepEqual(store.all(), { rawprocessid: "936", targetprocessid: "77" }, "one fact per concept, canonical keys only");
  store.set("pid", "4820");
  assert.equal(store.get("RawProcessId"), "4820");
  assert.equal(store.get("pid"), "4820");
  assert.deepEqual(JSON.parse(storage.getItem("k")), { rawprocessid: "4820", targetprocessid: "77" });
  store.remove("pid");
  assert.equal(store.get("rawprocessid"), "");
  setAliases([]);
  assert.equal(canonicalKey("pid"), "pid");
});

test("setAliases: a chain of aliases ends at one canonical key", () => {
  setAliases([["a", "b"], ["b", "c"]]);
  assert.equal(canonicalKey("a"), "c");
  assert.equal(canonicalKey("b"), "c");
  setAliases([]);
});
