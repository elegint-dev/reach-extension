// One versioned document under a store key (app/lib/document.js): the
// serialised writer that rereads before every mutation, the unchanged
// marker that skips the write, adoption of a damaged value, pruning past
// the budget in the document's own order, the byte count as stored, and
// the export envelope. Runs on store.js's memory backend.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const { versionedDocument, newId } = await import("../app/lib/document.js");
assert.equal(store.backend(), "memory");

const KEY = "doc-test";

function make(over = {}) {
  return versionedDocument({
    key: KEY,
    version: 2,
    empty: () => ({ v: 2, items: [] }),
    adopt: (raw) => ({ v: 2, items: raw && typeof raw === "object" && Array.isArray(raw.items) ? raw.items.filter((x) => typeof x === "string") : [] }),
    ...over,
  });
}

beforeEach(async () => {
  await store.remove(KEY);
});

test("concurrent updates serialise and each one mutates the document the one before it wrote", async () => {
  const D = make();
  await D.load();
  const results = await Promise.all([D.update((d) => d.items.push("a")), D.update((d) => d.items.push("b")), D.update((d) => d.items.push("c"))]);
  assert.deepEqual(results, [1, 2, 3], "each mutation saw the previous one's push");
  assert.deepEqual(D.get().items, ["a", "b", "c"]);
  assert.deepEqual((await store.get(KEY)).items, ["a", "b", "c"]);
});

test("a write rereads the stored document, so a change made elsewhere since the last load is not overwritten", async () => {
  const D = make();
  await D.load();
  await D.update((d) => d.items.push("mine"));
  await store.set(KEY, { v: 2, items: ["mine", "theirs"] });
  await D.update((d) => d.items.push("after"));
  assert.deepEqual((await store.get(KEY)).items, ["mine", "theirs", "after"]);
});

test("an update that returns unchanged() leaves the store alone and emits nothing", async () => {
  const D = make();
  await D.load();
  await D.update((d) => d.items.push("kept"));
  const before = JSON.stringify(await store.get(KEY));
  const events = [];
  const off = D.subscribe((ev) => events.push(ev.type));
  const out = await D.update((d) => (d.items.includes("kept") ? D.unchanged("already") : d.items.push("kept")));
  off();
  assert.equal(out, "already");
  assert.equal(JSON.stringify(await store.get(KEY)), before);
  assert.deepEqual(events, []);
});

test("a damaged or foreign stored value adopts to the empty document; the readers answer empty before load", async () => {
  const D = make();
  assert.deepEqual(D.get(), { v: 2, items: [] });
  await store.set(KEY, "garbage");
  assert.deepEqual(await D.load({ force: true }), { v: 2, items: [] });
  await store.set(KEY, { v: 1, items: ["ok", 7, null, "fine"] });
  assert.deepEqual(await D.load({ force: true }), { v: 2, items: ["ok", "fine"] });
});

test("a write from another context is adopted and announced once as a change", async () => {
  const D = make();
  await D.load();
  const events = [];
  const off = D.subscribe((ev) => events.push(ev.type));
  await store.set(KEY, { v: 2, items: ["elsewhere"] });
  off();
  assert.deepEqual(D.get().items, ["elsewhere"]);
  assert.deepEqual(events, ["change"]);
});

test("past the budget the document's own prune runs and a pruned event says what went; under it prune is never called", async () => {
  let calls = 0;
  const D = make({
    budget: 60,
    prune: (d, { bytes, budget }) => {
      calls += 1;
      const pruned = [];
      while (bytes(d) > budget && d.items.length > 1) pruned.push(d.items.shift());
      return { pruned, warning: pruned.length ? `${pruned.length} dropped` : "" };
    },
  });
  await D.load();
  const events = [];
  const off = D.subscribe((ev) => events.push(ev));
  await D.update((d) => d.items.push("short"));
  assert.equal(calls, 0, "under the budget the prune hook is not consulted");
  await D.update((d) => d.items.push("x".repeat(30), "y".repeat(30)));
  off();
  assert.equal(calls, 1);
  assert.ok(D.bytes() <= 60 || D.get().items.length === 1);
  const pruned = events.find((ev) => ev.type === "pruned");
  assert.deepEqual(pruned.pruned, ["short", "x".repeat(30)]);
  assert.equal(pruned.warning, "2 dropped");
  assert.deepEqual(D.lastPrune().pruned, ["short", "x".repeat(30)]);
  assert.deepEqual(await D.prune(), { pruned: [], warning: "" }, "an explicit prune is an empty write");
});

test("bytes counts the document as stored, in UTF-8", async () => {
  const D = make();
  await D.load();
  await D.update((d) => d.items.push("café"));
  assert.equal(D.bytes(), Buffer.byteLength(JSON.stringify(await store.get(KEY)), "utf8"));
  assert.equal(D.bytes({ v: 2, items: [] }), JSON.stringify({ v: 2, items: [] }).length);
});

test("exportJSON puts v and exported_at before the body, pretty-printed", () => {
  const D = make();
  const text = D.exportJSON({ items: ["a"] });
  assert.deepEqual(Object.keys(JSON.parse(text)), ["v", "exported_at", "items"]);
  assert.equal(JSON.parse(text).v, 2);
  assert.match(text, /^\{\n  "v": 2,\n  "exported_at": "\d{4}-/);
});

test("newId carries the prefix and does not repeat", () => {
  const a = newId("e");
  const b = newId("e");
  assert.match(a, /^e_[0-9a-z]+_[0-9a-z-]{8}$/);
  assert.notEqual(a, b);
});
