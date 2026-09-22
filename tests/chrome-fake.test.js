// tests/_chrome.js stands in for the extension APIs the way Chrome
// behaves: one onChanged per set() with every key, values copied on the
// way in and out, a reply on a later microtask, permissions by origin.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

test("storage.local: get by key, list, defaults or everything; set fires one change with every key; remove reports the old value", async () => {
  const { chrome, local } = fakeChrome();
  const events = [];
  chrome.storage.onChanged.addListener((changes, area) => events.push([area, changes]));
  await chrome.storage.local.set({ a: 1, b: { x: [1] } });
  assert.equal(events.length, 1, "one event per set()");
  assert.deepEqual(events[0], ["local", { a: { oldValue: undefined, newValue: 1 }, b: { oldValue: undefined, newValue: { x: [1] } } }]);
  assert.deepEqual(await chrome.storage.local.get("a"), { a: 1 });
  assert.deepEqual(await chrome.storage.local.get(["a", "zz"]), { a: 1 });
  assert.deepEqual(await chrome.storage.local.get({ zz: "dflt", a: 0 }), { zz: "dflt", a: 1 });
  assert.deepEqual(await chrome.storage.local.get(null), { a: 1, b: { x: [1] } });
  const read = (await chrome.storage.local.get("b")).b;
  read.x.push(2);
  assert.deepEqual(local.get("b"), { x: [1] }, "a read is a copy, as across the structured-clone boundary");
  await chrome.storage.local.remove(["a", "zz"]);
  assert.deepEqual(events[1][1], { a: { oldValue: 1, newValue: undefined } });
  assert.equal(local.has("a"), false);
});

test("deferChanges delivers onChanged on a later task, not inside set()", async () => {
  // instant: true isolates deferChanges' own task boundary from the
  // fake's default macrotask on set() itself, which is not this test's
  // subject.
  const { chrome } = fakeChrome({ deferChanges: true, instant: true });
  let seen = 0;
  chrome.storage.onChanged.addListener(() => (seen += 1));
  await chrome.storage.local.set({ k: 1 });
  assert.equal(seen, 0);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(seen, 1);
});

test("runtime.sendMessage answers from answer() on a later microtask, ok spread in, a throw as { ok: false }; without one the worker's listeners reply", async () => {
  let sync = true;
  const a = fakeChrome({ answer: (msg) => (msg.boom ? (() => { throw Object.assign(new Error("no"), { status: 503 }); })() : { rows: [msg.n] }) });
  const got = await new Promise((resolve) => {
    a.chrome.runtime.sendMessage({ n: 2 }, (res) => resolve({ res, sync }));
    sync = false;
  });
  assert.deepEqual(got, { res: { ok: true, rows: [2] }, sync: false });
  assert.deepEqual(await a.chrome.runtime.sendMessage({ boom: true }), { ok: false, error: "no", status: 503 });
  assert.deepEqual(a.messages, [{ n: 2 }, { boom: true }]);

  const b = fakeChrome({ id: "ext" });
  b.chrome.runtime.onMessage.addListener((msg, sender, respond) => {
    if (msg.type !== "ping") return false;
    setTimeout(() => respond({ ok: true, from: sender.id }), 0);
    return true;
  });
  b.chrome.runtime.onMessage.addListener(() => {
    throw new Error("a listener after the async one is never asked");
  });
  assert.deepEqual(await b.chrome.runtime.sendMessage({ type: "ping" }), { ok: true, from: "ext" });
});

test("permissions: contains needs every origin granted; request grants and notifies onAdded; remove revokes; getAll lists", async () => {
  const c = fakeChrome({ permitted: ["https://a.test/*"] });
  const added = [];
  c.chrome.permissions.onAdded.addListener((g) => added.push(g));
  assert.equal(await c.chrome.permissions.contains({ origins: ["https://a.test/*"] }), true);
  assert.equal(await c.chrome.permissions.contains({ origins: ["https://a.test/*", "https://b.test/*"] }), false);
  await c.chrome.permissions.request({ origins: ["https://b.test/*"] });
  assert.deepEqual(added, [{ origins: ["https://b.test/*"] }]);
  assert.deepEqual((await c.chrome.permissions.getAll()).origins.sort(), ["https://a.test/*", "https://b.test/*"]);
  await c.chrome.permissions.remove({ origins: ["https://a.test/*"] });
  assert.deepEqual([...c.permitted], ["https://b.test/*"]);
});

test("install puts the fake on globalThis and restore brings back what was there; storage: false leaves chrome.storage out", () => {
  const before = globalThis.chrome;
  const c = fakeChrome({ storage: false });
  const restore = c.install();
  assert.equal(globalThis.chrome, c.chrome);
  assert.equal("storage" in c.chrome, false);
  restore();
  assert.equal(globalThis.chrome, before);
  if (before === undefined) assert.equal("chrome" in globalThis, false);
});
