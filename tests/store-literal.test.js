// The literal keys in store.js (app/lib/store.js getLiteral, setLiteral,
// removeLiteral, subscribeLiteral): stored under their own name with no
// reach. prefix, so the worker and the in-page popups read the same key;
// a change reaches literal subscribers as stored and never the prefixed
// ones; the onChanged hook follows a swapped chrome object; without chrome
// the memory backend round-trips.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

const store = await import("../app/lib/store.js");

test("without chrome a literal key round-trips through the fallback and notifies its subscribers", async () => {
  assert.equal(store.backend(), "memory");
  const seen = [];
  const off = store.subscribeLiteral((k, v) => seen.push([k, v]));
  await store.setLiteral({ csIndex: "main" });
  assert.deepEqual(await store.getLiteral("csIndex"), { csIndex: "main" });
  assert.deepEqual(await store.getLiteral(["csIndex", "absent"]), { csIndex: "main" });
  await store.removeLiteral("csIndex");
  assert.deepEqual(await store.getLiteral("csIndex"), {});
  off();
  assert.deepEqual(seen, [["csIndex", "main"], ["csIndex", undefined]]);
});

test("a literal key is stored under its own name, with no reach. prefix", async () => {
  const fake = fakeChrome();
  const restore = fake.install();
  try {
    await store.setLiteral({ csIndex: "main", trustedOrigins: ["https://splunk.example.com"] });
    assert.equal(fake.local.get("csIndex"), "main");
    assert.equal(fake.local.has("reach.csIndex"), false);
    assert.deepEqual(await store.getLiteral(["csIndex", "trustedOrigins"]), { csIndex: "main", trustedOrigins: ["https://splunk.example.com"] });
    await store.removeLiteral(["csIndex", "trustedOrigins"]);
    assert.equal(fake.local.has("csIndex"), false);
  } finally {
    restore();
  }
});

test("a change to a literal key reaches literal subscribers as stored and prefixed subscribers never", async () => {
  const fake = fakeChrome();
  const restore = fake.install();
  try {
    const literal = [];
    const prefixed = [];
    const offL = store.subscribeLiteral((k, v) => literal.push([k, v]));
    const offP = store.subscribe((k, v) => prefixed.push([k, v]));
    await chrome.storage.local.set({ csIndex: "from_options" });
    await chrome.storage.local.set({ "reach.notebook": { v: 1 } });
    offL();
    offP();
    assert.deepEqual(literal.filter(([k]) => k === "csIndex"), [["csIndex", "from_options"]]);
    assert.deepEqual(prefixed, [["notebook", { v: 1 }]], "the document subscriber sees the stripped key only");
    assert.ok(!prefixed.some(([k]) => k === "csIndex"));
  } finally {
    restore();
  }
});

test("a swapped chrome object is hooked again, so a fresh fake's changes still arrive", async () => {
  const first = fakeChrome();
  let restore = first.install();
  const seen = [];
  const off = store.subscribeLiteral((k, v) => seen.push(v));
  try {
    await chrome.storage.local.set({ "reach.sentinel.alwaysPanel": true });
  } finally {
    restore();
  }
  const second = fakeChrome();
  restore = second.install();
  try {
    store.subscribeLiteral(() => {})();
    await chrome.storage.local.set({ "reach.sentinel.alwaysPanel": false });
    await chrome.storage.local.set({ "reach.sentinel.alwaysPanel": true });
  } finally {
    restore();
    off();
  }
  assert.deepEqual(seen, [true, false, true], "each change once, from whichever fake is installed");
});
