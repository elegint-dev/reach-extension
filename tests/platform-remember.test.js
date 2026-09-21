// rememberPlatform writes the platform the next app page opens on under
// the one localStorage key platform.js reads back, and never a word other
// than sentinel or splunk.

import { test } from "node:test";
import assert from "node:assert/strict";

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.REACH_PLATFORM = "splunk";

const { rememberPlatform } = await import("../app/lib/platform.js");
const { KEYS } = await import("../app/lib/storage-keys.js");

test("sentinel and splunk are written under KEYS.platform", () => {
  rememberPlatform("sentinel");
  assert.equal(store.get(KEYS.platform), "sentinel");
  rememberPlatform("splunk");
  assert.equal(store.get(KEYS.platform), "splunk");
});

test("anything else is written as splunk", () => {
  rememberPlatform("cortex");
  assert.equal(store.get(KEYS.platform), "splunk");
  rememberPlatform(undefined);
  assert.equal(store.get(KEYS.platform), "splunk");
});

test("a storage that throws is survived", () => {
  const setItem = globalThis.localStorage.setItem;
  globalThis.localStorage.setItem = () => {
    throw new Error("quota");
  };
  assert.doesNotThrow(() => rememberPlatform("sentinel"));
  globalThis.localStorage.setItem = setItem;
});
