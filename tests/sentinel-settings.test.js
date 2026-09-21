// The Sentinel-only "always open Reach beside the menu" toggle
// (app/lib/sentinel-settings.js): chrome.storage.local only, read fresh by
// the blade's content script, cached and followed by the settings bar.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

test("read(): false with no chrome.storage (a served app, not the extension)", async () => {
  assert.equal(typeof globalThis.chrome, "undefined");
  const fresh = await import("../app/lib/sentinel-settings.js?no-chrome");
  assert.equal(await fresh.read(), false);
  assert.equal(fresh.alwaysPanel(), false, "cached value defaults false before hydrate()");
});

test("setAlwaysPanel writes through; read() sees it without hydrate()'s cache", async () => {
  const { chrome } = fakeChrome();
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/sentinel-settings.js?write-through");
    assert.equal(await fresh.read(), false);
    fresh.setAlwaysPanel(true);
    assert.equal(fresh.alwaysPanel(), true, "cache updates synchronously");
    assert.equal(await fresh.read(), true, "a fresh one-shot read sees the same write");
  } finally {
    delete globalThis.chrome;
  }
});

test("hydrate() loads the stored value once and follows later changes", async () => {
  const { chrome, local } = fakeChrome();
  local.set("reach.sentinel.alwaysPanel", true);
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/sentinel-settings.js?hydrate");
    let calls = 0;
    const off = fresh.subscribe(() => (calls += 1));
    await fresh.hydrate();
    assert.equal(fresh.alwaysPanel(), true, "the stored value is picked up at hydrate");
    assert.equal(calls, 1);

    await chrome.storage.local.set({ "reach.sentinel.alwaysPanel": false }); // e.g. the settings bar, elsewhere
    assert.equal(fresh.alwaysPanel(), false, "a later change is followed");
    assert.equal(calls, 2);
    off();
  } finally {
    delete globalThis.chrome;
  }
});
