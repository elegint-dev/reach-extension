// app/lib/onboarding.js: whether the start page's first-install card
// shows. Fresh module per test (query-string cache-bust), the same shape
// tests/sentinel-settings.test.js uses, since the module's cache and
// hydrate() memo are module-scoped singletons.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

test("no chrome and nothing dismissed: shows, not enabled (the served harness case)", async () => {
  assert.equal(typeof globalThis.chrome, "undefined");
  const fresh = await import("../app/lib/onboarding.js?no-chrome");
  assert.equal(fresh.shouldShow(), true, "default before hydrate() is the safe one: show");
  await fresh.hydrate();
  assert.equal(fresh.shouldShow(), true, "no chrome.storage: enabled count stays 0");
});

test("hydrate() reads a nonempty trustedOrigins as enabled: the card hides", async () => {
  const { chrome, local } = fakeChrome();
  local.set("trustedOrigins", ["https://splunk.example.com"]);
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?enabled");
    await fresh.hydrate();
    assert.equal(fresh.shouldShow(), false);
  } finally {
    delete globalThis.chrome;
  }
});

test("hydrate() reads no trustedOrigins: the card shows until dismissed", async () => {
  const { chrome } = fakeChrome();
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?not-enabled");
    await fresh.hydrate();
    assert.equal(fresh.shouldShow(), true);
    fresh.dismiss();
    assert.equal(fresh.shouldShow(), false);
  } finally {
    delete globalThis.chrome;
  }
});

test("dismiss() writes through; a fresh hydrate() elsewhere sees it stay dismissed", async () => {
  const { chrome, local } = fakeChrome();
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?dismiss-writes-through");
    await fresh.hydrate();
    fresh.dismiss();
    assert.equal(local.get("reach.onboarding.dismissed"), true);
  } finally {
    delete globalThis.chrome;
  }
});

test("reset() (Settings' show setup again) brings a dismissed card back", async () => {
  const { chrome, local } = fakeChrome();
  local.set("reach.onboarding.dismissed", true);
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?reset");
    await fresh.hydrate();
    assert.equal(fresh.shouldShow(), false);
    fresh.reset();
    assert.equal(fresh.shouldShow(), true);
    assert.equal(local.has("reach.onboarding.dismissed"), false);
  } finally {
    delete globalThis.chrome;
  }
});

test("subscribe() fires only on the show/hide flip, not on every write", async () => {
  const { chrome } = fakeChrome();
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?subscribe-flip");
    await fresh.hydrate();
    let calls = 0;
    const off = fresh.subscribe(() => (calls += 1));
    fresh.dismiss(); // true → false: a flip
    assert.equal(calls, 1);
    fresh.dismiss(); // already false: no flip
    assert.equal(calls, 1);
    fresh.reset(); // false → true: a flip
    assert.equal(calls, 2);
    off();
  } finally {
    delete globalThis.chrome;
  }
});

test("cardModel(): the Splunk step names the Splunk search page and its button, shown while the card should show", async () => {
  const fresh = await import("../app/lib/onboarding.js?card-model-splunk");
  const model = fresh.cardModel();
  assert.equal(model.show, true);
  assert.match(model.steps[0], /Open your Splunk search page/);
  assert.match(model.steps[0], /Enable on this Splunk instance/);
  assert.match(model.steps[1], /Click any value in an event/);
  assert.match(model.note, /Nothing runs until you click/);
});

test("cardModel().show tracks shouldShow(): false once dismissed", async () => {
  const fresh = await import("../app/lib/onboarding.js?card-model-dismissed");
  fresh.dismiss();
  assert.equal(fresh.cardModel().show, false);
});

test("a later trustedOrigins change is followed after hydrate()", async () => {
  const { chrome } = fakeChrome();
  globalThis.chrome = chrome;
  try {
    const fresh = await import("../app/lib/onboarding.js?follow-origins");
    await fresh.hydrate();
    assert.equal(fresh.shouldShow(), true);
    await chrome.storage.local.set({ trustedOrigins: ["https://splunk.example.com"] }); // e.g. popup.js, elsewhere
    assert.equal(fresh.shouldShow(), false);
  } finally {
    delete globalThis.chrome;
  }
});
