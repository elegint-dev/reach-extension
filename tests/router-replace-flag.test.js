// The router flags every hashchange it raises itself: a replace() lands on
// the same history entry and says so, so the trail relabels instead of
// adding a hop; a hashchange the router did not raise carries no flag.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as router from "../app/lib/router.js";

function fakeWindow(hash = "#/") {
  const listeners = {};
  const w = {
    location: { hash },
    history: { length: 1, replaceState: (_s, _t, url) => { w.location.hash = url; } },
    Event: class { constructor(type) { this.type = type; } },
    addEventListener: (type, fn) => (listeners[type] = listeners[type] || []).push(fn),
    removeEventListener: (type, fn) => { listeners[type] = (listeners[type] || []).filter((f) => f !== fn); },
    dispatchEvent: (e) => { for (const fn of listeners[e.type] || []) fn(e); return true; },
  };
  return w;
}

test("replace() fires onChange once with replaced: true and no history entry is added", () => {
  const w = fakeWindow("#/catalogue");
  globalThis.window = w;
  try {
    const calls = [];
    const stop = router.start((state, meta) => calls.push([state.route, meta]), w);
    assert.deepEqual(calls, [["catalogue", { replaced: false }]], "the first fire is the page as loaded");
    router.replace("packs", {});
    assert.equal(w.location.hash, "#/packs");
    assert.equal(w.history.length, 1);
    assert.deepEqual(calls[1], ["packs", { replaced: true }]);
    assert.equal(calls.length, 2);
    stop();
  } finally {
    delete globalThis.window;
  }
});

test("a hashchange the router did not raise arrives with replaced: false", () => {
  const w = fakeWindow("#/");
  globalThis.window = w;
  try {
    const calls = [];
    const stop = router.start((state, meta) => calls.push([state.route, meta.replaced]), w);
    w.location.hash = "#/discover";
    w.dispatchEvent(new w.Event("hashchange"));
    assert.deepEqual(calls.at(-1), ["discover", false]);
    stop();
  } finally {
    delete globalThis.window;
  }
});

test("the flag does not leak: after replace() throws inside a listener the next hashchange is unflagged", () => {
  const w = fakeWindow("#/");
  globalThis.window = w;
  try {
    let boom = true;
    const calls = [];
    const stop = router.start((state, meta) => {
      calls.push(meta.replaced);
      if (boom && meta.replaced) throw new Error("render failed");
    }, w);
    assert.throws(() => router.replace("packs", {}));
    boom = false;
    w.location.hash = "#/share";
    w.dispatchEvent(new w.Event("hashchange"));
    assert.deepEqual(calls, [false, true, false]);
    stop();
  } finally {
    delete globalThis.window;
  }
});
