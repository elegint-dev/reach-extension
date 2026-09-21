// apply() from the app in its own tab: the active tab is the app itself,
// so a request that names a Splunk instance goes on to the search pages
// open on that origin, the last used first, and the first with a search
// bar takes the text; the active tab still comes first (the side panel
// sits beside it) and a request without an origin never looks further.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as bridge from "../app/lib/editor-bridge.js";
import { fakeChrome } from "./_chrome.js";

const ORIGIN = "https://splunk.example";
const SPL = "search index=main sourcetype=x\n| stats count";

// tabs: id -> reply of its content script (a thrown error stands for no script there).
function withTabs({ active, byOrigin, reply }, fn) {
  const fake = fakeChrome({ id: "reach" });
  const queries = [];
  const sent = [];
  fake.chrome.tabs = {
    query: async (opts) => {
      queries.push(opts);
      if (opts.active) return active ? [active] : [];
      return opts.url === `${ORIGIN}/*` ? byOrigin : [];
    },
    sendMessage: async (tabId, msg) => {
      sent.push([tabId, msg]);
      const r = reply[tabId];
      if (r instanceof Error) throw r;
      return r;
    },
  };
  const restore = fake.install();
  return Promise.resolve()
    .then(() => fn({ queries, sent }))
    .finally(restore);
}

const noScript = () => new Error("Could not establish connection");

test("with an origin, the app's own active tab is skipped for the search page open on that origin, and the text lands there", async () => {
  await withTabs(
    { active: { id: 1 }, byOrigin: [{ id: 5, lastAccessed: 10 }, { id: 7, lastAccessed: 20 }], reply: { 1: noScript(), 5: { ok: true, how: "set", notice: "Search set" }, 7: { ok: false, how: null, notice: "no search bar on this page" } } },
    async ({ queries, sent }) => {
      const res = await bridge.apply({ text: SPL, mode: "set", form: "stage", platform: "splunk", origin: ORIGIN });
      assert.deepEqual(res, { ok: true, how: "set", notice: "Search set" });
      assert.deepEqual(queries, [{ active: true, lastFocusedWindow: true }, { url: `${ORIGIN}/*` }]);
      // The last used tab first (7), then the one with a bar (5); the origin never rides in the message.
      assert.deepEqual(sent.map(([id]) => id), [1, 7, 5]);
      for (const [, msg] of sent) assert.deepEqual(msg, { type: bridge.APPLY_MESSAGE, text: SPL, mode: "set", form: "stage", platform: "splunk" });
    },
  );
});

test("the active tab with a search bar takes the text before any other tab on the origin", async () => {
  await withTabs({ active: { id: 3 }, byOrigin: [{ id: 3 }, { id: 4 }], reply: { 3: { ok: true, how: "set", notice: "Search set" }, 4: { ok: true, how: "set", notice: "Search set" } } }, async ({ sent }) => {
    const res = await bridge.apply({ text: SPL, mode: "set", form: "stage", platform: "splunk", origin: ORIGIN });
    assert.equal(res.how, "set");
    assert.deepEqual(sent.map(([id]) => id), [3]);
  });
});

test("without an origin only the active tab is asked, and no bar there means the clipboard", async () => {
  const written = [];
  const had = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => written.push(t) } }, configurable: true, writable: true });
  try {
    await withTabs({ active: { id: 1 }, byOrigin: [{ id: 5 }], reply: { 1: noScript(), 5: { ok: true, how: "set", notice: "Search set" } } }, async ({ queries, sent }) => {
      const res = await bridge.apply({ text: SPL, mode: "set", form: "stage", platform: "splunk" });
      assert.equal(res.how, "copied");
      assert.match(res.notice, /No Splunk search bar in the active tab/);
      assert.deepEqual(queries, [{ active: true, lastFocusedWindow: true }]);
      assert.deepEqual(sent.map(([id]) => id), [1]);
    });
  } finally {
    if (had) Object.defineProperty(globalThis, "navigator", had);
    else delete globalThis.navigator;
  }
  assert.deepEqual(written, [SPL]);
});

test("with an origin but no search page open on it, the tab's own answer is kept and the text is copied with its notice", async () => {
  const written = [];
  const had = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => written.push(t) } }, configurable: true, writable: true });
  try {
    await withTabs({ active: { id: 1 }, byOrigin: [{ id: 2 }], reply: { 1: noScript(), 2: { ok: false, how: null, notice: "no search bar on this page" } } }, async ({ sent }) => {
      const res = await bridge.apply({ text: SPL, mode: "set", form: "stage", platform: "splunk", origin: ORIGIN });
      assert.equal(res.how, "copied");
      assert.match(res.notice, /no search bar on this page; copied instead/);
      assert.deepEqual(sent.map(([id]) => id), [1, 2]);
    });
  } finally {
    if (had) Object.defineProperty(globalThis, "navigator", had);
    else delete globalThis.navigator;
  }
  assert.deepEqual(written, [SPL]);
});
