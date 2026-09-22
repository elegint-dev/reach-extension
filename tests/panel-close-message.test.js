// it_3cb327f3: index.html opened as a top-level tab tells the background
// once (reach:app:opened); the window's open panel, if any, is told to
// close (reach:panel:close, over its own port); the side panel is turned
// off for that one tab so it does not reopen there on its own. A framed
// sender is refused. The popup never sees this: it has no port in the
// background's panel map and registers no onMessage listener of its own.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fakeChrome } from "./_chrome.js";

const EXT_ID = "test-ext";
const fake = fakeChrome({ id: EXT_ID });
fake.chrome.permissions.contains = async () => true;
fake.chrome.sidePanel = { calls: [], setOptions(opts) { this.calls.push(opts); return Promise.resolve(); } };
fake.install();
await import("../background.js");

function fakePort(windowId) {
  const messages = [];
  const listeners = [];
  const port = {
    name: "reach-panel",
    sender: { id: EXT_ID },
    onMessage: { addListener: (fn) => listeners.push(fn) },
    onDisconnect: { addListener: () => {} },
    postMessage: (msg) => messages.push(msg),
  };
  for (const fn of fake.connectListeners) fn(port);
  for (const fn of listeners) fn({ type: "reach:panel:hello", windowId });
  return messages;
}

const send = (msg, sender) => fake.deliver(fake.bgListeners, msg, sender);

test("a top-level tab open sends the window's panel one close message", async () => {
  const messages = fakePort(5);
  await send({ type: "reach:app:opened", windowId: 5 }, { id: EXT_ID, tab: { id: 9, windowId: 5 }, frameId: 0 });
  assert.deepEqual(messages, [{ type: "reach:panel:close" }]);
});

test("the background turns the side panel off for the tab that opened, so it does not reopen there on its own", async () => {
  fake.chrome.sidePanel.calls.length = 0;
  fakePort(6);
  await send({ type: "reach:app:opened", windowId: 6 }, { id: EXT_ID, tab: { id: 11, windowId: 6 }, frameId: 0 });
  assert.deepEqual(fake.chrome.sidePanel.calls, [{ tabId: 11, enabled: false }]);
});

test("a window with no open panel still gets the side-panel tweak, and nothing throws", async () => {
  fake.chrome.sidePanel.calls.length = 0;
  await send({ type: "reach:app:opened", windowId: 999 }, { id: EXT_ID, tab: { id: 12, windowId: 999 }, frameId: 0 });
  assert.deepEqual(fake.chrome.sidePanel.calls, [{ tabId: 12, enabled: false }]);
});

test("a framed sender's open is refused: no close, no side-panel change", async () => {
  const messages = fakePort(7);
  fake.chrome.sidePanel.calls.length = 0;
  await send({ type: "reach:app:opened", windowId: 7 }, { id: EXT_ID, tab: { id: 13, windowId: 7 }, frameId: 1 });
  assert.deepEqual(messages, []);
  assert.deepEqual(fake.chrome.sidePanel.calls, []);
});

test("popup.js registers no onMessage listener of its own: the relay is the only ear background.js gives the message", async () => {
  const src = await readFile(new URL("../popup.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /onMessage\.addListener/);
});
