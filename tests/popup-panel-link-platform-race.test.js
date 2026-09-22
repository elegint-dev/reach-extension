// it_88b661de part 3: popup.js's panelLink click loaded app/lib/platform.js
// with an unawaited dynamic import; a click fast enough to land before it
// resolved skipped rememberPlatform() outright (`if (platformLib) ...`)
// and opened the side panel on whatever platform localStorage already
// held, not this tab's. The click handler now awaits the import (the
// cached platformLibReady promise, resolved before almost every real
// click) before writing or opening, so a fast click cannot use a stale
// platform.
//
// A real dynamic import, not a stub: chrome.runtime.getURL is pointed at
// this file on disk, the same specifier popup.js gives it
// (app/lib/platform.js), so the race is exercised against the real module,
// not a reimplementation of it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fakeChrome } from "./_chrome.js";

function makeEl(id) {
  const classes = new Set();
  return {
    id,
    textContent: "",
    disabled: false,
    hidden: false,
    dataset: {},
    style: {},
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
      toggle(c, force) {
        const want = force === undefined ? !classes.has(c) : !!force;
        if (want) classes.add(c);
        else classes.delete(c);
        return want;
      },
    },
    _listeners: {},
    addEventListener(type, fn) {
      this._listeners[type] = fn;
    },
  };
}

const IDS = ["toggle", "status", "origin", "appLink", "enableBlock", "enableHint", "panelLink", "settingsLink"];

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), _map: m };
}

test("a panelLink click before the platform import resolves still opens on the clicked tab's platform, not a stale remembered one", async () => {
  const storage = memoryStorage();
  storage.setItem("reach.platform", "sentinel"); // an earlier session's remembered platform, the wrong one for this click
  const url = "https://splunk.example.com/en-US/app/search/search";

  const els = new Map(IDS.map((id) => [id, makeEl(id)]));
  globalThis.document = { getElementById: (id) => els.get(id) };
  globalThis.localStorage = storage;
  // A real file URL for app/lib/platform.js: the same specifier popup.js
  // asks chrome.runtime.getURL for, resolved to the module on disk so the
  // import genuinely takes a macrotask or more, not a stub answered
  // sooner than a real click could ever land.
  // platform.js resolves for real (not a stub), but slowed down (a data:
  // wrapper module that awaits first, then re-exports the real file) so
  // it is still pending when the click fires, well after render() itself
  // (tabs.query, executeScript, permissions.contains against the fake)
  // has already set currentTab. That is the actual race: a click that
  // lands after the popup can respond to it, but before its own platform
  // module has loaded.
  const realPlatformUrl = new URL("../app/lib/platform.js", import.meta.url).href;
  const slowPlatformUrl = `data:text/javascript,${encodeURIComponent(
    `await new Promise((r) => setTimeout(r, 150)); export * from ${JSON.stringify(realPlatformUrl)};`,
  )}`;
  const fake = fakeChrome({
    id: "ext",
    tabs: [{ id: 1, url, windowId: 1 }],
    getURL: (p) => (p === "app/lib/platform.js" ? slowPlatformUrl : new URL(`../${p}`, import.meta.url).href),
  });
  fake.chrome.scripting.executeScript = async () => [{ result: false }];
  const opened = [];
  fake.chrome.sidePanel = {
    open: async (opts) => {
      opened.push({ windowId: opts.windowId, platformAtOpen: storage.getItem("reach.platform") });
      return undefined;
    },
  };
  globalThis.window = { close() {} };
  fake.install();

  const configSrc = await readFile(new URL("../content-config.js", import.meta.url), "utf8");
  const popupSrc = await readFile(new URL("../popup.js", import.meta.url), "utf8");
  new Function(configSrc + "\n" + popupSrc)();
  // Enough for render() to finish against the fake (a handful of
  // macrotask hops), nowhere near the platform module's 150ms delay: the
  // click below lands with currentTab set and platformLib still null.
  await new Promise((resolve) => setTimeout(resolve, 40));
  const btn = els.get("panelLink");
  await btn._listeners.click({ preventDefault() {} });
  await new Promise((resolve) => setTimeout(resolve, 200));

  assert.equal(storage.getItem("reach.platform"), "splunk", "the click's own tab platform won, not the stale remembered one");
  assert.equal(opened.length, 1, "the panel opened exactly once");
  assert.equal(opened[0].platformAtOpen, "splunk", "rememberPlatform() landed before sidePanel.open() was called");
});
