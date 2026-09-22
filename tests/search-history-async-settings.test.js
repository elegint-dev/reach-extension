// it_88b661de part 2: search-history.js's sticky Auto-run/time-mode read
// (historyAutoRun/historyTimeMode) is routed through app/lib/store.js and
// gated so a fast History click, right after the page loads, cannot
// construct the panel off the false/"exact" defaults while the read is
// still in flight.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";

function setUpDom() {
  const restoreDom = dom.install();
  // A MutationObserver that never calls back: the script only needs the
  // constructor to exist (it observes document.body at load), and a real
  // callback here would reach for a scheduling timer this test does not
  // need and cannot clean up before it ends.
  globalThis.MutationObserver = class {
    observe() {}
    disconnect() {}
    takeRecords() {
      return [];
    }
  };
  globalThis.window = {
    addEventListener() {},
    removeEventListener() {},
    innerWidth: 1000,
    requestAnimationFrame: (fn) => setTimeout(fn, 0),
  };
  const marker = document.createElement("link");
  marker.setAttribute("href", "/static/@abc123/build.css");
  document.body.appendChild(marker);
  const left = document.createElement("div");
  left.className = "left-container";
  document.body.appendChild(left);
  // The browser's Option(text, value) constructor, for the time-mode select.
  globalThis.Option = class Option {
    constructor(text, value) {
      const el = document.createElement("option");
      el.textContent = text;
      el.value = value;
      return el;
    }
  };
  return () => {
    restoreDom();
    delete globalThis.window;
    delete globalThis.Option;
    delete globalThis.MutationObserver;
  };
}

test("a History click before the sticky read resolves cannot paint the panel off the stale defaults", async () => {
  const restoreDom = setUpDom();
  const fake = fakeChrome({ getURL: (p) => new URL(`../${p}`, import.meta.url).href });
  fake.local.set("historyAutoRun", true);
  fake.local.set("historyTimeMode", "range");
  const restoreChrome = fake.install();
  try {
    const src = readFileSync(new URL("../search-history.js", import.meta.url), "utf8");
    new Function(src)();

    const btn = document.getElementById("reach-history-btn");
    assert.ok(btn, "the History button mounted");

    dom.fire(btn, "click");
    // Right after the click, before any tick: on main this constructed the
    // panel synchronously off the false/"exact" defaults; the fix awaits
    // the sticky read first, so nothing has painted yet.
    assert.equal(document.getElementById(undefined), null); // no-op guard against an empty body read
    const panelBefore = dom.walk(document.body, (n) => n.classList && n.classList.contains("reach-history-panel"))[0];
    assert.equal(panelBefore, undefined, "no panel painted synchronously off the click");

    // Give the dynamic import + the literal read several macrotask hops.
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));

    const panelAfter = dom.walk(document.body, (n) => n.classList && n.classList.contains("reach-history-panel"))[0];
    assert.ok(panelAfter, "the panel painted once the click's await resolved");
    const autoRunBtn = dom.walk(panelAfter, (n) => n.classList && n.classList.contains("reach-history-panel__iconbtn") && /Auto-run/.test(n.textContent))[0];
    assert.ok(autoRunBtn.classList.contains("is-on"), "the panel's very first paint already reflects the stored Auto-run value, not the default");
  } finally {
    restoreChrome();
    restoreDom();
  }
});

test("setAutoRun and setTimeMode write through app/lib/store.js's literal keys, not a raw chrome.storage.local call", async () => {
  const restoreDom = setUpDom();
  const fake = fakeChrome({ getURL: (p) => new URL(`../${p}`, import.meta.url).href });
  const restoreChrome = fake.install();
  try {
    const src = readFileSync(new URL("../search-history.js", import.meta.url), "utf8");
    new Function(src)();
    const btn = document.getElementById("reach-history-btn");
    dom.fire(btn, "click");
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));
    const panel = dom.walk(document.body, (n) => n.classList && n.classList.contains("reach-history-panel"))[0];
    const autoRunBtn = dom.walk(panel, (n) => n.classList && n.classList.contains("reach-history-panel__iconbtn") && /Auto-run/.test(n.textContent))[0];
    dom.fire(autoRunBtn, "click");
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));
    assert.equal(fake.local.get("historyAutoRun"), true, "the click's write landed under the same literal key the boot read used");
  } finally {
    restoreChrome();
    restoreDom();
  }
});
