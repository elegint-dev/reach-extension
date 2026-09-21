// app/lib/runtime.js: the one reading of the extension runtime the modules
// share. Each helper is tried with chrome absent (a served page) and with a
// fake chrome shaped like the real one, and the inline copies the classic
// scripts keep of the Splunk asset signature are pinned to the exported
// selector so they cannot drift.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const runtime = await import("../app/lib/runtime.js");

function withChrome(fake, fn) {
  const had = Object.prototype.hasOwnProperty.call(globalThis, "chrome");
  const was = globalThis.chrome;
  globalThis.chrome = fake;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (had) globalThis.chrome = was;
      else delete globalThis.chrome;
    });
}

const fakeRuntime = ({ answer = undefined, lastError = null, id = "ext" } = {}) => ({
  id,
  lastError: null,
  getURL: (p) => `chrome-extension://${id}/${p}`,
  sendMessage(msg, cb) {
    this.lastError = lastError;
    cb(typeof answer === "function" ? answer(msg) : answer);
    this.lastError = null;
  },
});

test("hasChrome() and canAsk() are false with no chrome global and true with storage and a runtime", async () => {
  await withChrome(undefined, () => {
    delete globalThis.chrome;
    assert.equal(runtime.hasChrome(), false);
    assert.equal(runtime.canAsk(), false);
  });
  await withChrome({ storage: { local: {} }, runtime: fakeRuntime() }, () => {
    assert.equal(runtime.hasChrome(), true);
    assert.equal(runtime.canAsk(), true);
  });
  await withChrome({ runtime: {} }, () => {
    assert.equal(runtime.hasChrome(), false);
    assert.equal(runtime.canAsk(), false);
  });
});

test("ask() resolves null with no worker to ask, the worker's answer when it answers, and never rejects", async () => {
  await withChrome(undefined, async () => {
    delete globalThis.chrome;
    assert.equal(await runtime.ask({ type: "x" }), null);
  });
  await withChrome({ runtime: fakeRuntime({ answer: (msg) => ({ ok: true, echo: msg.type }) }) }, async () => {
    assert.deepEqual(await runtime.ask({ type: "reach:vt:status" }), { ok: true, echo: "reach:vt:status" });
  });
});

test("ask() turns chrome.runtime.lastError into the { ok: false, status: 0, error } shape every relay consumer already reads", async () => {
  await withChrome({ runtime: fakeRuntime({ answer: undefined, lastError: { message: "Receiving end does not exist." } }) }, async () => {
    assert.deepEqual(await runtime.ask({ type: "x" }), { ok: false, status: 0, error: "Receiving end does not exist." });
  });
  const throwing = { runtime: { sendMessage() { throw new Error("Extension context invalidated."); } } };
  await withChrome(throwing, async () => {
    assert.deepEqual(await runtime.ask({ type: "x" }), { ok: false, status: 0, error: "Extension context invalidated." });
  });
});

test("appUrl() and optionsUrl() build the app's pages under the extension, or a relative path with no extension around", async () => {
  await withChrome({ runtime: fakeRuntime({ id: "abc" }) }, () => {
    assert.equal(runtime.appUrl("splunk"), "chrome-extension://abc/index.html?platform=splunk");
    assert.equal(runtime.appUrl("sentinel", "#/notebook"), "chrome-extension://abc/index.html?platform=sentinel#/notebook");
    assert.equal(runtime.optionsUrl("splunk", "module-enrich"), "chrome-extension://abc/options.html?platform=splunk#module-enrich");
    assert.equal(runtime.optionsUrl("sentinel"), "chrome-extension://abc/options.html?platform=sentinel");
  });
  await withChrome(undefined, () => {
    delete globalThis.chrome;
    assert.equal(runtime.appUrl("splunk", "#/f/x"), "index.html?platform=splunk#/f/x");
    assert.equal(runtime.optionsUrl("sentinel", "a"), "options.html?platform=sentinel#a");
  });
});

test("copyText() writes the clipboard, flashes the label on the element and restores its text", async () => {
  const written = [];
  const wasNav = globalThis.navigator;
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => written.push(t) } }, configurable: true });
  try {
    const el = { textContent: "Copy" };
    assert.equal(await runtime.copyText("select *", el, "copied ✓"), true);
    assert.deepEqual(written, ["select *"]);
    assert.equal(el.textContent, "copied ✓");
    await new Promise((r) => setTimeout(r, 950));
    assert.equal(el.textContent, "Copy");
  } finally {
    Object.defineProperty(globalThis, "navigator", { value: wasNav, configurable: true });
  }
});

test("copyText() says so on the element when the page has no clipboard or refuses the write", async () => {
  const wasNav = globalThis.navigator;
  Object.defineProperty(globalThis, "navigator", { value: {}, configurable: true });
  try {
    const el = { textContent: "Copy" };
    assert.equal(await runtime.copyText("x", el), false);
    assert.equal(el.textContent, "Could not copy");
  } finally {
    Object.defineProperty(globalThis, "navigator", { value: wasNav, configurable: true });
  }
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => { throw new Error("denied"); } } }, configurable: true });
  try {
    const el = { textContent: "Copy" };
    assert.equal(await runtime.copyText("x", el), false);
    assert.equal(el.textContent, "Could not copy");
  } finally {
    Object.defineProperty(globalThis, "navigator", { value: wasNav, configurable: true });
  }
});

test("looksLikeSplunk() answers on the versioned /static/@ asset signature alone", () => {
  const docWith = { querySelector: (sel) => (sel === runtime.SPLUNK_ASSET_SELECTOR ? {} : null) };
  const docWithout = { querySelector: () => null };
  assert.equal(runtime.looksLikeSplunk(docWith), true);
  assert.equal(runtime.looksLikeSplunk(docWithout), false);
  assert.equal(runtime.looksLikeSplunk(null), false);
});

test("localePrefix() reads Splunk Web's locale segment off the path and falls back to en-US", () => {
  assert.equal(runtime.localePrefix({ pathname: "/ja-JP/app/search/search" }), "ja-JP");
  assert.equal(runtime.localePrefix({ pathname: "/" }), "en-US");
  assert.equal(runtime.localePrefix(null), "en-US");
});

// The classic scripts gate on the same selector before they can import
// anything; the toolbar popup carries it inside a function that
// chrome.scripting stringifies. Both stay byte-equal to the export.
const GATED = ["value-popup.js", "field-info-popup.js", "json-tree-fields.js", "search-history.js", "discovery-agent.js", "popup.js"];

test("every classic script's inline Splunk asset signature is the selector runtime.js exports", () => {
  for (const name of GATED) {
    const src = readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url)), "utf8");
    const found = src.match(/querySelector\('([^']+)'\)/g) || [];
    const sigs = found.filter((m) => m.includes("/static/@"));
    assert.ok(sigs.length >= 1, `${name} gates on the asset signature`);
    for (const m of sigs) assert.equal(m, `querySelector('${runtime.SPLUNK_ASSET_SELECTOR}')`, name);
  }
});

test("no module or content script keeps its own copy of the helpers runtime.js exports", () => {
  const files = ["value-popup.js", "field-info-popup.js", "sentinel-grid.js", "live-lookup.js", "app/lib/click-context.js", "app/lib/click-section.js", "app/lib/click-splunk.js", "app/lib/click-sentinel.js", "app/lib/popup-ui.js", "app/lib/popup-shell.js", "app/lib/bands/band.js", "app/lib/bands/value.js", "app/lib/bands/verdict.js", "app/lib/bands/pattern.js", "app/lib/bands/meaning.js", "app/lib/bands/workflows.js", "app/lib/bands/enrich.js", "app/lib/bands/hold-and-benign.js", "app/views/value.js", "app/views/notebook.js", "app/views/discover-sentinel.js", "app/components/moduleList.js", "app/lib/store.js", "app/lib/scope.js", "app/lib/onboarding.js", "app/lib/sentinel-settings.js", "app/lib/modules.js"];
  for (const name of files) {
    const src = readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url)), "utf8");
    assert.ok(!/function (hasChrome|ask|copyText|localePrefix|settingsUrlFor)\(/.test(src), `${name} defines no helper copy`);
    assert.ok(!/chrome\.runtime\.sendMessage\(/.test(src), `${name} sends through runtime.ask`);
    assert.ok(!src.includes('"index.html?platform='), `${name} builds no app URL by hand`);
    assert.ok(!src.includes("navigator.clipboard.writeText("), `${name} writes no clipboard by hand`);
  }
});
