// The toolbar popup, end to end: originPatternFor() (which pages it will
// even consider) and the page-classification it feeds (classify() /
// updateLayout(), which decide whether "Enable on this Splunk instance" or
// "Open the catalogue" leads). popup.js is a classic script, not a module
// (content-config.js's top-level consts have to be visible to it the way a
// browser shares script scope), so it is evaluated the same way
// relay.test.js evaluates background.js: read both files, splice them into
// one function body, run it against fake chrome/document globals, and read
// the DOM stubs back.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fakeChrome } from "./_chrome.js";

// ---------------------------------------------------------------------------
// A DOM stub with just enough of Element for popup.js: textContent,
// disabled, classList add/remove/toggle/contains, one click listener.

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

// Runs one popup "open" against a fake tab and a fake looksLikeSplunk()
// answer, then hands back the element stubs for assertions. Each call gets
// its own fresh globals, the same as a real popup open would.
async function openPopup({ url, tabId = 1, marker = false, executeScriptThrows = false, granted = [] }) {
  const els = new Map(IDS.map((id) => [id, makeEl(id)]));

  globalThis.document = { getElementById: (id) => els.get(id) };
  const fake = fakeChrome({ id: "ext", permitted: granted, tabs: url ? [{ id: tabId, url, windowId: 1 }] : [] });
  fake.chrome.scripting.executeScript = async () => {
    if (executeScriptThrows) throw new Error("cannot access this page");
    return [{ result: marker }];
  };
  fake.install();
  const created = fake.created;

  const configSrc = await readFile(new URL("../content-config.js", import.meta.url), "utf8");
  const popupSrc = await readFile(new URL("../popup.js", import.meta.url), "utf8");
  // new Function, not vm: popup.js's dynamic import()-free top level runs
  // fine as a plain function body, and content-config.js's consts land in
  // the same scope this way, exactly as the two <script> tags share one in
  // popup.html.
  new Function(configSrc + "\n" + popupSrc)();
  // render() at the bottom is async (tabs.query, executeScript,
  // permissions.contains, each a real await); a macrotask boundary flushes
  // every microtask queued behind them.
  await new Promise((resolve) => setTimeout(resolve, 10));
  els.created = created;
  return els;
}

// A link's click handler, run with a stub event and every await flushed.
async function click(els, id) {
  await els.get(id)._listeners.click({ preventDefault() {} });
  await new Promise((resolve) => setTimeout(resolve, 10));
}

// ---------------------------------------------------------------------------
// Real Splunk: the asset-signature marker is present, origin is not the
// Azure portal. Leads with the enable button, as before.

test("real Splunk page: enable leads, catalogue stays secondary", async () => {
  const els = await openPopup({ url: "https://splunk.example.com/en-US/app/search/search", marker: true });
  assert.equal(els.get("toggle").textContent, "Enable on this Splunk instance");
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), false);
  assert.equal(els.get("enableBlock").classList.contains("r-secondary"), false);
  assert.equal(els.get("origin").textContent, "https://splunk.example.com");
});

// ---------------------------------------------------------------------------
// The Azure portal: recognized by origin alone, no marker needed.

test("Azure portal: enable leads without a marker check", async () => {
  const els = await openPopup({ url: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs", marker: false });
  assert.equal(els.get("toggle").textContent, "Enable in the Azure portal");
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), false);
  assert.equal(els.get("enableBlock").classList.contains("r-secondary"), false);
});

// ---------------------------------------------------------------------------
// The store-reviewer trap this fixes: any other http(s) page used to lead
// with "Enable on this Splunk instance" and do nothing when clicked.

test("unrecognized http(s) page: catalogue leads, enable is demoted", async () => {
  const els = await openPopup({ url: "https://example.com/", marker: false });
  assert.equal(els.get("toggle").textContent, "Enable Reach on this site if it is a Splunk instance");
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), true);
  assert.equal(els.get("appLink").textContent, "Open the catalogue →");
  assert.equal(els.get("enableBlock").classList.contains("r-secondary"), true);
  assert.match(els.get("status").textContent, /doesn't look like a Splunk Web page/);
});

// ---------------------------------------------------------------------------
// activeTab injection can fail outright (a page Chrome will not let the
// extension touch); that must read as "not Splunk", not as an error.

test("marker check throws: treated as unrecognized, never throws out of render", async () => {
  const els = await openPopup({ url: "https://example.com/", executeScriptThrows: true });
  assert.equal(els.get("toggle").textContent, "Enable Reach on this site if it is a Splunk instance");
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), true);
});

// ---------------------------------------------------------------------------
// A non-http(s) page (chrome://, file://, a PDF): still leads with the
// catalogue rather than a disabled Splunk-only button.

test("non-http(s) page: not available, catalogue still leads", async () => {
  const els = await openPopup({ url: "chrome://extensions/" });
  assert.equal(els.get("toggle").textContent, "Not available here");
  assert.equal(els.get("toggle").disabled, true);
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), true);
});

// ---------------------------------------------------------------------------
// Already enabled (however that happened) stays primary even if the marker
// check now disagrees: a small line is the wrong shape for a control that
// also has to offer turning it off.

test("already enabled on an unmarked page: stays primary, not demoted", async () => {
  const els = await openPopup({ url: "https://example.com/", marker: false, granted: ["https://example.com/*"] });
  assert.equal(els.get("toggle").textContent, "Enabled: click to disable");
  assert.equal(els.get("appLink").classList.contains("r-primary-action"), false);
  assert.equal(els.get("enableBlock").classList.contains("r-secondary"), false);
});

// ---------------------------------------------------------------------------
// The grant hint: shown under the button on a recognized page (real Splunk
// or the Azure portal) not yet enabled, so the reviewer path and a real
// first user both see what the button does before they press it.

test("Splunk, not enabled: the grant hint shows under the button", async () => {
  const els = await openPopup({ url: "https://splunk.example.com/en-US/app/search/search", marker: true });
  assert.equal(els.get("enableHint").hidden, false);
  assert.match(els.get("enableHint").textContent, /nothing runs until you click a value/);
});

test("Azure portal, not enabled: the grant hint shows under the button", async () => {
  const els = await openPopup({ url: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs", marker: false });
  assert.equal(els.get("enableHint").hidden, false);
});

test("unrecognized page: no grant hint (there is no grant this button gives that does anything)", async () => {
  const els = await openPopup({ url: "https://example.com/", marker: false });
  assert.equal(els.get("enableHint").hidden, true);
});

test("already enabled: the grant hint hides, the status line covers it instead", async () => {
  const els = await openPopup({ url: "https://splunk.example.com/en-US/app/search/search", marker: true, granted: ["https://splunk.example.com/*"] });
  assert.equal(els.get("enableHint").hidden, true);
});

test("non-http(s) page: no grant hint", async () => {
  const els = await openPopup({ url: "chrome://extensions/" });
  assert.equal(els.get("enableHint").hidden, true);
});

// ---------------------------------------------------------------------------
// Settings opens options.html scoped to the platform of the tab the popup
// is on, the same way the catalogue link is scoped, so the module list is
// this platform's and not the one remembered from the last Reach page.

test("the Settings link opens options.html with the platform of the current tab", async () => {
  const splunk = await openPopup({ url: "https://splunk.example.com/en-US/app/search/search", marker: true });
  await click(splunk, "settingsLink");
  assert.deepEqual(splunk.created, [{ url: "chrome-extension://ext/options.html?platform=splunk" }]);
  const portal = await openPopup({ url: "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs", marker: false });
  await click(portal, "settingsLink");
  assert.deepEqual(portal.created, [{ url: "chrome-extension://ext/options.html?platform=sentinel" }]);
  const other = await openPopup({ url: "https://example.com/", marker: false });
  await click(other, "settingsLink");
  assert.deepEqual(other.created, [{ url: "chrome-extension://ext/options.html?platform=splunk" }], "an unrecognised page is a Splunk one");
});
