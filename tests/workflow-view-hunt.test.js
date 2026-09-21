// The hunt page (a pack workflow with hunt wording): Save as scheduled
// alert joins Run and Copy SPL in the title block, hands the rendered
// search to the editor bridge and says the analyst schedules it in Splunk;
// the FDR five keep their two actions. Rows (N) follows Searches with a run
// control that waits for a Splunk instance; the rows drawn from a run link
// each field cell to the value page on that field and container, and a
// click on one holds and pins nothing.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as dom from "./_dom.js";

let relay = () => ({ ok: true, origins: [] });
globalThis.chrome = {
  runtime: {
    id: "test-extension",
    lastError: null,
    sendMessage(msg, cb) {
      Promise.resolve().then(() => cb(relay(msg)));
    },
  },
};
globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });
const copied = [];
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => copied.push(t) } }, configurable: true, writable: true });

const catalogue = await import("../app/lib/catalogue.js");
const fields = await import("../app/lib/pack-fields.js");
const modules = await import("../app/lib/modules.js");
const facts = await import("../app/lib/facts.js");
const pinned = await import("../app/lib/pinned.js");
const { render } = await import("../app/views/workflow.js");
await catalogue.load();

const ROWS = JSON.parse(readFileSync(new URL("./fixtures/hunt-rows.json", import.meta.url), "utf8"));

function drawerStub() {
  const calls = [];
  const d = { calls };
  for (const m of ["fill", "fail", "copy"]) d[m] = (...a) => calls.push([m, ...a]);
  return d;
}

function ctx(params) {
  return { fields, catalogue, route: "workflow", params, drawer: drawerStub(), navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

const settle = () => new Promise((r) => setTimeout(r, 30));
const headings = (el) => el.querySelectorAll("h2").map(dom.text);

test("the hunt page adds Save as scheduled alert after Run and Copy SPL, names the container in the scope line, and orders Rows after Searches; the FDR five keep two actions", async () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ id: "hunt_mac_signing" }));
    if (el.afterMount) el.afterMount();
    await settle();
    const title = el.children[0];
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Run", "Copy SPL", "Save as scheduled alert"]);
    assert.equal(dom.text(title.querySelector(".r-scope")), "on crowdstrike:events:sensor");
    const h2 = headings(el);
    assert.ok(h2.indexOf("Searches (2)") < h2.indexOf("Rows (0)") && h2.indexOf("Rows (0)") < h2.indexOf("Expected results"), h2.join(" > "));
    assert.match(dom.text(el.querySelector(".r-hunt__handoff")), /Save As, Alert/);
    const ioc = render(ctx({ id: "ioc" }));
    assert.deepEqual(ioc.children[0].querySelector(".r-actions").children.map(dom.text), ["Run", "Copy SPL"]);
    assert.equal(ioc.querySelector(".r-hunt"), null);
  } finally {
    restore();
  }
});

test("Save as scheduled alert hands the rendered search to the bridge whole and tells the analyst to schedule it in Splunk; an unrendered page says so", async () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ id: "hunt_mac_signing" }));
    const save = el.children[0].querySelector(".r-hunt__save");
    dom.fire(save, "click");
    await settle();
    assert.match(dom.text(el.querySelector(".r-hunt__status")), /No search rendered yet/);
    if (el.afterMount) el.afterMount();
    await settle();
    // where() has no page or tab here: the bridge copies, and the status says what comes next.
    dom.fire(save, "click");
    await settle();
    const status = dom.text(el.querySelector(".r-hunt__status"));
    assert.match(status, /Save As, Alert, on a schedule that matches the window/);
    assert.equal(copied.length, 1);
    assert.match(copied[0], /^search index=.*earliest=-7d\n  event_platform=Mac event_simpleName=ProcessRollup2\n  SigningId="com\.apple\.\*"/);
  } finally {
    restore();
  }
});

test("with no Splunk instance the run control is disabled and says so; with one, a run draws the rows with each field cell a value-page link on its field and container, and a click holds and pins nothing", async () => {
  const restore = dom.install();
  try {
    let el = render(ctx({ id: "hunt_mac_signing" }));
    if (el.afterMount) el.afterMount();
    await settle();
    assert.equal(el.querySelector(".r-hunt__run").disabled, true);
    assert.match(dom.text(el.querySelector(".r-hunt").querySelector(".r-hunt__status")), /No Splunk instance enabled yet/);

    const sent = [];
    relay = (msg) => {
      sent.push(msg);
      if (msg.type === "reach:discover:tabs") return { ok: true, origins: [{ origin: "https://splunk.test", tabs: 1 }] };
      // The golden rows, the second with a multivalue signing id as values() returns one.
      if (msg.type === "reach:discover:run") return { ok: true, rows: [ROWS[0], { ...ROWS[1], signing_id: [ROWS[1].signing_id, "-"] }], messages: [] };
      return { ok: false, error: "unexpected" };
    };
    el = render(ctx({ id: "hunt_mac_signing", window: "-30d" }));
    if (el.afterMount) el.afterMount();
    await settle();
    const run = el.querySelector(".r-hunt__run");
    assert.equal(run.disabled, false);
    const before = { bound: JSON.stringify(facts.bound()), pins: JSON.stringify(pinned.all()) };
    dom.fire(run, "click");
    await settle();
    const ran = sent.find((m) => m.type === "reach:discover:run");
    assert.ok(ran, "the search ran through the relay");
    assert.match(ran.spl, /earliest=-30d/);
    assert.match(ran.spl, /SigningId="com\.apple\.\*"/);
    assert.ok(headings(el).includes("Rows (2)"), headings(el).join(" > "));
    assert.match(dom.text(el.querySelector(".r-hunt").querySelector(".r-hunt__status")), /2 rows from https:\/\/splunk\.test/);
    const table = el.querySelector(".r-hunt__rows").querySelector("table");
    assert.deepEqual(table.querySelectorAll("th").map(dom.text), ["host", "aid", "image", "signing id", "team id", "validation category", "sha256", "events", "first seen", "last seen"]);
    const rows = table.querySelector("tbody").querySelectorAll("tr");
    assert.equal(rows.length, 2);
    const links = rows[0].querySelectorAll("a").map((a) => a.getAttribute("href"));
    assert.equal(links[0], "#/v/mac-lab-01.example?st=crowdstrike%3Aevents%3Asensor&name=ComputerName");
    assert.equal(links[2], "#/v/%2FApplications%2FFake%20Finder.app%2FContents%2FMacOS%2FFinder?st=crowdstrike%3Aevents%3Asensor&name=ImageFileName");
    assert.equal(links[5], "#/v/6?st=crowdstrike%3Aevents%3Asensor&name=CsValidationCategory", "the validation category the signer test reads is a cell on its field");
    assert.equal(links[6], "#/v/3b1fd0c4a7e2985f6d1b0c9e8a7f6d5c4b3a2918f7e6d5c4b3a291807f6e5d4c?st=crowdstrike%3Aevents%3Asensor&name=SHA256HashData");
    assert.equal(links.length, 7, "counts and times are text, not links");
    assert.equal(rows[1].querySelectorAll("a")[3].getAttribute("href"), "#/v/com.apple.notasystemd%2C%20-?st=crowdstrike%3Aevents%3Asensor&name=SigningId", "a multivalue cell joins its values");
    assert.equal(rows[0].querySelectorAll("button").length, 0, "no write action on a row");
    dom.fire(rows[0].querySelector("a"), "click");
    await settle();
    assert.equal(JSON.stringify(facts.bound()), before.bound, "a click on a cell holds nothing");
    assert.equal(JSON.stringify(pinned.all()), before.pins, "a click on a cell pins nothing");
  } finally {
    relay = () => ({ ok: true, origins: [] });
    restore();
  }
});

test("Save as scheduled alert names the chosen Splunk instance to the bridge, so the SPL lands in a search tab on that origin when the app's own tab is the active one", async () => {
  const restore = dom.install();
  const sent = [];
  // The bridge knows it is inside the extension by runtime.getURL; the other tests keep it off so where() is the clipboard.
  globalThis.chrome.runtime.getURL = (p) => `chrome-extension://test-extension/${p}`;
  globalThis.chrome.tabs = {
    query: async (opts) => (opts.active ? [{ id: 1 }] : opts.url === "https://splunk.test/*" ? [{ id: 9 }] : []),
    sendMessage: async (tabId, msg) => {
      sent.push([tabId, msg]);
      if (tabId === 1) throw new Error("Could not establish connection");
      return { ok: true, how: "set", notice: "Search set" };
    },
  };
  relay = (msg) => (msg.type === "reach:discover:tabs" ? { ok: true, origins: [{ origin: "https://splunk.test", tabs: 1 }] } : { ok: false, error: "unexpected" });
  try {
    const el = render(ctx({ id: "hunt_mac_signing" }));
    if (el.afterMount) el.afterMount();
    await settle();
    copied.length = 0;
    dom.fire(el.children[0].querySelector(".r-hunt__save"), "click");
    await settle();
    assert.deepEqual(sent.map(([id]) => id), [1, 9]);
    assert.equal(sent[1][1].mode, "set");
    assert.match(sent[1][1].text, /^search index=.*\n  event_platform=Mac event_simpleName=ProcessRollup2/);
    assert.equal(sent[1][1].origin, undefined, "the origin picks the tab and does not ride in the message");
    assert.match(dom.text(el.querySelector(".r-hunt__status")), /^In the search bar\. In Splunk: Save As, Alert/);
    assert.equal(copied.length, 0, "nothing copied when a tab took it");
  } finally {
    delete globalThis.chrome.tabs;
    delete globalThis.chrome.runtime.getURL;
    relay = () => ({ ok: true, origins: [] });
    restore();
  }
});
