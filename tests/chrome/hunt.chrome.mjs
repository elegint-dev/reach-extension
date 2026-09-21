// The mac signing hunt in the real extension: the workflow page runs its
// search through the discovery relay on the Splunk fixture tab (the jobs
// endpoints answered from tests/fixtures/hunt-rows.json, the stats the
// search makes of the fixture page's rows: tests/hunt-fixture-rows.test.js
// holds the two together), draws the rows, and a cell opens the value page
// on its field without holding or pinning anything; Save as scheduled
// alert puts the SPL in the open Splunk tab's search bar, the app's own
// tab being the active one, and says the analyst schedules it in Splunk.
// On Sentinel the same page renders the KQL twin with Copy KQL and the
// analytics-rule hand-off.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { launch, shot, ROOT, SPLUNK_ORIGIN, SECTION_WAIT } from "./harness.mjs";

let h;
const ROWS = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "hunt-rows.json"), "utf8"));
const IMAGE = ROWS[0].ImageFileName;
const JOBS = `${SPLUNK_ORIGIN}/en-US/splunkd/__raw/servicesNS/-/search/search/v2/jobs`;
const SID = "1758400000.42";
const seen = [];

before(async () => {
  h = await launch({ viewport: { width: 380, height: 700 } });
});
after(async () => {
  if (h) await h.close();
});

// The Splunk jobs endpoints the agent drives from the fixture page: a page
// route, which runs before the harness's origin-wide one.
async function answerJobs(page) {
  await page.route((url) => url.href.startsWith(JOBS), async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    const entry = { method: req.method(), path: u.pathname, body: req.postData() || "", answered: null };
    seen.push(entry);
    const json = (body) => { entry.answered = body; return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) }); };
    try {
      if (req.method() === "POST" && u.pathname.endsWith("/jobs")) return await json({ sid: SID });
      if (req.method() === "DELETE") return await json({});
      if (u.pathname.endsWith(`/jobs/${SID}/results`)) return await json({ results: ROWS });
      if (u.pathname.endsWith(`/jobs/${SID}`)) return await json({ entry: [{ content: { isDone: true, dispatchState: "DONE", messages: [] } }] });
      entry.answered = 404;
      return await route.fulfill({ status: 404, contentType: "text/plain", body: "not in the fixture" });
    } catch (err) {
      entry.answered = `threw ${err.message}`;
      throw err;
    }
  });
}

test("on Splunk the hunt runs on the fixture tab through the relay, the rows draw grouped by host and image, and a cell opens the value page without holding or pinning", async (t) => {
  const splunk = await h.splunkPage();
  await answerJobs(splunk);
  const page = await h.extensionPage("index.html?platform=splunk#/w/hunt_mac_signing");
  try {
    await shot(t, page, async () => {
      await page.waitForSelector(".r-hunt__run", { timeout: SECTION_WAIT });
      await page.waitForFunction(() => !document.querySelector(".r-hunt__run").disabled, null, { timeout: SECTION_WAIT });
      await page.getByRole("button", { name: "Run here" }).click();
      await page.waitForFunction(() => /^Rows \(2\)$/.test((document.querySelector('[data-heading="rows"]') || {}).textContent || ""), null, { timeout: 15000 }).catch(async (err) => {
        const status = await page.$eval(".r-hunt", (e) => e.querySelector(".r-hunt__status").textContent).catch(() => "");
        throw new Error(`${err.message}\n  status: ${status}\n  requests: ${JSON.stringify(seen.map((x) => ({ ...x, body: x.body.slice(0, 40) })))}`);
      });
      const posted = seen.find((s) => s.method === "POST");
      assert.ok(posted, "the search was dispatched");
      const params = new URLSearchParams(posted.body);
      assert.match(params.get("search"), /^search index=.*sourcetype=crowdstrike:events:sensor earliest=-7d/);
      assert.match(params.get("search"), /NOT \(CsValidationCategory=1 TeamId="-"\)/);
      assert.equal(params.get("earliest_time"), "0");
      const headers = await page.$$eval(".r-hunt__rows th", (els) => els.map((e) => e.textContent.trim()));
      assert.deepEqual(headers, ["host", "aid", "image", "signing id", "team id", "validation category", "sha256", "events", "first seen", "last seen"]);
      const categories = await page.$$eval(".r-hunt__rows tbody tr", (els) => els.map((e) => e.querySelectorAll("td")[5].textContent.trim()));
      assert.deepEqual(categories, ROWS.map((r) => r.validation_category));
      const hosts = await page.$$eval(".r-hunt__rows tbody tr", (els) => els.map((e) => e.querySelector("td").textContent.trim()));
      assert.deepEqual(hosts, ["mac-lab-01.example", "mac-lab-02.example"]);
      // The run itself is a hand-off and lands in the search history; the
      // cell click after it writes nothing.
      const before = await page.evaluate(async () => ({ pinned: localStorage.getItem("reach.pinned"), keys: Object.keys(await chrome.storage.local.get(null)).sort() }));
      assert.ok(before.keys.includes("reach.searches"), "the run wrote the search history");
      await page.getByRole("link", { name: IMAGE, exact: true }).click();
      // The title block shortens a long value in the h1; the route carries it whole.
      await page.waitForFunction(() => location.hash.startsWith("#/v/") && /MacOS\/Finder/.test((document.querySelector("main h1") || {}).textContent || ""), null, { timeout: SECTION_WAIT });
      const hash = await page.evaluate(() => location.hash);
      assert.ok(hash.startsWith(`#/v/${encodeURIComponent(IMAGE)}?`) && hash.includes("name=ImageFileName") && hash.includes("st=crowdstrike%3Aevents%3Asensor"), hash);
      const after = await page.evaluate(async () => ({ pinned: localStorage.getItem("reach.pinned"), keys: Object.keys(await chrome.storage.local.get(null)).sort() }));
      assert.equal(after.pinned, before.pinned, "the click pinned nothing");
      assert.deepEqual(after.keys, before.keys, "the click held nothing");
    });
  } finally {
    await page.close();
    await splunk.close();
  }
});

test("Save as scheduled alert fills the open Splunk tab's search bar with the SPL while the app's own tab is active, and says the analyst schedules it in Splunk", async (t) => {
  const splunk = await h.splunkPage();
  const page = await h.extensionPage("index.html?platform=splunk#/w/hunt_mac_signing");
  try {
    await shot(t, page, async () => {
      await page.bringToFront();
      const before = await splunk.evaluate(() => window.__fixtureEditor.getValue());
      await page.waitForSelector(".r-hunt__save", { timeout: SECTION_WAIT });
      await page.waitForFunction(() => (document.querySelector(".r-spl__code") || {}).textContent?.includes("event_platform=Mac"), null, { timeout: SECTION_WAIT });
      await page.waitForFunction(() => !document.querySelector(".r-hunt__run").disabled, null, { timeout: SECTION_WAIT });
      const labels = await page.$$eval(".r-actions > *", (els) => els.map((e) => e.textContent.trim()));
      assert.deepEqual(labels, ["Run", "Copy SPL", "Save as scheduled alert"]);
      const spl = await page.$eval(".r-spl__code", (e) => e.textContent);
      await page.getByRole("button", { name: "Save as scheduled alert" }).click();
      await page.waitForFunction(() => /Save As, Alert/.test((document.querySelector(".r-hunt__handoff .r-hunt__status") || {}).textContent || ""), null, { timeout: SECTION_WAIT });
      const status = await page.$eval(".r-hunt__handoff .r-hunt__status", (e) => e.textContent);
      assert.match(status, /^In the search bar\. In Splunk: Save As, Alert/, status);
      assert.doesNotMatch(status, /Copied|alert (was )?created/i);
      const after = await splunk.evaluate(() => window.__fixtureEditor.getValue());
      assert.notEqual(after, before, "the search bar changed");
      assert.equal(after, spl);
      assert.match(await splunk.locator(".search-bar-input .ace_line").first().textContent(), /^search index=/);
    });
  } finally {
    await page.close();
    await splunk.close();
  }
});

test("on Sentinel the same page renders the KQL twin on the sample table with Copy KQL and the analytics-rule hand-off, and no run control", async (t) => {
  const page = await h.extensionPage("index.html?platform=sentinel#/w/hunt_mac_signing");
  try {
    await shot(t, page, async () => {
      await page.waitForSelector(".r-hunt__save", { timeout: SECTION_WAIT });
      await page.waitForFunction(() => (document.querySelector(".r-spl__code") || {}).textContent?.startsWith("ReachCrowdStrike_CL"), null, { timeout: SECTION_WAIT });
      const labels = await page.$$eval(".r-actions > *", (els) => els.map((e) => e.textContent.trim()));
      assert.deepEqual(labels, ["Run", "Copy KQL", "Save as scheduled alert"]);
      assert.equal(await page.$(".r-hunt__run"), null);
      const kql = await page.$eval(".r-spl__code", (e) => e.textContent);
      assert.match(kql, /\| where TimeGenerated > ago\(7d\)/);
      assert.match(kql, /by Aid, ComputerName, ImageFileName/);
      await page.getByRole("button", { name: "Save as scheduled alert" }).click();
      await page.waitForFunction(() => /Scheduled query rule/.test((document.querySelector(".r-hunt__handoff .r-hunt__status") || {}).textContent || ""), null, { timeout: SECTION_WAIT });
    });
  } finally {
    await page.close();
  }
});
