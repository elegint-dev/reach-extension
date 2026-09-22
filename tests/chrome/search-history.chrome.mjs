// Scenario 12 in the real extension: a pivot run from the drawer's Run in
// Splunk link writes the search history; the notebook page lists it with
// no investigation open, newest first, and Re-run puts the same text in
// the open Splunk tab's search bar while the app's own tab is active. On
// Sentinel the drawer's copy writes an entry that carries the KQL and no
// run. The section holds its width at 320 and 380 with a long query.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot } from "./harness.mjs";

let h;
const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
const ST = "crowdstrike:events:sensor";
const FIELD_ROUTE = `#/f/SHA256HashData?st=${ST}&on=ProcessRollup2&value=${HASH}`;

before(async () => {
  h = await launch({ viewport: { width: 380, height: 700 } });
});
after(async () => {
  if (h) await h.close();
});

// The stored document once it holds n entries (a copy's write lands a tick
// after the click).
async function storedEntries(page, n) {
  for (let i = 0; i < 50; i++) {
    const doc = await page.evaluate(async () => (await chrome.storage.local.get("reach.searches"))["reach.searches"]);
    if (doc && doc.entries.length >= n) return doc.entries;
    await page.waitForTimeout(100);
  }
  throw new Error(`no ${n} search history entries within 5 s`);
}

async function historyRows(page) {
  return page.$$eval(".r-nb__search", (els) =>
    els.map((el) => ({
      name: (el.querySelector(".r-nb__sname") || {}).textContent || "",
      where: el.querySelector(".r-nb__text").textContent.trim(),
      text: el.querySelector(".r-nb__query").getAttribute("title"),
      badge: el.querySelector(".r-nb__kind").textContent.trim(),
      acts: [...el.querySelectorAll(".r-nb__act")].map((b) => b.textContent.trim()),
    })),
  );
}

test("a pivot run from the drawer lands in the notebook's Search history with no investigation open, and Re-run fills the open Splunk tab's search bar", async (t) => {
  const splunk = await h.splunkPage();
  const page = await h.extensionPage(`index.html?platform=splunk${FIELD_ROUTE}`);
  try {
    await shot(t, page, async () => {
      await page.bringToFront();
      // The base URL gives the run link; the index is scope (Settings), which the
      // pivot needs bound before Copy and the run link open.
      await page.evaluate(() => {
        localStorage.setItem("reach.splunkBase", "https://splunk.fixture.test/en-US");
        localStorage.setItem("reach.scope", JSON.stringify({ index: "fdr", bySourcetype: {} }));
        location.reload();
      });
      await page.waitForSelector(".r-packpivots tr[data-row-id]", { timeout: 8000 });
      const before = await page.evaluate(async () => Object.keys(await chrome.storage.local.get(null)).sort());
      await page.click(".r-packpivots tr[data-row-id]");
      await page.waitForFunction(() => !document.querySelector(".r-drawer__run").hidden, null, { timeout: 5000 });
      const spl = await page.$eval(".r-spl__code", (e) => e.textContent);
      assert.ok(spl.includes("index=fdr"), spl);
      const name = await page.$eval(".r-drawer__title", (e) => e.textContent.trim());
      assert.ok(spl.includes(HASH), spl);
      const [results] = await Promise.all([h.context.waitForEvent("page"), page.click(".r-drawer__run")]);
      await results.close();
      const entries = await storedEntries(page, 1);
      assert.equal(entries.length, 1);
      assert.equal(entries[0].text, spl);
      assert.equal(entries[0].source, "run");
      assert.equal(entries[0].origin, "pivot");
      assert.equal(entries[0].container, ST);
      assert.equal(entries[0].field, "SHA256HashData");
      assert.equal(entries[0].investigation, undefined, "no investigation was current");
      const after = await page.evaluate(async () => Object.keys(await chrome.storage.local.get(null)).sort());
      assert.deepEqual(after.filter((k) => k !== "reach.searches"), before, "the run started no investigation");

      await page.evaluate(() => { location.hash = "#/notebook"; });
      await page.waitForSelector(".r-nb__searches .r-nb__search", { timeout: 8000 });
      const h2 = await page.$$eval("main h2", (els) => els.map((e) => e.textContent.trim()));
      assert.ok(h2.includes("Search history (1)"), h2.join(", "));
      assert.equal(await page.$(".r-nb__timeline"), null, "no investigation is open");
      const rows = await historyRows(page);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].text, spl);
      assert.equal(rows[0].name, name);
      assert.equal(rows[0].badge, "SPL");
      assert.match(rows[0].where, /on crowdstrike:events:sensor · from pivot · ran/);
      assert.deepEqual(rows[0].acts, ["Re-run", "Copy", "×"]);

      const barBefore = await splunk.evaluate(() => window.__fixtureEditor.getValue());
      await page.getByRole("button", { name: "Re-run" }).first().click();
      await page.waitForFunction(() => /Search bar set/.test((document.querySelector(".r-nb__status") || {}).textContent || ""), null, { timeout: 8000 }).catch(async (err) => {
        const note = await page.$eval(".r-nb__status", (e) => e.textContent).catch(() => "");
        throw new Error(`${err.message}\n  status: ${note}`);
      });
      const barAfter = await splunk.evaluate(() => window.__fixtureEditor.getValue());
      assert.notEqual(barAfter, barBefore, "the search bar changed");
      assert.equal(barAfter, spl);
      // The same text as the newest entry moves that entry rather than adding one.
      const moved = await storedEntries(page, 1);
      assert.equal(moved.length, 1);
      assert.ok(moved[0].at > entries[0].at, "the entry's time moved to the re-run");
      assert.equal((await historyRows(page)).length, 1);
    });
  } finally {
    await page.close();
    await splunk.close();
  }
});

test("on Sentinel the drawer's Copy KQL writes an entry with the KQL, no run and Re-run and Copy on its row", async (t) => {
  const page = await h.extensionPage(`index.html?platform=sentinel#/f/SHA256HashData?st=ReachCrowdStrike_CL&value=${HASH}`);
  try {
    await shot(t, page, async () => {
      await page.evaluate(async () => {
        const store = await import(chrome.runtime.getURL("app/lib/store.js"));
        await store.remove("searches");
      });
      await page.waitForSelector(".r-packpivots tr[data-row-id]", { timeout: 8000 });
      await page.click(".r-packpivots tr[data-row-id]");
      await page.waitForFunction(() => (document.querySelector(".r-spl__code") || {}).textContent?.includes("ReachCrowdStrike_CL"), null, { timeout: 8000 });
      const kql = await page.$eval(".r-spl__code", (e) => e.textContent);
      await page.click(".r-drawer__copy");
      const entries = await storedEntries(page, 1);
      assert.equal(entries.length, 1);
      assert.equal(entries[0].text, kql);
      assert.equal(entries[0].platform, "sentinel");
      assert.equal(entries[0].language, "kql");
      assert.equal(entries[0].source, "copy");
      assert.equal(entries[0].ran, false);
      await page.evaluate(() => { location.hash = "#/notebook"; });
      await page.waitForSelector(".r-nb__searches .r-nb__search", { timeout: 8000 });
      const rows = await historyRows(page);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].badge, "KQL");
      assert.match(rows[0].where, /on ReachCrowdStrike_CL · from pivot · copied/);
      assert.deepEqual(rows[0].acts, ["Re-run", "Copy", "×"]);
    });
  } finally {
    await page.close();
  }
});

test("the section keeps the page inside its width at 320 and 380 with a long query, on the chrome storage backend", async (t) => {
  const long = `index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/a-very-long-user-name-that-goes-on" ${"eventName=ConsoleLogin OR ".repeat(12)}eventName=CreateAccessKey | stats count by eventName, sourceIPAddress, userAgent`;
  for (const width of [320, 380]) {
    const page = await h.context.newPage({ viewport: { width, height: 700 } });
    try {
      await page.goto(h.url("index.html?platform=splunk#/notebook"));
      await page.waitForSelector("main", { timeout: 5000 });
      await page.evaluate(async (text) => {
        const s = await import(chrome.runtime.getURL("app/lib/searches.js"));
        await s.load({ force: true });
        await s.clear();
        await s.record({ text, platform: "splunk", source: "copy", origin: "pivot", container: "aws:cloudtrail", field: "userIdentity.arn", value: "arn:aws:iam::123456789012:user/a-very-long-user-name-that-goes-on", name: "every event by this identity in the last day and the day before" });
        await s.record({ text: "SigninLogs | where UserPrincipalName == 'bob@corp.example' | summarize count() by IPAddress", platform: "sentinel", source: "open", origin: "runbook", container: "SigninLogs", name: "sign-ins" });
      }, long);
      await shot(t, page, async () => {
        await page.waitForFunction(() => document.querySelectorAll(".r-nb__search").length === 2, null, { timeout: 5000 });
        const seen = await page.evaluate(() => {
          const d = document;
          d.querySelectorAll("details").forEach((x) => { x.open = true; });
          const cw = d.documentElement.clientWidth;
          // The skip link sits off screen by design.
          const past = [...d.querySelectorAll("*")].filter((el) => {
            const r = el.getBoundingClientRect();
            return !el.classList.contains("r-skip") && r.width > 0 && r.height > 0 && (r.right > cw + 1 || r.left < -1);
          }).map((el) => `${el.tagName.toLowerCase()}.${el.className}`);
          return { overflow: d.scrollingElement.scrollWidth > cw, past, rows: d.querySelectorAll(".r-nb__search").length };
        });
        assert.equal(seen.rows, 2);
        assert.equal(seen.overflow, false, `${width}: page overflows`);
        assert.deepEqual(seen.past, [], `${width}: past the edge`);
      });
    } finally {
      await page.close();
    }
  }
});

// it_88b661de part 2/5: search-history.js's sticky Auto-run/time-mode read
// is routed through a dynamic import of app/lib/store.js
// (chrome.runtime.getURL("app/lib/store.js")), gated so the History
// panel's first paint always waits for it. The node test for that gate
// (tests/search-history-async-settings.test.js) stands in for the
// content-script world; it cannot prove the import actually resolves
// against the real built extension on a real page. This does: a stored
// Auto-run value is already reflected the moment the panel opens for the
// very first time.
test("the History panel's first paint already reflects a stored Auto-run value, proving the real dynamic import of app/lib/store.js resolves on a real page", async (t) => {
  await h.setStorage({ historyAutoRun: true });
  const page = await h.splunkPage();
  try {
    await shot(t, page, async () => {
      const btn = page.locator("#reach-history-btn");
      await btn.waitFor({ timeout: 5000 });
      await btn.click();
      const autoRunBtn = page.locator(".reach-history-panel .reach-history-panel__iconbtn", { hasText: "Auto-run" });
      await autoRunBtn.waitFor({ timeout: 5000 });
      assert.equal(await autoRunBtn.evaluate((el) => el.classList.contains("is-on")), true, "already on at the panel's first paint, not flipped on a tick later");
    });
  } finally {
    await page.close();
  }
});
