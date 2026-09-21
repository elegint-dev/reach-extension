// VirusTotal on with a key stored: the row offers the lookup and sends
// exactly one request, only after the explicit click. The request leaves
// through the module service worker (background.js lookup(), not the
// content-script page), so it is read off a fetch spy installed on the
// worker itself (context.serviceWorkers()[0].evaluate), not from page
// "request" events, which never see a worker-side fetch.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, openValuePopup, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let page;
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";
const VT_URL = `https://www.virustotal.com/api/v3/files/${HASH}`;
const leaf = (name, row = 1) => `.shared-eventsviewer-list-body-row:nth-of-type(${row}) .json-tree .f-v[data-field-name="${name}"]`;

before(async () => {
  h = await launch({ extraOrigins: ["https://www.virustotal.com/*"] });
  await h.setStorage({ "reach.modules": { enabled: { virustotal: true } }, vtApiKey: "fake-test-key-0000000000000000000000000000000000000000000000000000000000" });
  page = await h.splunkPage();
});
after(async () => {
  if (h) await h.close();
});

// Tags every fetch the worker makes from here on into globalThis.__reachFetchLog,
// idempotent so a second install mid-test does not lose earlier entries.
async function installFetchSpy() {
  await h.worker.evaluate(() => {
    if (globalThis.__reachFetchSpied) return;
    globalThis.__reachFetchSpied = true;
    globalThis.__reachFetchLog = [];
    const orig = globalThis.fetch.bind(globalThis);
    globalThis.fetch = (...args) => {
      globalThis.__reachFetchLog.push(String(args[0] && args[0].url ? args[0].url : args[0]));
      return orig(...args);
    };
  });
}

async function fetchLog() {
  return h.worker.evaluate(() => globalThis.__reachFetchLog || []);
}

async function closePopup() {
  await page.mouse.click(4, 4);
  await page.locator(".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown").waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
}

test("VirusTotal on with a key stored offers the lookup behind the fold and sends exactly one request, only on the click", async (t) => {
  await shot(t, page, async () => {
    await installFetchSpy();
    assert.deepEqual(await fetchLog(), [], "nothing fetched before the popup even opens");

    const section = await openValuePopup(page, leaf("SHA256HashData"));
    // LOLDrivers (bundled, always on) also answers this sha256 and holds the
    // always-open index-0 slot; VirusTotal is not specially promoted, so it
    // lands behind "Other sources" until that fold is opened.
    const row = section.locator(".reach-enrich .reach-enrich__row", { hasText: "VirusTotal" });
    await row.waitFor({ state: "attached", timeout: 5000 });
    if (!(await row.isVisible())) await section.locator(".reach-enrich .reach-fold summary", { hasText: "Other sources" }).click();
    await row.waitFor({ state: "visible", timeout: 5000 });
    const btn = row.locator("button", { hasText: "Check on VirusTotal" });
    await btn.waitFor({ timeout: 5000 });
    assert.deepEqual(await fetchLog(), [], "the row offering the lookup sends nothing on its own");

    await btn.click();
    // enrichSourceRow's run() flips the button to "Check again" only after
    // source.call() resolves (app/lib/popup-ui.js): the round trip, and so
    // the worker's fetch, is over by the time this settles, so the log
    // below reads the total, not a length-1 snapshot mid-flight.
    await row.locator("button", { hasText: "Check again" }).waitFor({ timeout: SECTION_WAIT });
    const log = await fetchLog();
    assert.deepEqual(log, [VT_URL], "exactly one request, to the clicked hash's VT files endpoint");
    await closePopup();
  });
});
