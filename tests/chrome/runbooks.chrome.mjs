// The runbook band in Chrome with the real extension: a Splunk notable
// row and a Sentinel SecurityAlert row each get the band first in the
// REACH section, keyed by the rule the row came from, with the seed source
// and the counts filled from the bundled index and a link into the panel
// page; a row with no rule key (the T1003.001 events, the seeded table)
// gets none.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, openValuePopup, SECTION_WAIT } from "./harness.mjs";

let h;

before(async () => {
  h = await launch();
});
after(async () => {
  if (h) await h.close();
});

const leaf = (name) => `.shared-eventsviewer-list-body-row .json-tree .f-v[data-field-name="${name}"]`;

test("a Splunk notable row's value popup opens on the runbook band, keyed by the ESCU search name, seeded and linked to the panel page", async (t) => {
  const page = await h.notablePage();
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("dest"));
    const band = section.locator(".reach-runbook");
    await band.waitFor({ timeout: 5000 });
    assert.equal(await section.locator(".reach-row").first().getAttribute("class"), "reach-row reach-runbook", "the band is the first row of the section");
    assert.equal(await band.locator(".reach-runbook__name").textContent(), "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser");
    await page.waitForFunction(() => /seeded from/.test(document.querySelector(".reach-runbook__source")?.textContent || ""), null, { timeout: 5000 });
    assert.equal(await band.locator(".reach-runbook__source").textContent(), "seeded from Splunk ESCU");
    assert.match(await band.locator(".reach-runbook__count").textContent(), /^\d+ steps, \d+ bound from this row$/);
    const href = await band.locator(".reach-runbook__open").getAttribute("href");
    assert.match(href, /^chrome-extension:\/\/[a-p]{32}\/index\.html\?platform=splunk#\/runbook\/escu%3Aname%3A/);
    assert.match(href, /[?&]dest=WIN-DC01/);
    assert.match(href, /[?&]st=stash/);
  });
  await page.close();
});

test("the T1003.001 event rows carry no rule key, so their popup draws no runbook band", async (t) => {
  const page = await h.splunkPage();
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    assert.equal(await section.locator(".reach-runbook").count(), 0);
  });
  await page.close();
});

test("a SecurityAlert row's blade menu opens on the runbook band keyed by AlertName, and a renamed rule says it is not in the bundles", async (t) => {
  const page = await h.bladePage("/alerts");
  await shot(t, page, async () => {
    const cell = (col, row) => `.ag-root [role="row"][aria-rowindex="${row}"] [role="gridcell"][aria-colindex="${col}"]`;
    await page.locator(cell(5, 2)).click({ button: "right" });
    const section = page.locator('.ag-menu-list[role="menu"] .reach-section');
    await section.waitFor({ timeout: SECTION_WAIT });
    const band = section.locator(".reach-runbook");
    await band.waitFor({ timeout: 5000 });
    assert.equal(await band.locator(".reach-runbook__name").textContent(), "GitLab - Brute-force Attempts");
    await page.waitForFunction(() => /seeded from|not in/.test(document.querySelector(".reach-runbook__source")?.textContent || ""), null, { timeout: 5000 });
    assert.equal(await band.locator(".reach-runbook__source").textContent(), "seeded from Sentinel analytic rules");
    const href = await band.locator(".reach-runbook__open").getAttribute("href");
    assert.match(href, /index\.html\?platform=sentinel#\/runbook\/sentinel-rules%3Aname%3Agitlab%20bruteforce%20attempts/);
    assert.match(href, /[?&]Entities=/);
    await page.mouse.click(4, 4);
    await page.locator(".ag-popup-child").waitFor({ state: "detached", timeout: 2000 }).catch(() => {});

    await page.locator(cell(5, 3)).click({ button: "right" });
    await section.waitFor({ timeout: SECTION_WAIT });
    await page.waitForFunction(() => /seeded from|not in/.test(document.querySelector(".reach-runbook__source")?.textContent || ""), null, { timeout: 5000 });
    assert.equal(await section.locator(".reach-runbook__name").textContent(), "SOC GitLab brute force (tuned)");
    assert.equal(await section.locator(".reach-runbook__source").textContent(), "not in the bundled rules");
  });
  await page.close();
});

test("the seeded table's rows carry no rule key, so the blade menu draws no runbook band", async (t) => {
  const page = await h.bladePage();
  await shot(t, page, async () => {
    await page.locator('.ag-root [role="row"][aria-rowindex="2"] [role="gridcell"][aria-colindex="6"]').click({ button: "right" });
    const section = page.locator('.ag-menu-list[role="menu"] .reach-section');
    await section.waitFor({ timeout: SECTION_WAIT });
    assert.equal(await section.locator(".reach-runbook").count(), 0);
  });
  await page.close();
});
