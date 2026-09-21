// The Logs blade grid slice, in Chrome with the real extension: a
// right-click on a value cell gets the blade's own menu with the REACH
// section appended, scoped to the row's table and record type.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let page;

before(async () => {
  h = await launch();
  page = await h.bladePage();
});
after(async () => {
  if (h) await h.close();
});

const cell = (col, rowIndex = 2) => `.ag-root [role="row"][aria-rowindex="${rowIndex}"] [role="gridcell"][aria-colindex="${col}"]`;

async function openMenu(selector) {
  await page.locator(selector).click({ button: "right" });
  const section = page.locator('.ag-menu-list[role="menu"] .reach-section');
  await section.waitFor({ timeout: SECTION_WAIT });
  return section;
}

async function closeMenu() {
  await page.mouse.click(4, 4);
  await page.locator(".ag-popup-child").waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
}

test("a right-click on a blade cell appends the REACH section to the grid's own menu, scoped to the row's table and record type", async (t) => {
  await shot(t, page, async () => {
    const section = await openMenu(cell(6));
    assert.equal(await section.locator(".reach-scope").textContent(), "on ReachCrowdStrike_CL · ProcessRollup2");
    assert.deepEqual(await page.locator('.ag-menu-list [role="menuitem"] .ag-menu-option-text').allTextContents(), ["Copy value", "Filter for", "Filter to exclude"], "the blade's own items stay");
    await closeMenu();
  });
});

test("the pattern block on a blade cell speaks KQL and offers copy, since the fixture has no Monaco to insert into", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { pattern: true } } });
    const section = await openMenu(cell(6));
    const pattern = section.locator(".reach-pattern");
    assert.equal(await pattern.locator(".reach-pattern__code").textContent(), 'SHA256HashData == "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436"');
    assert.deepEqual(await pattern.locator(".reach-pattern__actions button").allTextContents(), ["Copy KQL"]);
    await closeMenu();
  });
});

test("an on-but-unconfigured relay's Set it up link is visible in the blade menu without opening any fold", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { selfhosted: true } } });
    const section = await openMenu(cell(6));
    const row = section.locator(".reach-enrich .reach-enrich__row", { hasText: "Self-hosted" });
    assert.match(await row.textContent(), /Self-hosted \(MISP \/ IntelOwl\): not configured/);
    const setup = row.locator(".reach-enrich__setup");
    assert.equal(await setup.isVisible(), true, "the link is on screen with every fold still shut");
    assert.equal(await setup.locator("xpath=ancestor::details").count(), 0, "not inside the more-sources fold");
    assert.match(await setup.getAttribute("href"), /options\.html\?platform=sentinel#module-selfhosted$/);
    await closeMenu();
    await h.setStorage({ "reach.modules": { enabled: {} } });
  });
});

test("Hold from the blade records a Sentinel pin with the table and the query off the editor", async (t) => {
  await shot(t, page, async () => {
    const section = await openMenu(cell(7, 3));
    const hold = section.locator(".reach-hold").first();
    await hold.locator(".reach-hold__btn").click();
    await hold.locator(".reach-hold__btn", { hasText: "Held" }).waitFor({ timeout: 5000 });
    const store = await h.storage();
    const entry = (store["reach.notebook"] || { investigations: [] }).investigations.flatMap((i) => i.entries).find((e) => e.field === "TargetProcessId");
    assert.ok(entry, "the pin is there");
    assert.equal(entry.value, "326552622");
    assert.equal(entry.from.platform, "sentinel");
    assert.equal(entry.from.container, "ReachCrowdStrike_CL");
    assert.match(entry.from.search.text, /ReachCrowdStrike_CL\n\| where EventSimpleName == "ProcessRollup2"/);
    await closeMenu();
  });
});
