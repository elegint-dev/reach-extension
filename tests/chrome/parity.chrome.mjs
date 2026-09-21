// Popup and value page parity (C5): for the same click, the in-page popup
// (Splunk's value menu, the Sentinel grid's menu) and the panel's value
// page draw the same bands under the same registry titles in the same
// order, with the same action row; a field click (a Splunk JSON key, a
// Sentinel column header) walks the same list with no value line, no
// verdict and no action row. The popups are one assembler
// (app/lib/click-section.js sectionFor) and the page's section loop reads
// the same band plan (bands/band.js plan), so the id lists agree by
// construction; this suite holds the rendered result on both hosts.
// Exceptions, and only these: the popup's Run control (the page has the
// drawer) and the page's FDR carriers ledger (Splunk), which is why the
// Pivots count may differ.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, openValuePopup, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let splunk;
let blade;
const POPUP = ".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown";
const leaf = (name, row = 1) => `.shared-eventsviewer-list-body-row:nth-of-type(${row}) .json-tree .f-v[data-field-name="${name}"]`;
const cell = (col, rowIndex = 2) => `.ag-root [role="row"][aria-rowindex="${rowIndex}"] [role="gridcell"][aria-colindex="${col}"]`;
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";

before(async () => {
  h = await launch();
  splunk = await h.splunkPage();
  blade = await h.bladePage();
});
after(async () => {
  if (h) await h.close();
});

// The popup's bands: id and title, in document order; the action row's labels.
const readPopup = (section) =>
  section.evaluate((el) => ({
    bands: Array.from(el.querySelectorAll(":scope > [data-band]")).map((b) => ({ band: b.dataset.band, title: (b.querySelector(":scope > .reach-row__title, :scope > summary > .reach-row__title") || {}).textContent || null })),
    actions: Array.from(el.querySelectorAll(":scope > .reach-hold .reach-hold__btn, :scope > .reach-benign .reach-benign__btn")).map((b) => b.textContent.trim()),
    decode: (el.querySelector(".reach-value__body") || {}).textContent || null,
  }));

// The page's sections: id and h2, in document order; the action row's labels.
const readPage = (page) =>
  page.evaluate(() => ({
    bands: Array.from(document.querySelectorAll("main section[data-band]")).map((s) => ({ band: s.dataset.band, title: s.querySelector("h2").textContent })),
    actions: Array.from(document.querySelectorAll(".r-actions .reach-hold__btn, .r-actions .reach-benign__btn")).map((b) => b.textContent.trim()),
    decode: (document.querySelector(".r-value__meaning") || {}).textContent || null,
  }));

// The section's children beside the REACH badge and the head (the scope
// line, the action rows): every one a band, so no line sits outside a
// registry title.
const HEAD_PARTS = ["reach-badge", "reach-scope", "reach-head", "reach-hold", "reach-benign"];
const readStray = (section, head = HEAD_PARTS) => section.evaluate((el, head) => Array.from(el.children).filter((c) => !c.dataset.band && !head.some((cls) => c.classList.contains(cls))).map((c) => c.className), head);

// The Pivots count differs by the page's ledger, the written exception.
const norm = (list) => list.map((b) => ({ band: b.band, title: b.band === "pivots" ? b.title.replace(/ \(\d+\)$/, "") : b.title }));

async function closeSplunkPopup() {
  await splunk.mouse.click(4, 4);
  await splunk.locator(POPUP).waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
}

async function openBladeMenu(selector) {
  await blade.locator(selector).click({ button: "right" });
  const section = blade.locator('.ag-menu-list[role="menu"] .reach-section');
  await section.waitFor({ timeout: SECTION_WAIT });
  return section;
}

async function closeBladeMenu() {
  await blade.mouse.click(4, 4);
  await blade.locator(".ag-popup-child").waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
}

// The panel: app.js decides it is the panel by chrome.tabs.getCurrent()
// resolving to no tab (followPanel), so a plain extension tab with that
// call spoofed takes the clicks the way the real panel does.
async function panelFor(platform) {
  const panel = await h.context.newPage();
  await panel.addInitScript(() => {
    chrome.tabs.getCurrent = () => Promise.resolve(undefined);
  });
  await panel.goto(h.url(`index.html?platform=${platform}#/`));
  await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
  return panel;
}

async function settle(page) {
  await page.waitForFunction(() => !document.querySelector('.reach-verdict[data-tier="pending"]'), { timeout: SECTION_WAIT }).catch(() => {});
}

test("J1 on Splunk: the SHA256 value click draws the same bands, titles and actions in the popup and on the value page", async (t) => {
  await shot(t, splunk, async () => {
    await h.clearStorage();
    const section = await openValuePopup(splunk, leaf("SHA256HashData", 4));
    await settle(splunk);
    const popup = await readPopup(section);
    const stray = await readStray(section);
    await closeSplunkPopup();
    assert.deepEqual(popup.bands.map((b) => b.band), ["verdict", "meaning", "everywhere", "enrich", "pivots", "workflows"]);
    assert.deepEqual(popup.actions, ["Hold", "Mark benign"]);
    assert.deepEqual(stray, [], "every line sits under a band title");

    const panel = await panelFor("splunk");
    await splunk.locator(leaf("SHA256HashData", 4)).first().click();
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });
    await panel.evaluate((hash) => { location.hash = hash; }, `#/v/${HASH}?st=crowdstrike:events:sensor&name=SHA256HashData&on=ProcessRollup2`);
    await panel.waitForSelector('main section[data-band="pivots"]', { timeout: 5000 });
    await settle(panel);
    const page = await readPage(panel);
    await panel.close();
    await closeSplunkPopup();
    assert.deepEqual(norm(page.bands), norm(popup.bands));
    assert.deepEqual(page.actions, popup.actions);
  });
});

test("J2 on Splunk: a decoded value (IntegrityLevel = 12288) reads the decode on both surfaces under the same bands", async (t) => {
  await shot(t, splunk, async () => {
    const section = await openValuePopup(splunk, leaf("IntegrityLevel"));
    const popup = await readPopup(section);
    await closeSplunkPopup();
    assert.match(popup.decode, /High \(elevated\)/);

    const panel = await panelFor("splunk");
    await splunk.locator(leaf("IntegrityLevel")).first().click();
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });
    await panel.evaluate(() => { location.hash = "#/v/12288?st=crowdstrike:events:sensor&name=IntegrityLevel&on=ProcessRollup2"; });
    await panel.waitForSelector('main section[data-band="meaning"]', { timeout: 5000 });
    const page = await readPage(panel);
    await panel.close();
    await closeSplunkPopup();
    assert.match(page.decode, /High \(elevated\)/);
    assert.deepEqual(norm(page.bands), norm(popup.bands));
    assert.deepEqual(page.actions, popup.actions);
  });
});

test("J1 on Sentinel: the SHA256 cell draws the same bands, titles and actions in the grid menu and on the value page", async (t) => {
  await shot(t, blade, async () => {
    const section = await openBladeMenu(cell(6));
    const popup = await readPopup(section);
    const stray = await readStray(section);
    await closeBladeMenu();
    // No verdict off a Windows row, no workflows on Sentinel; the
    // everywhere band draws because the inventory pack also binds
    // SHA256HashData on CrowdStrike_Secondary_Data_CL.
    assert.deepEqual(popup.bands.map((b) => b.band), ["meaning", "everywhere", "enrich", "pivots"]);
    assert.deepEqual(popup.actions, ["Hold", "Mark benign"]);
    assert.deepEqual(stray, [], "every line sits under a band title");

    const panel = await panelFor("sentinel");
    await blade.locator(cell(6)).click({ button: "right" });
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });
    await panel.evaluate((hash) => { location.hash = hash; }, `#/v/${HASH}?st=ReachCrowdStrike_CL&name=SHA256HashData&on=ProcessRollup2`);
    await panel.waitForSelector('main section[data-band="pivots"]', { timeout: 5000 });
    const page = await readPage(panel);
    const noLedger = await panel.evaluate(() => document.querySelectorAll(".r-ledger__band").length);
    await panel.close();
    await closeBladeMenu();
    assert.equal(noLedger, 0, "the carriers ledger is Splunk knowledge");
    assert.deepEqual(norm(page.bands), norm(popup.bands));
    assert.deepEqual(page.actions, popup.actions);
  });
});

test("a Splunk field-name click (the JSON key) walks the same bands with no value line, no verdict and no action row: Meaning, Other sourcetypes, Pivots by name, Workflows", async (t) => {
  await shot(t, splunk, async () => {
    await splunk.locator('.shared-eventsviewer-list-body-row:nth-of-type(4) .json-tree .key-name[data-reach-key][data-field-name="SHA256HashData"]').first().click();
    const section = splunk.locator(".reach-panel .reach-section");
    await section.waitFor({ timeout: SECTION_WAIT });
    const popup = await readPopup(section);
    const stray = await readStray(section);
    await splunk.mouse.click(4, 4);
    assert.deepEqual(popup.bands.map((b) => b.band), ["meaning", "everywhere", "pivots", "workflows"]);
    assert.equal(popup.bands[0].title, "Meaning");
    assert.match(popup.bands[1].title, /^Other sourcetypes \(\d+\)$/);
    assert.match(popup.bands[2].title, /^Pivots \(\d+\)$/);
    assert.equal(popup.bands[3].title, "Workflows");
    assert.deepEqual(popup.actions, []);
    assert.equal(popup.decode, null);
    assert.deepEqual(stray, [], "every line sits under a band title");
  });
});

test("a Sentinel column click walks the same bands with no value line, no verdict and no action row: Meaning, then Pivots by name, no everywhere band on a column no other table binds", async (t) => {
  await shot(t, blade, async () => {
    // TargetProcessId is bound only on ReachCrowdStrike_CL on Sentinel:
    // the negative case for the everywhere band's presence rule.
    await blade.locator('[role="columnheader"][col-id="TargetProcessId"]').click({ button: "right" });
    const section = blade.locator(".reach-panel .reach-section");
    await section.waitFor({ timeout: SECTION_WAIT });
    const popup = await readPopup(section);
    assert.deepEqual(popup.bands.map((b) => b.band), ["meaning", "pivots"]);
    assert.equal(popup.bands[0].title, "Meaning");
    assert.match(popup.bands[1].title, /^Pivots \(\d+\)$/);
    assert.deepEqual(popup.actions, []);
    assert.equal(popup.decode, null);
    assert.deepEqual(await readStray(section), [], "every line sits under a band title");
    await blade.mouse.click(4, 4);
  });
});

// The bitmask rule on the handle-open row (DesiredAccess = 2097151): one
// decode path, so the popup's value band and the value page read the flag
// set on both hosts, and the FDR bundle's absence on Sentinel changes nothing.
test("J2 on Splunk: DesiredAccess = 2097151 on the handle-open event reads PROCESS_ALL_ACCESS (0x1FFFFF) in the popup and on the value page", async (t) => {
  await shot(t, splunk, async () => {
    const section = await openValuePopup(splunk, leaf("DesiredAccess", 6));
    const popup = await readPopup(section);
    await closeSplunkPopup();
    assert.match(popup.decode, /^2097151: PROCESS_ALL_ACCESS \(0x1FFFFF\)/);

    const panel = await panelFor("splunk");
    await splunk.locator(leaf("DesiredAccess", 6)).first().click();
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });
    await panel.evaluate(() => { location.hash = "#/v/2097151?st=crowdstrike:events:sensor&name=DesiredAccess&on=ProcessHandleOpDetectInfo"; });
    await panel.waitForSelector('main section[data-band="meaning"]', { timeout: 5000 });
    const page = await readPage(panel);
    await panel.close();
    await closeSplunkPopup();
    assert.match(page.decode, /PROCESS_ALL_ACCESS \(0x1FFFFF\)/);
    assert.deepEqual(norm(page.bands), norm(popup.bands));
  });
});

test("J2 on Sentinel: the DesiredAccess cell on the handle-open row reads PROCESS_ALL_ACCESS (0x1FFFFF) in the grid menu and on the value page", async (t) => {
  await shot(t, blade, async () => {
    // The handle-open row sits low in the grid, so the section may open
    // beside the menu rather than inside it (menu-fit.js): read either.
    await blade.locator(cell(10, 6)).click({ button: "right" });
    const section = blade.locator('.ag-menu-list[role="menu"] .reach-section, .reach-panel .reach-section');
    await section.waitFor({ timeout: 8000 });
    const popup = await readPopup(section);
    await closeBladeMenu();
    await blade.mouse.click(4, 4);
    assert.match(popup.decode, /^2097151: PROCESS_ALL_ACCESS \(0x1FFFFF\)/);

    const panel = await panelFor("sentinel");
    await blade.locator(cell(10, 6)).click({ button: "right" });
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });
    await panel.evaluate(() => { location.hash = "#/v/2097151?st=ReachCrowdStrike_CL&name=DesiredAccess&on=ProcessHandleOpDetectInfo"; });
    await panel.waitForSelector('main section[data-band="meaning"]', { timeout: 5000 });
    const page = await readPage(panel);
    await panel.close();
    await closeBladeMenu();
    assert.match(page.decode, /PROCESS_ALL_ACCESS \(0x1FFFFF\)/);
    assert.deepEqual(norm(page.bands), norm(popup.bands));
  });
});
