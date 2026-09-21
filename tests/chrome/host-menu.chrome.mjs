// Reach never moves the host's own menu. A click whose menu leaves room
// for the section mounts it under the host's items as before; a click low
// in the viewport leaves the host menu's bounding rect exactly where the
// host put it and opens the section as Reach's own panel beside the menu,
// fully inside the viewport, closed when the host menu goes. Both
// platforms: Splunk's field-value popup and field-info popdown, and the
// blade's ag-Grid menu.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let splunk;
let blade;
const POPUP = ".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown";
const leaf = (name, row = 1) => `.shared-eventsviewer-list-body-row:nth-of-type(${row}) .json-tree .f-v[data-field-name="${name}"]`;
const cell = (col, rowIndex) => `.ag-root [role="row"][aria-rowindex="${rowIndex}"] [role="gridcell"][aria-colindex="${col}"]`;

before(async () => {
  h = await launch();
  splunk = await h.splunkPage();
  blade = await h.bladePage();
});
after(async () => {
  if (h) await h.close();
});

// Scrolls the leaf to `fromBottom` px above the viewport's bottom (or to
// `fromTop` below its top), clicks it the way the page does, and reads
// the popup's rect in the same tick, before Reach can have mounted.
async function clickLeaf(page, sel, { fromBottom = null, fromTop = null }) {
  return page.evaluate(
    ({ sel, fromBottom, fromTop, POPUP }) => {
      const el = document.querySelector(sel);
      const r = el.getBoundingClientRect();
      window.scrollTo(0, window.scrollY + (fromBottom !== null ? r.bottom - (window.innerHeight - fromBottom) : r.top - fromTop));
      el.click();
      const p = document.querySelector(POPUP);
      const pr = p.getBoundingClientRect();
      return { top: Math.round(pr.top), left: Math.round(pr.left), width: Math.round(pr.width), height: Math.round(pr.height), viewport: { w: window.innerWidth, h: window.innerHeight } };
    },
    { sel, fromBottom, fromTop, POPUP },
  );
}

async function popupRect(page) {
  return page.evaluate((POPUP) => {
    const r = document.querySelector(POPUP).getBoundingClientRect();
    return { top: Math.round(r.top), left: Math.round(r.left), width: Math.round(r.width), height: Math.round(r.height) };
  }, POPUP);
}

async function panelRect(page) {
  return page.evaluate(() => {
    const r = document.querySelector(".reach-panel").getBoundingClientRect();
    return { top: r.top, left: r.left, right: r.right, bottom: r.bottom, w: window.innerWidth, h: window.innerHeight };
  });
}

function assertInsideViewport(r) {
  assert.ok(r.top >= 0 && r.left >= 0 && r.right <= r.w && r.bottom <= r.h, `panel ${JSON.stringify(r)} is inside the viewport`);
}

test("Splunk: a click low in the viewport leaves the popup's rect where Splunk put it and opens the section as a panel beside it, inside the viewport", async (t) => {
  await shot(t, splunk, async () => {
    const before = await clickLeaf(splunk, leaf("IntegrityLevel"), { fromBottom: 140 });
    await splunk.locator(".reach-section").first().waitFor({ timeout: SECTION_WAIT });
    const after = await popupRect(splunk);
    const { viewport, ...menu } = before;
    assert.deepEqual(after, menu, "the popup did not move or grow");
    const panel = splunk.locator(".reach-panel");
    assert.equal(await panel.count(), 1, "the section opened as Reach's own panel");
    assert.equal(await splunk.locator(POPUP + " .reach-section").count(), 0, "nothing of Reach's is inside Splunk's popup");
    assert.equal(await panel.locator(".reach-badge").textContent(), "REACH");
    const pr = await panelRect(splunk);
    assertInsideViewport(pr);
    assert.ok(pr.left >= menu.left + menu.width, "the panel is at the popup's right edge");
    assert.ok(pr.top <= menu.top, "the panel's top is at the popup's top, or above it when the popup is low");
    // A click into the panel closes Splunk's popup (an outside click, to
    // Splunk); the panel the user is working in stays.
    await panel.locator("summary").first().click();
    await splunk.locator(POPUP).waitFor({ state: "detached", timeout: 2000 });
    await splunk.waitForTimeout(300);
    assert.equal(await panel.count(), 1, "the panel outlives the popup once clicked into");
    await splunk.mouse.click(4, 4);
    await panel.waitFor({ state: "detached", timeout: 2000 });
    // Untouched, the panel goes with the popup.
    await clickLeaf(splunk, leaf("IntegrityLevel"), { fromBottom: 140 });
    await panel.waitFor({ timeout: SECTION_WAIT });
    await splunk.mouse.click(4, 4);
    await splunk.locator(POPUP).waitFor({ state: "detached", timeout: 2000 });
    await panel.waitFor({ state: "detached", timeout: 2000 });
  });
});

test("Splunk: a click near the top mounts the section under Splunk's own items as before, no panel", async (t) => {
  await shot(t, splunk, async () => {
    await clickLeaf(splunk, leaf("IntegrityLevel"), { fromTop: 60 });
    const section = splunk.locator(POPUP + " .reach-section");
    await section.waitFor({ timeout: SECTION_WAIT });
    assert.equal(await splunk.locator(".reach-panel").count(), 0);
    assert.equal(await splunk.locator(POPUP + " li a.curr_inc_val").count(), 1, "Splunk's own items stay above the section");
    const r = await splunk.evaluate((POPUP) => {
      const s = document.querySelector(POPUP + " .reach-section").getBoundingClientRect();
      return { bottom: s.bottom, h: window.innerHeight };
    }, POPUP);
    assert.ok(r.bottom <= r.h, "the section ends inside the viewport");
    await splunk.mouse.click(4, 4);
    await splunk.locator(POPUP).waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
  });
});

// The blade's menu lives in an overlay that clips at the grid's edge: a
// cell whose section is taller than what is left between its menu and
// that edge (the ProcessHandleOpDetectInfo record type on the last row).
const FIELD_INFO = ".popdown-dialog.shared-fieldinfo";
async function openFieldInfo(page, name) {
  const before = await page.evaluate(
    ({ name, FIELD_INFO }) => {
      window.scrollTo(0, 0);
      document.querySelector(`.field-info-link[data-field-name="${name}"]`).click();
      const r = document.querySelector(FIELD_INFO).getBoundingClientRect();
      return { top: Math.round(r.top), left: Math.round(r.left), width: Math.round(r.width), height: Math.round(r.height) };
    },
    { name, FIELD_INFO },
  );
  const flyout = page.locator(FIELD_INFO + " .reach-section--flyout");
  await flyout.waitFor({ timeout: SECTION_WAIT });
  const after = await page.evaluate(
    (FIELD_INFO) => {
      const p = document.querySelector(FIELD_INFO);
      const r = p.getBoundingClientRect();
      const f = p.querySelector(".reach-section--flyout").getBoundingClientRect();
      return { popdown: { top: Math.round(r.top), left: Math.round(r.left), width: Math.round(r.width), height: Math.round(r.height) }, flyout: { top: f.top, left: f.left, right: f.right, bottom: f.bottom, w: window.innerWidth, h: window.innerHeight }, side: p.querySelector(".reach-section--flyout").dataset.side };
    },
    FIELD_INFO,
  );
  assert.deepEqual(after.popdown, before, "the popdown did not move or grow");
  assertInsideViewport(after.flyout);
  return after;
}

async function closeFieldInfo(page) {
  await page.mouse.click(4, 4);
  await page.locator(FIELD_INFO).waitFor({ state: "detached", timeout: 2000 });
}

test("Splunk: the field-info flyout takes the popdown's right when there is room, its left when there is not, below when neither side has, and the popdown never moves", async (t) => {
  t.after(() => splunk.setViewportSize({ width: 1280, height: 900 }));
  await shot(t, splunk, async () => {
    // The sidebar's last name sits at the page's right edge: Splunk keeps
    // the popdown inside the viewport, so its right has no room.
    const left = await openFieldInfo(splunk, "CommandLine");
    assert.equal(left.side, "left");
    assert.ok(left.flyout.right <= left.popdown.left, "the flyout is at the popdown's left edge");
    await closeFieldInfo(splunk);

    const right = await openFieldInfo(splunk, "ImageFileName");
    assert.equal(right.side, "right");
    assert.ok(right.flyout.left >= right.popdown.left + right.popdown.width, "the flyout is at the popdown's right edge");
    await closeFieldInfo(splunk);

    await splunk.setViewportSize({ width: 1000, height: 900 });
    const below = await openFieldInfo(splunk, "CommandLine");
    assert.equal(below.side, "below");
    assert.ok(below.flyout.top >= below.popdown.top + below.popdown.height, "the flyout is under the popdown");
    await closeFieldInfo(splunk);
  });
});

test("Sentinel: a right-click whose section does not fit above the grid's edge leaves the blade's menu where ag-Grid put it and opens the section beside it, inside the viewport", async (t) => {
  await shot(t, blade, async () => {
    const before = await blade.evaluate((sel) => {
      const el = document.querySelector(sel);
      const r = el.getBoundingClientRect();
      el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: r.left + 20, clientY: r.top + 10 }));
      const m = document.querySelector(".ag-popup-child").getBoundingClientRect();
      return { top: Math.round(m.top), left: Math.round(m.left), width: Math.round(m.width), height: Math.round(m.height) };
    }, cell(3, 6));
    await blade.locator(".reach-section").first().waitFor({ timeout: SECTION_WAIT });
    const after = await blade.evaluate(() => {
      const m = document.querySelector(".ag-popup-child").getBoundingClientRect();
      return { top: Math.round(m.top), left: Math.round(m.left), width: Math.round(m.width), height: Math.round(m.height) };
    });
    assert.deepEqual(after, before, "the menu did not move or grow");
    const panel = blade.locator(".reach-panel");
    assert.equal(await panel.count(), 1, "the section opened as Reach's own panel");
    assert.equal(await blade.locator('.ag-menu-list[role="menu"] .reach-section').count(), 0, "nothing of Reach's is inside the blade's menu");
    assert.deepEqual(await blade.locator('.ag-menu-list [role="menuitem"] .ag-menu-option-text').allTextContents(), ["Copy value", "Filter for", "Filter to exclude"]);
    const pr = await panelRect(blade);
    assertInsideViewport(pr);
    assert.ok(pr.left >= before.left + before.width, "the panel is at the menu's right edge");
    await blade.mouse.click(4, 4);
    await blade.locator(".ag-popup-child").waitFor({ state: "detached", timeout: 2000 });
    await panel.waitFor({ state: "detached", timeout: 2000 });
  });
});

test("Sentinel: a right-click with room below mounts the section in the blade's menu as before, no panel", async (t) => {
  await shot(t, blade, async () => {
    await blade.locator(cell(6, 2)).click({ button: "right" });
    const section = blade.locator('.ag-menu-list[role="menu"] .reach-section');
    await section.waitFor({ timeout: SECTION_WAIT });
    assert.equal(await blade.locator(".reach-panel").count(), 0);
    const r = await blade.evaluate(() => {
      const s = document.querySelector('.ag-menu-list[role="menu"] .reach-section').getBoundingClientRect();
      return { bottom: s.bottom, h: window.innerHeight };
    });
    assert.ok(r.bottom <= r.h, "the section ends inside the viewport");
    await blade.mouse.click(4, 4);
    await blade.locator(".ag-popup-child").waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
  });
});
