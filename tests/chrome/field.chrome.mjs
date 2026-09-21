// The field page in the side panel as the extension serves it: the title
// block first, headings from the registry in the entity master order, the
// clicked value's verdict and enrichment on the page a click lands on, and
// the Hold action writing the notebook from the title block.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let page;
const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
const ST = "crowdstrike:events:sensor";
const ROUTES = [
  `#/f/SHA256HashData?st=${ST}&on=ProcessRollup2&value=${HASH}`,
  `#/f/DesiredAccess?st=${ST}&on=ProcessHandleOpDetectInfo&value=2097151`,
  `#/f/TemplateDisposition?st=${ST}&value=30`,
  `#/f/RawProcessId?st=${ST}&value=936`,
  `#/f/TargetProcessId?st=${ST}&on=ProcessHandleOpDetectInfo&value=5497396`,
];

before(async () => {
  h = await launch({ viewport: { width: 380, height: 600 } });
  page = await h.extensionPage("index.html?platform=splunk#/");
  await page.waitForSelector("main", { timeout: 5000 });
  await page.evaluate((fields) => sessionStorage.setItem("reach.lastEvent", JSON.stringify({ platform: "splunk", container: "crowdstrike:events:sensor", fields, at: Date.now() })), { event_platform: "Mac", SHA256HashData: HASH, ImageFileName: "/usr/bin/ssh", event_simpleName: "ProcessRollup2" });
});
after(async () => {
  if (h) await h.close();
});

async function go(route) {
  // field.js's render() rewrites the query string itself (the value/index
  // params are stripped once read, `on` is added when the route omits it),
  // which re-enters renderRoute() and re-renders main a second time before
  // the first call returns; wait for the title block that lands from that
  // settled state instead of guessing how long it takes.
  await page.evaluate((r) => { location.hash = r; }, route);
  await page.waitForFunction(() => {
    const view = document.querySelector("main")?.firstElementChild;
    const title = view?.firstElementChild;
    return Boolean(title && /^r-title\b/.test(title.className));
  });
}

// The first screen's geometry, read inside the page: the view's first
// child, the bottoms of the scope line and the action row, the first
// section heading's top (the drawer's own empty h2 skipped), the callout
// slot's height and how many callouts it stacks.
function firstScreen() {
  const main = document.querySelector("main");
  const view = main.firstElementChild;
  const title = view && view.firstElementChild;
  const bottom = (s) => { const el = document.querySelector(s); return el ? Math.round(el.getBoundingClientRect().bottom) : null; };
  const h2 = [...document.querySelectorAll("main h2")].find((n) => n.textContent.trim());
  const slot = document.querySelector(".r-title__callout");
  return {
    firstClass: title ? title.className : null,
    actions: bottom(".r-actions"),
    scope: bottom(".r-scope"),
    h2: h2 ? Math.round(h2.getBoundingClientRect().top) : null,
    callout: slot ? Math.round(slot.getBoundingClientRect().height) : 0,
    callouts: slot ? slot.querySelectorAll(".r-callout").length : 0,
    decodeChip: Boolean(document.querySelector(".r-title__chips .r-chip--decode")),
    chipRows: (() => { const c = document.querySelector(".r-title__chips"); return c ? Math.round(c.getBoundingClientRect().height / 28) : 0; })(),
  };
}

// The first h2 starts inside 400 px on an entity route. The one exception:
// a slot stacking a hazard callout and the Sentinel platform note, which
// the contract budgets at 40 px more.
function h2Budget(first) {
  return first.callouts > 1 ? 440 : 400;
}

// The page's headings as registry ids, resolved inside the extension page.
async function headingIds() {
  return page.evaluate(async () => {
    const m = await import(chrome.runtime.getURL("app/lib/headings.js"));
    const resolve = m.matcher();
    return [...document.querySelectorAll("main h2")].filter((n) => n.textContent.trim()).map((n) => { const e = resolve(n.textContent); return e ? e.id : `?${n.textContent.trim()}`; });
  });
}

test("every field route draws the title block first with the action row inside 600 px, and its h2s follow the entity master", async (t) => {
  await shot(t, page, async () => {
    const order = await page.evaluate(async () => (await import(chrome.runtime.getURL("app/lib/headings.js"))).ENTITY_ORDER);
    for (const route of ROUTES) {
      await go(route);
      const first = await page.evaluate(firstScreen);
      assert.match(first.firstClass || "", /^r-title\b/, `${route}: the title block is the view's first child`);
      assert.ok(first.actions && first.actions <= 600, `${route}: action row bottom ${first.actions}`);
      assert.ok(first.scope && first.scope <= 600, `${route}: scope line bottom ${first.scope}`);
      assert.ok(first.h2 && first.h2 <= h2Budget(first), `${route}: first h2 top ${first.h2} with a ${first.callout} px callout`);
      const ids = await headingIds();
      assert.ok(!ids.some((id) => id.startsWith("?")), `${route}: ${ids.join(", ")}`);
      let i = 0;
      for (const id of ids) {
        i = order.indexOf(id, i);
        assert.ok(i >= 0, `${route}: ${ids.join(" > ")} is not in the master order`);
        i += 1;
      }
    }
  });
});

test("at 320 x 600 with two values pinned, every field route on both platforms keeps its first h2 inside 400 px, with the decode chip drawn", async (t) => {
  const HELD = { aid: "abc123def4567890abc123def4567890", SHA256HashData: HASH };
  const SENTINEL = [
    `#/f/SHA256HashData?st=ReachCrowdStrike_CL&on=ProcessRollup2&value=${HASH}`,
    `#/f/DesiredAccess?st=ReachCrowdStrike_CL&on=ProcessHandleOpDetectInfo&value=2097151`,
    `#/f/RawProcessId?st=ReachCrowdStrike_CL&value=936`,
    `#/f/TemplateDisposition?st=ReachCrowdStrike_CL&value=30`,
  ];
  for (const [platform, routes] of [["splunk", ROUTES], ["sentinel", SENTINEL]]) {
    const narrow = await h.extensionPage(`index.html?platform=${platform}#/`, { viewport: { width: 320, height: 600 } });
    try {
      await shot(t, narrow, async () => {
        await narrow.waitForSelector("main", { timeout: 5000 });
        await narrow.evaluate((held) => localStorage.setItem("reach.pinned", JSON.stringify(held)), HELD);
        await narrow.reload();
        await narrow.waitForSelector(".r-holding", { timeout: 5000 });
        for (const route of routes) {
          await narrow.evaluate((r) => { location.hash = r; }, route);
          await narrow.waitForTimeout(500);
          const first = await narrow.evaluate(firstScreen);
          assert.match(first.firstClass || "", /^r-title\b/, `${platform} ${route}: the title block first`);
          assert.ok(first.decodeChip, `${platform} ${route}: the decode chip`);
          assert.ok(first.chipRows <= 2, `${platform} ${route}: chip rows ${first.chipRows}`);
          assert.ok(first.actions <= 600, `${platform} ${route}: action row bottom ${first.actions}`);
          assert.ok(first.h2 && first.h2 <= h2Budget(first), `${platform} ${route}: first h2 top ${first.h2} with a ${first.callout} px callout`);
        }
      });
    } finally {
      await narrow.close();
    }
  }
});

test("the landing for a hash click carries the verdict chip, Verdict and Enrichment before Pivots, and Workflows within reach of Pivots", async (t) => {
  await shot(t, page, async () => {
    await go(ROUTES[0]);
    const ids = await headingIds();
    assert.ok(ids.indexOf("verdict") >= 0 && ids.indexOf("verdict") < ids.indexOf("enrichment") && ids.indexOf("enrichment") < ids.indexOf("pivots"), ids.join(", "));
    await page.waitForSelector(".r-chip--verdict:not([data-tier=pending])", { timeout: 5000 });
    const facts = await page.evaluate(() => {
      const h2 = [...document.querySelectorAll("main h2")];
      const piv = h2.find((n) => /^Pivots \((\d+)\)$/.test(n.textContent.trim()));
      const wf = h2.find((n) => n.textContent.trim() === "Workflows");
      const n = Number(/\((\d+)\)/.exec(piv.textContent)[1]);
      const folded = [...document.querySelectorAll(".r-pivots details.r-ledger__fold")].map((d) => d.open);
      return { n, gap: Math.round(wf.getBoundingClientRect().top - piv.getBoundingClientRect().top), folded, packFirst: document.querySelector(".r-pivots .r-packpivots__list") !== null, held: document.querySelector(".r-title__held").textContent.trim() };
    });
    assert.equal(facts.folded.length, 5, "the five ledger bands");
    assert.ok(facts.folded.every((o) => o === false), "every band folds closed on the panel");
    assert.ok(facts.gap <= 28 + 64 * facts.n + 5 * 44, `Workflows ${facts.gap} px under Pivots (${facts.n})`);
    assert.ok(facts.packFirst, "the pack's pivots lead the section");
    assert.match(facts.held, /^value 8ae6/);
  });
});

test("Hold in the title block records the pin in the notebook and the button says so", async (t) => {
  await shot(t, page, async () => {
    await page.evaluate(() => localStorage.removeItem("notebook"));
    await go(ROUTES[2]);
    await page.click(".r-actions .r-action-hold");
    await page.waitForFunction(() => document.querySelector(".r-action-hold").textContent.trim() === "Held ✓", null, { timeout: 5000 });
    const status = await page.$eval(".r-title__keep .reach-hold__status", (el) => el.textContent);
    assert.match(status, /^Held · .* · Release$/);
    const pins = await page.evaluate(async () => {
      const nb = await import(chrome.runtime.getURL("app/lib/notebook.js"));
      await nb.load();
      const inv = nb.current();
      return inv ? inv.entries.filter((e) => e.kind === "pin").map((e) => `${e.field}=${e.value}`) : [];
    });
    assert.deepEqual(pins, ["TemplateDisposition=30"]);
    // Mark benign opens the reason and expiry under the action row.
    await page.click(".r-actions .r-action-benign");
    assert.equal(await page.$eval(".r-title__keep .reach-benign", (el) => el.hidden), false);
    assert.equal(await page.$eval(".r-title__keep .reach-benign .reach-benign__expiry", (el) => el.tagName), "SELECT");
  });
});

test("on the value page Hold and Mark benign sit in the action row and what they open is the keep row under it, a sibling of the action row, hidden until pressed", async (t) => {
  await shot(t, page, async () => {
    // A value the tests before did not hold or mark.
    await go(`#/v/2097151?st=${ST}&name=DesiredAccess&on=ProcessHandleOpDetectInfo`);
    const before = await page.evaluate(() => {
      const title = document.querySelector(".r-title");
      const actions = title.querySelector(".r-actions");
      const keep = title.querySelector(".r-title__keep");
      return {
        actions: [...actions.children].map((b) => b.textContent.trim()),
        keepIsSibling: keep !== null && keep.parentElement === title && keep.previousElementSibling === actions,
        keepHidden: keep ? keep.hidden : null,
        benignInActions: actions.querySelector(".reach-benign") !== null,
        actionsBottom: Math.round(actions.getBoundingClientRect().bottom),
      };
    });
    assert.deepEqual(before.actions, ["Hold", "Mark benign"]);
    assert.equal(before.keepIsSibling, true, "the keep row follows the action row inside the title block");
    assert.equal(before.keepHidden, true, "nothing to show yet");
    assert.equal(before.benignInActions, false, "the benign block is not a child of the action row");
    await page.click(".r-actions .reach-benign__btn");
    await page.waitForFunction(() => document.querySelector(".r-title__keep") && !document.querySelector(".r-title__keep").hidden, null, { timeout: 2000 });
    const opened = await page.evaluate(() => {
      const keep = document.querySelector(".r-title__keep");
      const form = keep.querySelector(".reach-benign__form");
      const actions = document.querySelector(".r-actions").getBoundingClientRect();
      return { formHidden: form.hidden, expiry: form.querySelector(".reach-benign__expiry").tagName, formTop: Math.round(form.getBoundingClientRect().top), actionsBottom: Math.round(actions.bottom), width: keep.getBoundingClientRect().right <= document.documentElement.clientWidth };
    });
    assert.equal(opened.formHidden, false);
    assert.equal(opened.expiry, "SELECT");
    assert.ok(opened.formTop >= opened.actionsBottom, `the reason and expiry open under the action row (${opened.formTop} vs ${opened.actionsBottom})`);
    assert.ok(opened.width, "inside the panel's edge");
    await page.click(".r-actions .reach-hold__btn");
    await page.waitForFunction(() => /^Held/.test(document.querySelector(".r-actions .reach-hold__btn").textContent.trim()), null, { timeout: 5000 });
    const held = await page.evaluate(() => ({ release: document.querySelector(".r-title__keep .reach-hold__release") !== null, status: document.querySelector(".r-title__keep .reach-hold__status").textContent.trim() }));
    assert.equal(held.release, true, "a Release control is drawn once held, the same row as the field page");
    assert.match(held.status, /^Held · .* · Release$/);
  });
});

test("on Sentinel the platform note is the callout where no pivot exists and the Pivots line where one does", async (t) => {
  const sentinel = await h.extensionPage("index.html?platform=sentinel#/f/TemplateDisposition?st=ReachCrowdStrike_CL&value=30");
  try {
    await shot(t, sentinel, async () => {
      await sentinel.waitForSelector(".r-title", { timeout: 5000 });
      const note = await sentinel.$eval(".r-title__callout", (el) => el.textContent);
      assert.match(note, /No guided workflow on Sentinel/);
      assert.equal(await sentinel.$(".r-pivots"), null);
      await sentinel.evaluate(() => { location.hash = "#/f/SHA256HashData?st=ReachCrowdStrike_CL&on=ProcessRollup2"; });
      await sentinel.waitForTimeout(400);
      assert.match(await sentinel.$eval(".r-pivots__platform", (el) => el.textContent), /Copy KQL/);
      assert.equal(await sentinel.$(".r-ledger__band"), null, "no FDR ledger on Sentinel");
      assert.equal(await sentinel.$(".r-title__callout"), null);
    });
  } finally {
    await sentinel.close();
  }
});

test("a blade right-click on the Mac hash with the panel open lands the Sentinel field page with the verdict tier on the first screen at 320 x 600", async (t) => {
  // The native side panel cannot be driven; app.js takes chrome.tabs.getCurrent()
  // resolving to no tab as the panel, so a 320 x 600 extension tab with that one
  // call spoofed walks the same handoff a real panel does.
  const panel = await h.newPage({ viewport: { width: 320, height: 600 } });
  const blade = await h.bladePage();
  try {
    await shot(t, panel, async () => {
      await panel.addInitScript(() => {
        chrome.tabs.getCurrent = () => Promise.resolve(undefined);
      });
      await panel.goto(h.url("index.html?platform=sentinel#/"));
      await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
      // The Mac row (aria-rowindex 5) carries the corpus-matched contactsd hash.
      await blade.locator('.ag-root [role="row"][aria-rowindex="5"] [role="gridcell"][aria-colindex="6"]').click({ button: "right" });
      await panel.waitForFunction(() => location.hash.startsWith("#/f/SHA256HashData"), { timeout: SECTION_WAIT });
      await panel.waitForSelector(".r-chip--verdict:not([data-tier=pending])", { timeout: SECTION_WAIT });
      const seen = await panel.evaluate(() => {
        const chip = document.querySelector(".r-chip--verdict");
        const r = chip.getBoundingClientRect();
        const h2 = [...document.querySelectorAll("main h2")].map((n) => n.textContent.trim()).filter(Boolean);
        return { tier: chip.dataset.tier, text: chip.textContent.trim(), bottom: Math.round(r.bottom), scrollY: window.scrollY, h2, st: new URLSearchParams(location.hash.split("?")[1]).get("st") };
      });
      assert.equal(seen.st, "ReachCrowdStrike_CL");
      assert.equal(seen.tier, "normal");
      assert.equal(seen.scrollY, 0);
      assert.ok(seen.bottom <= 600, `verdict chip bottom ${seen.bottom}`);
      assert.ok(seen.h2.includes("Verdict"), seen.h2.join(", "));
    });
  } finally {
    await blade.close();
    await panel.close();
  }
});

// The panel: app.js takes chrome.tabs.getCurrent() resolving to no tab as
// the panel, so a 320 x 600 extension tab with that call spoofed walks the
// same handoff. A fresh panel takes the window's last click on hello (the
// test before's, on either platform): that lands before the test's own.
async function panelFor(platform) {
  const panel = await h.newPage({ viewport: { width: 320, height: 600 } });
  await panel.addInitScript(() => {
    chrome.tabs.getCurrent = () => Promise.resolve(undefined);
  });
  await panel.goto(h.url(`index.html?platform=${platform}#/`));
  await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
  await panel.waitForTimeout(800);
  await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
  return panel;
}

// What the panel holds after a click: the notebook's pins, the tab's held
// facts, the browser's pins, and what the Holding rail draws.
async function heldState(panel) {
  return panel.evaluate(async () => {
    const nb = await import(chrome.runtime.getURL("app/lib/notebook.js"));
    await nb.load({ force: true });
    const inv = nb.current();
    return {
      pins: inv ? inv.entries.filter((e) => e.kind === "pin").map((e) => `${e.field}=${e.value}`) : [],
      tabFacts: JSON.parse(sessionStorage.getItem("reach.investigation") || "{}"),
      pinned: localStorage.getItem("reach.pinned"),
      chips: document.querySelectorAll(".r-holding__chip").length,
      empty: document.querySelector(".r-holding").classList.contains("r-holding--empty"),
    };
  });
}

// J1 through the panel on both platforms: the hash click lands the field
// page with the value line, the decode chip and the verdict, and holds
// nothing until Hold is pressed.
// A clean notebook and no pins, so what is held after a walk is that
// walk's alone (the notebook is one document across the panels this file
// opens, and an earlier walk's Hold would otherwise show as a pin here).
async function clearHeld(panel) {
  await panel.evaluate(async () => {
    localStorage.removeItem("reach.pinned");
    const store = await import(chrome.runtime.getURL("app/lib/store.js"));
    const nb = await import(chrome.runtime.getURL("app/lib/notebook.js"));
    await store.remove(nb.KEY);
    await nb.load({ force: true });
  });
}

async function walkJ1(t, panel, clickHash, st) {
  await shot(t, panel, async () => {
    await clearHeld(panel);
    await clickHash();
    await panel.waitForFunction((s) => location.hash.startsWith(`#/f/SHA256HashData?st=${encodeURIComponent(s)}`) && /[?&]value=/.test(location.hash), st, { timeout: SECTION_WAIT });
    await panel.waitForSelector(".r-chip--verdict:not([data-tier=pending])", { timeout: SECTION_WAIT });
    const seen = await panel.evaluate(() => ({
      line: document.querySelector(".r-title__held").textContent.trim(),
      decode: (document.querySelector(".r-title__chips .r-chip--decode") || {}).textContent,
      verdict: { tier: document.querySelector(".r-chip--verdict").dataset.tier, title: document.querySelector(".r-chip--verdict").title },
      text: document.querySelector(".r-title").textContent,
    }));
    assert.match(seen.line, /^value 077fc518\S* →$/, `the value line: ${seen.line}`);
    assert.ok(seen.decode, "the decode chip");
    assert.equal(seen.verdict.tier, "normal");
    assert.doesNotMatch(seen.verdict.title, /held/, seen.verdict.title);
    assert.doesNotMatch(seen.text, /\bheld\b/i, "nothing on the landing calls the click held");
    const before = await heldState(panel);
    assert.deepEqual(before.pins, [], "no pin from the click");
    assert.deepEqual(before.tabFacts, {}, "no held fact from the click");
    assert.equal(before.pinned, null, "nothing pinned from the click");
    assert.equal(before.chips, 0, "the Holding rail draws nothing");
    assert.equal(before.empty, true);
    await panel.click(".r-actions .r-action-hold");
    await panel.waitForFunction(() => document.querySelector(".r-action-hold").textContent.trim() === "Held ✓", null, { timeout: 5000 });
    const after = await heldState(panel);
    assert.deepEqual(after.pins, ["SHA256HashData=077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9"], "one pin from Hold");
    assert.equal(after.chips, 1, "the Holding rail draws the held value");
    assert.equal(after.empty, false);
  });
}

test("J1: the Mac hash click on the Splunk search page with the panel open lands the field page showing the value line, the decode chip and the verdict, holds nothing, and Hold makes one pin", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    await walkJ1(t, panel, () => search.locator('.shared-eventsviewer-list-body-row:nth-of-type(4) .json-tree .f-v[data-field-name="SHA256HashData"]').first().click(), "crowdstrike:events:sensor");
  } finally {
    await search.close();
    await panel.close();
  }
});

test("J1 on Sentinel: the Mac hash right-click on the blade with the panel open lands the field page showing the value line, the decode chip and the verdict, holds nothing, and Hold makes one pin", async (t) => {
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    await walkJ1(t, panel, () => blade.locator('.ag-root [role="row"][aria-rowindex="5"] [role="gridcell"][aria-colindex="6"]').click({ button: "right" }), "ReachCrowdStrike_CL");
  } finally {
    await blade.close();
    await panel.close();
  }
});

// The verdict's other two tiers through the panel on both platforms: the
// fixture rows are found by their text, not their position. `click` lands
// the row's `field` in the panel; the field page's verdict chip settles on
// `tier` and the verdict band's headline reads `headline`.
async function walkTier(t, panel, { click, st, field, tier, headline }) {
  await shot(t, panel, async () => {
    await clearHeld(panel);
    await click();
    await panel.waitForFunction(({ f, s }) => location.hash.startsWith(`#/f/${f}?st=${encodeURIComponent(s)}`), { f: field, s: st }, { timeout: SECTION_WAIT });
    await panel.waitForSelector(".r-chip--verdict:not([data-tier=pending])", { timeout: SECTION_WAIT });
    const seen = await panel.evaluate(() => {
      const band = document.querySelector(".reach-verdict");
      return {
        tier: document.querySelector(".r-chip--verdict").dataset.tier,
        band: band ? band.dataset.tier : null,
        headline: band ? band.querySelector(".reach-verdict__text").textContent : "",
      };
    });
    assert.equal(seen.tier, tier, `the title chip: ${seen.tier}`);
    assert.equal(seen.band, tier, `the verdict band: ${seen.band}`);
    assert.match(seen.headline, headline, seen.headline);
    const held = await heldState(panel);
    assert.deepEqual(held.pins, [], "no pin from the click");
    assert.equal(held.pinned, null, "nothing pinned from the click");
  });
}

const IMPERSONATION = { field: "SigningId", tier: "impersonation", headline: /^Disagrees with the corpus: path \/System\/Library\/Frameworks\/Contacts\.framework\/Support\/contactsd belongs to Apple platform binary com\.apple\.contactsd in the corpus, event claims signing id com\.evil\.contactsd/ };
const LINUX = { field: "SHA256HashData", tier: "normal", headline: /^In the known-good corpus for ubuntu 22\.04$/ };

test("a Splunk click on the signing id of the row claiming Apple's contactsd path under another name lands the field page reading impersonation", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    const row = search.locator(".shared-eventsviewer-list-body-row", { hasText: "com.evil.contactsd" });
    await walkTier(t, panel, { ...IMPERSONATION, st: "crowdstrike:events:sensor", click: () => row.locator('.json-tree .f-v[data-field-name="SigningId"]').first().click() });
  } finally {
    await search.close();
    await panel.close();
  }
});

test("a blade right-click on the signing id of the row claiming Apple's contactsd path under another name lands the field page reading impersonation", async (t) => {
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    const row = blade.locator('.ag-root [role="row"]', { hasText: "com.evil.contactsd" });
    await walkTier(t, panel, { ...IMPERSONATION, st: "ReachCrowdStrike_CL", click: () => row.locator('[role="gridcell"]', { hasText: "com.evil.contactsd" }).click({ button: "right" }) });
  } finally {
    await blade.close();
    await panel.close();
  }
});

test("a Splunk click on the hash of the Ubuntu 22.04 curl row lands the field page reading normal from the bundled Linux corpus", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    const row = search.locator(".shared-eventsviewer-list-body-row", { hasText: "Ubuntu 22.04" });
    await walkTier(t, panel, { ...LINUX, st: "crowdstrike:events:sensor", click: () => row.locator('.json-tree .f-v[data-field-name="SHA256HashData"]').first().click() });
  } finally {
    await search.close();
    await panel.close();
  }
});

test("a blade right-click on the hash of the Ubuntu 22.04 curl row lands the field page reading normal from the bundled Linux corpus", async (t) => {
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    const row = blade.locator('.ag-root [role="row"]', { hasText: "Ubuntu 22.04" });
    await walkTier(t, panel, { ...LINUX, st: "ReachCrowdStrike_CL", click: () => row.locator('[role="gridcell"]', { hasText: "b1b4a0805c83790a" }).click({ button: "right" }) });
  } finally {
    await blade.close();
    await panel.close();
  }
});


const HANDLE_ROW = ".shared-eventsviewer-list-body-row:nth-of-type(6) .json-tree";
const bladeCell = (row, col) => `.ag-root [role="row"][aria-rowindex="${row}"] [role="gridcell"][aria-colindex="${col}"]`;

// The FDR bundle lists the handle-open event under its older name
// (FalconProcessHandleOpDetectInfo); the scope line still names the record
// type the click carried.
test("J2: the DesiredAccess key-name click on the handle-open event with the panel open lands the Splunk field page with the title block, the decode chip and Meaning on the first screen at 320 x 600", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    await shot(t, panel, async () => {
      await search.locator(`${HANDLE_ROW} .key-name[data-field-name="DesiredAccess"]`).click();
      await panel.waitForFunction(() => location.hash.startsWith("#/f/DesiredAccess?st=crowdstrike%3Aevents%3Asensor"), null, { timeout: SECTION_WAIT });
      await panel.waitForSelector(".r-title__chips .r-chip--decode:not([data-state=pending])", { timeout: SECTION_WAIT });
      const first = await panel.evaluate(firstScreen);
      assert.match(first.firstClass || "", /^r-title\b/);
      assert.ok(first.decodeChip);
      assert.ok(first.actions <= 600, `action row bottom ${first.actions}`);
      assert.ok(first.h2 && first.h2 <= 400, `first h2 top ${first.h2}`);
      const scope = await panel.$eval(".r-scope", (el) => el.textContent.trim());
      assert.match(scope, /^on crowdstrike:events:sensor · ProcessHandleOpDetectInfo\b/);
      assert.equal(await panel.$eval("main h2", (n) => n.textContent.trim()), "Meaning");
    });
  } finally {
    await search.close();
    await panel.close();
  }
});

test("J2 on Sentinel: the DesiredAccess column-header right-click with the panel open lands the column page scoped to the table", async (t) => {
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    await shot(t, panel, async () => {
      await blade.locator('[role="columnheader"][col-id="DesiredAccess"]').click({ button: "right" });
      await panel.waitForFunction(() => location.hash.startsWith("#/f/DesiredAccess?st=ReachCrowdStrike_CL"), null, { timeout: SECTION_WAIT });
      await panel.waitForSelector(".r-title__chips .r-chip--decode:not([data-state=pending])", { timeout: SECTION_WAIT });
      const first = await panel.evaluate(firstScreen);
      assert.match(first.firstClass || "", /^r-title\b/);
      assert.ok(first.actions <= 600, `action row bottom ${first.actions}`);
      assert.match(await panel.$eval(".r-scope", (el) => el.textContent.trim()), /on ReachCrowdStrike_CL/);
    });
  } finally {
    await blade.close();
    await panel.close();
  }
});

// J3: RawProcessId 936, then TargetProcessId 5497396, on the handle-open
// event. The PID caution is the first thing in the callout slot; the two
// clicks are one row, so the trail's tail chip reads 936 and then 5497396
// in place (a hop, not a click), and one back returns to the page the
// panel was on before the row.
// The three hops of scenario 3 on one row: RawProcessId, then
// ContextProcessId (the process that opened the handle), then
// TargetProcessId, each relabelling the row's one chip in place.
async function walkChain(t, panel, clickRaw, clickTarget, st, clickContext = null) {
  await shot(t, panel, async () => {
    await settlePlatform(panel, clickRaw, "RawProcessId");
    await clickRaw();
    await panel.waitForFunction((s) => location.hash.startsWith(`#/f/RawProcessId?st=${encodeURIComponent(s)}`), st, { timeout: SECTION_WAIT });
    await panel.waitForSelector(".r-title__held", { timeout: 5000 });
    const raw = await panel.evaluate(() => {
      const slot = document.querySelector(".r-title__callout");
      return { callout: slot ? slot.textContent.trim() : "", top: slot ? Math.round(slot.getBoundingClientRect().top) : null, held: document.querySelector(".r-title__held").textContent.trim(), scope: document.querySelector(".r-scope").textContent.trim() };
    });
    assert.match(raw.scope, new RegExp(`^on ${st} · ProcessHandleOpDetectInfo\\b`), `the scope line names the handle-open row: ${raw.scope}`);
    assert.match(raw.callout, /Not safe to join on|recycled|PID/, `the PID caution: ${raw.callout.slice(0, 80)}`);
    assert.ok(raw.top !== null && raw.top <= 400, `the caution is in the first viewport (${raw.top})`);
    assert.match(raw.held, /^value 936\b/);
    const rawChips = await panel.evaluate(trailRead);
    assert.equal(rawChips.tail.text, "936");
    if (clickContext) {
      await clickContext();
      await panel.waitForFunction((s) => location.hash.startsWith(`#/f/ContextProcessId?st=${encodeURIComponent(s)}`) && /[?&]value=255667414\b/.test(location.hash), st, { timeout: SECTION_WAIT });
      await panel.waitForSelector(".r-title__held", { timeout: 5000 });
      const context = { ...(await panel.evaluate(trailRead)), held: await panel.$eval(".r-title__held", (el) => el.textContent.trim()) };
      assert.match(context.held, /^value 255667414\b/, "the second hop lands the handle's context process id");
      assert.equal(context.hops, rawChips.hops, `the same row, the same stack entry: ${context.chips.join(" › ")}`);
      assert.equal(context.tail.text, "255667414");
    }
    await clickTarget();
    await panel.waitForFunction((s) => location.hash.startsWith(`#/f/TargetProcessId?st=${encodeURIComponent(s)}`), st, { timeout: SECTION_WAIT });
    await panel.waitForSelector(".r-title__held", { timeout: 5000 });
    const target = { ...(await panel.evaluate(trailRead)), ...(await panel.evaluate(() => ({ held: document.querySelector(".r-title__held").textContent.trim(), scope: document.querySelector(".r-scope").textContent.trim() }))) };
    assert.match(target.scope, new RegExp(`^on ${st} · ProcessHandleOpDetectInfo\\b`), `the scope line names the handle-open row: ${target.scope}`);
    // One row, one stack entry: the Target click relabels it in place
    // rather than pushing a new one (the mirror's depth is unchanged),
    // whatever the visible trail shows for any hop it left stranded
    // earlier in this same walk (settlePlatform's throwaway click, an
    // entity hop of its own now that tool pages draw no chip).
    assert.equal(target.hops, rawChips.hops, `one row, one stack entry: ${target.chips.join(" › ")}`);
    assert.equal(target.tail.text, "5497396", "the tail chip took the value in place");
    assert.equal(target.tail.title, `TargetProcessId=5497396 on ${st} · ProcessHandleOpDetectInfo`);
    assert.match(target.held, /^value 5497396\b/);
    // settlePlatform put the start page (a tool page, no chip of its own)
    // between the panel's landing and this row: that is Back's target, not
    // read from the trail (the row's own chip may be the only one drawn).
    const from = "#/";
    await panel.click(".r-navctl__btn[aria-label=Back]");
    await panel.waitForFunction((h) => location.hash === h, from, { timeout: 5000 });
    assert.equal(await panel.$eval(".r-navctl__btn[aria-label=Forward]", (b) => b.disabled), false, "the row is one step forward");
    await panel.click(".r-navctl__btn[aria-label=Forward]");
    await panel.waitForFunction(() => location.hash.startsWith("#/f/TargetProcessId"), null, { timeout: 5000 });
    await panel.waitForSelector(".r-title__held", { timeout: 5000 });
    assert.match(await panel.$eval(".r-title__held", (el) => el.textContent.trim()), /^value 5497396\b/, "forward returns to the row as it was last left");
  });
}

// The worker replays the window's last click to a panel on hello, and a
// click from the other platform replaces the document: one click first,
// then the start page (a tool page, no chip of its own), so the walk runs
// in one document with a page before the row to go back to.
async function settlePlatform(panel, click, field) {
  await click();
  await panel.waitForFunction((f) => location.hash.startsWith(`#/f/${f}?`) && document.querySelector(".r-trail__chip--here"), field, { timeout: SECTION_WAIT });
  await panel.evaluate(() => { location.hash = "#/"; });
  await panel.waitForFunction(() => location.hash === "#/" && document.querySelector(".r-view--start"), null, { timeout: 5000 });
}

// The trail as drawn (the last three hops), the tail chip's text and title,
// and the count of hops up to the current one from the mirror (reach.trail).
function trailRead() {
  const chips = [...document.querySelectorAll(".r-trail__chip")].map((n) => n.textContent.trim());
  const tail = document.querySelector(".r-trail__chip--here");
  let hops = 0;
  try {
    hops = JSON.parse(sessionStorage.getItem("reach.trail")).pos + 1;
  } catch {
    hops = 0;
  }
  return { chips, hops, tail: { text: tail ? tail.textContent.trim() : "", title: tail ? tail.title : "" } };
}

test("J3: RawProcessId 936, ContextProcessId 255667414, then TargetProcessId 5497396 on the Splunk handle-open event: the PID caution, one chip relabelled in place, back to the page before the row", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    // Splunk's own menu from the first click sits over the next leaf: a
    // click outside closes it first, as the analyst's would.
    const leafClick = async (name) => {
      await search.mouse.click(4, 4);
      await search.locator(`${HANDLE_ROW} .f-v[data-field-name="${name}"]`).click();
    };
    await walkChain(t, panel, () => leafClick("RawProcessId"), () => leafClick("TargetProcessId"), "crowdstrike:events:sensor", () => leafClick("ContextProcessId"));
  } finally {
    await search.close();
    await panel.close();
  }
});

test("J3 on Sentinel: RawProcessId 936, ContextProcessId 255667414, then TargetProcessId 5497396 on the blade's handle-open row: the PID caution, one chip relabelled in place, back to the page before the row", async (t) => {
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    await walkChain(t, panel, () => blade.locator(bladeCell(6, 11)).click({ button: "right" }), () => blade.locator(bladeCell(6, 7)).click({ button: "right" }), "ReachCrowdStrike_CL", () => blade.locator(bladeCell(6, 13)).click({ button: "right" }));
  } finally {
    await blade.close();
    await panel.close();
  }
});

// The trail records hops, not clicks: fields clicked in one row update the
// tail chip in place, a click in another row adds a chip, and a pivot run
// from the drawer makes the click in its results a new hop.
async function walkHops(t, panel, { clicks, otherRow, st, type }) {
  await shot(t, panel, async () => {
    await settlePlatform(panel, () => clicks.click(clicks[0][0]), clicks[0][0]);
    let rowChips = null;
    for (const [field, value] of clicks) {
      await clicks.click(field);
      const title = `${field}=${value} on ${st} · ${type}`;
      await panel.waitForFunction((want) => (document.querySelector(".r-trail__chip--here") || {}).title === want, title, { timeout: SECTION_WAIT });
      const seen = await panel.evaluate(trailRead);
      if (rowChips === null) rowChips = seen.hops;
      assert.equal(seen.hops, rowChips, `${field}: one chip for the row (${seen.chips.join(" › ")})`);
      assert.ok(seen.tail.text.includes(value.slice(-4)), `${field}: the chip shows the value (${seen.tail.text})`);
    }
    await otherRow.click();
    const title = `${otherRow.field}=${otherRow.value} on ${st} · ${otherRow.type}`;
    await panel.waitForFunction((want) => (document.querySelector(".r-trail__chip--here") || {}).title === want, title, { timeout: SECTION_WAIT });
    const other = await panel.evaluate(trailRead);
    assert.equal(other.hops, rowChips + 1, `another row is another chip (${other.chips.join(" › ")})`);
  });
}

test("hops, not clicks: three fields on the Splunk J1 row are one chip whose value follows the click, the handle-open row is a second chip, and the click in a pivot run's results is a third", async (t) => {
  const panel = await panelFor("splunk");
  const search = await h.splunkPage();
  try {
    const ROW = ".shared-eventsviewer-list-body-row:nth-of-type(4) .json-tree";
    const leaf = async (name) => {
      await search.mouse.click(4, 4);
      await search.locator(`${ROW} .f-v[data-field-name="${name}"]`).first().click();
    };
    const clicks = [["SHA256HashData", "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9"], ["ImageFileName", "/System/Library/Frameworks/Contacts.framework/Support/contactsd"], ["aid", "0123456789abcdef0123456789abcdef"]];
    clicks.click = leaf;
    await walkHops(t, panel, { clicks, st: "crowdstrike:events:sensor", type: "ProcessRollup2", otherRow: { field: "RawProcessId", value: "936", type: "ProcessHandleOpDetectInfo", click: async () => { await search.mouse.click(4, 4); await search.locator(`${HANDLE_ROW} .f-v[data-field-name="RawProcessId"]`).click(); } } });
    // A key click on the same row is that row too (field-info-popup.js
    // sends where the click was).
    await search.mouse.click(4, 4);
    const rowHops = (await panel.evaluate(trailRead)).hops;
    await search.locator(`${HANDLE_ROW} .key-name[data-field-name="DesiredAccess"]`).click();
    await panel.waitForFunction(() => location.hash.startsWith("#/f/DesiredAccess?") && (document.querySelector(".r-trail__chip--here") || {}).dataset.kind === "field", null, { timeout: SECTION_WAIT });
    const keyed = await panel.evaluate(trailRead);
    assert.equal(keyed.hops, rowHops, "a key click names the field on the same chip");
    // The panel is 320 wide: a chip middle-ellipsizes at nine characters under 360 px.
    assert.equal(keyed.tail.text, "Desi…cess", "the chip reads the field, no value");
    // A pivot run: the drawer's run link opens the pivot's search (the
    // fixture answers any search on the origin), and the click in its
    // results is a new hop even on the same event.
    await shot(t, panel, async () => {
      await panel.evaluate((base) => localStorage.setItem("reach.splunkBase", base), "https://splunk.fixture.test/en-US");
      await search.mouse.click(4, 4);
      await search.locator(`${HANDLE_ROW} .f-v[data-field-name="aid"]`).click();
      await panel.waitForFunction(() => location.hash.startsWith("#/f/aid?"), null, { timeout: SECTION_WAIT });
      const before = await panel.evaluate(trailRead);
      await panel.waitForSelector(".r-packpivots tr[data-row-id]", { timeout: SECTION_WAIT });
      await panel.click(".r-packpivots tr[data-row-id]");
      await panel.waitForFunction(() => !document.querySelector(".r-drawer__run").hidden, null, { timeout: 5000 });
      const [results] = await Promise.all([h.context.waitForEvent("page"), panel.click(".r-drawer__run")]);
      await results.waitForSelector('.json-tree .f-v[data-reach-tagged]', { timeout: SECTION_WAIT });
      await results.locator(`${HANDLE_ROW} .f-v[data-field-name="RawProcessId"]`).click();
      await panel.waitForFunction((n) => JSON.parse(sessionStorage.getItem("reach.trail")).pos + 1 === n, before.hops + 1, { timeout: SECTION_WAIT });
      const after = await panel.evaluate(trailRead);
      assert.equal(after.tail.title, "RawProcessId=936 on crowdstrike:events:sensor · ProcessHandleOpDetectInfo");
      await results.close();
    });
  } finally {
    await search.close();
    await panel.close();
  }
});

test("hops, not clicks on Sentinel: three cells on the blade's J1 row are one chip whose value follows the click, and the handle-open row is a second chip", async (t) => {
  // The run link opens the portal itself, which the harness does not
  // answer: the pivot leg is Splunk's.
  const panel = await panelFor("sentinel");
  const blade = await h.bladePage();
  try {
    const cols = { SHA256HashData: 6, ImageFileName: 5, Aid: 4 };
    // The blade's menu closes on the next mousedown anywhere outside it,
    // as Splunk's popup does; the click outside first is the analyst's
    // own gesture (the Splunk leg makes the same one), and it keeps the
    // open menu from sitting over the next cell when the grid scrolls it
    // into view.
    const rightClick = async (row, col) => {
      await blade.mouse.click(4, 4);
      await blade.locator(bladeCell(row, col)).click({ button: "right" });
    };
    const clicks = [["SHA256HashData", "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9"], ["ImageFileName", "/System/Library/Frameworks/Contacts.framework/Support/contactsd"], ["Aid", "0123456789abcdef0123456789abcdef"]];
    clicks.click = (name) => rightClick(5, cols[name]);
    await walkHops(t, panel, { clicks, st: "ReachCrowdStrike_CL", type: "ProcessRollup2", otherRow: { field: "RawProcessId", value: "936", type: "ProcessHandleOpDetectInfo", click: () => rightClick(6, 11) } });
  } finally {
    await blade.close();
    await panel.close();
  }
});

// The trail's entity filter, driven at panel width on the served extension
// page (not a SIEM click): a value page is a chip, Share and Notebook off
// the nav are tool pages and add none, and Back twice from Notebook lands
// on the value page again.
test("a value's trail chip survives Share and Notebook, and Back twice from Notebook returns to the value page", async (t) => {
  await h.setStorage({ "reach.modules": { enabled: { share: true } } });
  await shot(t, page, async () => {
    await go(`#/v/${HASH}?st=${ST}&name=SHA256HashData`);
    await page.waitForFunction(() => document.querySelector(".r-trail__chip--here"), { timeout: 5000 });
    // The storage write above lands through chrome.storage.onChanged, live
    // but not instant: wait for the nav to draw Share before opening it.
    await page.waitForFunction(() => [...document.querySelectorAll(".r-nav a")].some((a) => a.textContent.trim() === "Share"), { timeout: 5000 });
    const valueHash = await page.evaluate(() => location.hash);
    // The page is reused across this file's earlier tests, which can leave
    // older entity hops on the trail: compare against this value's own
    // landing, not an assumed count of exactly one.
    const before = await page.evaluate(() => [...document.querySelectorAll(".r-trail__chip")].map((c) => c.textContent.trim()));

    await page.evaluate(() => { location.hash = "#/share"; });
    await page.waitForSelector(".r-view--share", { timeout: 5000 });
    const share = await page.evaluate(() => ({
      chips: [...document.querySelectorAll(".r-trail__chip")].map((c) => c.textContent.trim()),
      here: document.querySelectorAll(".r-trail__chip--here").length,
    }));
    assert.deepEqual(share.chips, before, `Share adds no chip of its own: ${share.chips.join(" › ")}`);
    assert.equal(share.here, 0, "the panel is not on the value page any more, so nothing reads as current");

    await page.evaluate(() => { location.hash = "#/notebook"; });
    await page.waitForSelector(".r-view--notebook", { timeout: 5000 });
    const notebook = await page.evaluate(() => [...document.querySelectorAll(".r-trail__chip")].map((c) => c.textContent.trim()));
    assert.deepEqual(notebook, before, `Notebook adds no chip either, still the same hops: ${notebook.join(" › ")}`);

    await page.click(".r-navctl__btn[aria-label=Back]");
    await page.waitForFunction(() => location.hash.startsWith("#/share"), { timeout: 5000 });
    await page.click(".r-navctl__btn[aria-label=Back]");
    await page.waitForFunction((h) => location.hash === h, valueHash, { timeout: 5000 });
    assert.ok(await page.evaluate(() => document.querySelector(".r-trail__chip--here")), "back twice from Notebook lands on the value page, marked current again");
  });
  await h.setStorage({ "reach.modules": { enabled: {} } });
});
