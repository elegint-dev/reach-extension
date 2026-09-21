// The Splunk search page, in Chrome with the real extension: the content
// scripts attach to the fixture, a value click opens Splunk's own popup
// with the REACH section in it, Hold lands in the notebook store, Insert
// lands in the search bar.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, openValuePopup, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let page;
const POPUP = ".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown";
const leaf = (name, row = 1) => `.shared-eventsviewer-list-body-row:nth-of-type(${row}) .json-tree .f-v[data-field-name="${name}"]`;

before(async () => {
  h = await launch();
  page = await h.splunkPage();
});
after(async () => {
  if (h) await h.close();
});

async function closePopup() {
  await page.mouse.click(4, 4);
  await page.locator(POPUP).waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
}

test("the content scripts attach to the fixture: every JSON leaf is a clickable .f-v with its path as the field name", async (t) => {
  await shot(t, page, async () => {
    const leaves = await page.evaluate(() => Array.from(document.querySelectorAll(".json-tree [data-path]")).filter((el) => el.classList.contains("t")));
    const tagged = await page.evaluate(() => Array.from(document.querySelectorAll(".json-tree .t[data-path]")).filter((el) => el.classList.contains("f-v") && el.dataset.fieldName === el.dataset.path).length);
    assert.ok(tagged > 100, `tagged ${tagged}`);
    assert.equal(tagged, leaves.length);
    const keys = await page.evaluate(() => document.querySelectorAll(".json-tree .key-name[data-reach-key][data-field-name]").length);
    assert.equal(keys, tagged, "every key name carries the same field name for the field-info popup");
  });
});

test("the History button mounts beside Splunk's own mode select in the search bar's left container, wearing that control's classes", async (t) => {
  await shot(t, page, async () => {
    const btn = page.locator("#reach-history-btn");
    await btn.waitFor({ timeout: 5000 });
    const got = await page.evaluate(() => {
      const b = document.getElementById("reach-history-btn");
      const model = document.querySelector('.left-container [data-id="spl-mode-select"]');
      const anchor = model.closest(".search-mode-container");
      return { text: b.textContent, className: b.className, modelClass: model.className, after: anchor.nextElementSibling === b, inLeft: Boolean(b.closest(".left-container")), label: b.getAttribute("aria-label"), panels: document.querySelectorAll(".reach-history-panel").length };
    });
    assert.equal(got.text, "History");
    assert.equal(got.className, got.modelClass, "the button clones the mode select's classes");
    assert.ok(got.after && got.inLeft, "the button follows the mode select's container");
    assert.equal(got.label, "Search history");
    assert.equal(got.panels, 0, "no dropdown and no request until a click");
  });
});

test("a value click opens Splunk's popup and the REACH section in it is scoped to the row's sourcetype and record type", async (t) => {
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("IntegrityLevel"));
    assert.equal(await section.locator(".reach-scope").textContent(), "on crowdstrike:events:sensor · ProcessRollup2");
    assert.equal(await section.locator(".reach-badge").textContent(), "REACH");
    assert.equal(await page.locator(POPUP + " li a.curr_inc_val").count(), 1, "Splunk's own items stay above the section");
    await closePopup();
  });
});

test("the value row reads the pack's decode for the clicked literal", async (t) => {
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("IntegrityLevel"));
    const row = section.locator(".reach-value");
    assert.match(await row.locator(".reach-value__body").textContent(), /^12288: .*High \(elevated\)/);
    await closePopup();
  });
});

test("the pattern band is absent while its module is off, the default", async (t) => {
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    assert.equal(await section.locator(".reach-pattern").count(), 0);
    assert.equal(await section.locator('[data-band="pattern"]').count(), 0);
    await closePopup();
  });
});

test("the pattern block renders the exact form of the clicked value as SPL with Insert and Replace offered", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { pattern: true } } });
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    const pattern = section.locator(".reach-pattern");
    assert.equal(await pattern.locator(".reach-pattern__code").textContent(), 'SHA256HashData="ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436"');
    assert.deepEqual(await pattern.locator(".reach-pattern__actions button").allTextContents(), ["Insert", "Replace term", "Copy SPL"]);
    await closePopup();
  });
});

test("the enrich band draws no VirusTotal row while its module is off, and nothing is fetched", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: {} } });
    const requests = [];
    const seen = (req) => { if (/virustotal/i.test(req.url())) requests.push(req.url()); };
    page.on("request", seen);
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    assert.equal(await section.locator(".reach-enrich .reach-enrich__row", { hasText: "VirusTotal" }).count(), 0, "an off module's row is absent, not greyed");
    page.off("request", seen);
    assert.deepEqual(requests, []);
    await closePopup();
  });
});

test("with its module on and no key, the VirusTotal row says not configured and links its settings head, with nothing fetched", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { virustotal: true } } });
    const requests = [];
    const seen = (req) => { if (/virustotal/i.test(req.url())) requests.push(req.url()); };
    page.on("request", seen);
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    const row = section.locator(".reach-enrich .reach-enrich__row", { hasText: "VirusTotal" });
    assert.equal(await row.locator(".reach-enrich__label").textContent(), "VirusTotal");
    assert.match(await row.textContent(), /VirusTotal: not configured/);
    const setup = row.locator(".reach-enrich__setup");
    assert.equal(await setup.textContent(), "Set it up →");
    assert.match(await setup.getAttribute("href"), /options\.html\?platform=splunk#module-virustotal$/);
    page.off("request", seen);
    assert.deepEqual(requests, []);
    await closePopup();
    await h.setStorage({ "reach.modules": { enabled: {} } });
  });
});

test("an on-but-unconfigured relay's Set it up link is visible without opening any fold, one click from the popup", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { selfhosted: true } } });
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    const row = section.locator(".reach-enrich .reach-enrich__row", { hasText: "Self-hosted" });
    assert.match(await row.textContent(), /Self-hosted \(MISP \/ IntelOwl\): not configured/);
    const setup = row.locator(".reach-enrich__setup");
    assert.equal(await setup.isVisible(), true, "the link is on screen with every fold still shut");
    assert.equal(await setup.locator("xpath=ancestor::details").count(), 0, "not inside the more-sources fold");
    assert.equal(await section.locator(".reach-fold[open]").count(), 0, "no fold was opened to reach it");
    assert.match(await setup.getAttribute("href"), /options\.html\?platform=splunk#module-selfhosted$/);
    await closePopup();
    await h.setStorage({ "reach.modules": { enabled: {} } });
  });
});

test("the known-good verdict renders on a mac image path and settles on a tier from the bundled corpus", async (t) => {
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("ImageFileName", 4));
    const verdict = section.locator(".reach-verdict");
    await verdict.waitFor();
    await page.waitForFunction(() => { const v = document.querySelector(".reach-verdict"); return v && v.dataset.tier !== "pending"; }, null, { timeout: SECTION_WAIT });
    const tier = await verdict.getAttribute("data-tier");
    assert.equal(tier, "normal");
    assert.match(await verdict.locator(".reach-verdict__text").textContent(), /contactsd/);
    await closePopup();
  });
});

test("Hold records a notebook entry in chrome.storage with the row's provenance and the search read off the bar", async (t) => {
  await shot(t, page, async () => {
    const section = await openValuePopup(page, leaf("TargetProcessId"));
    const hold = section.locator(".reach-hold").first();
    await hold.locator(".reach-hold__reason").fill("the dumper's process");
    await hold.locator(".reach-hold__btn").click();
    await hold.locator(".reach-hold__btn", { hasText: "Held" }).waitFor({ timeout: 5000 });
    const store = await h.storage();
    const doc = store["reach.notebook"];
    assert.ok(doc && doc.investigations.length, "reach.notebook holds an investigation");
    const entry = doc.investigations.flatMap((i) => i.entries).find((e) => e.field === "TargetProcessId");
    assert.ok(entry, "the pin is there");
    assert.equal(entry.value, "332855234");
    assert.equal(entry.reason, "the dumper's process");
    assert.equal(entry.from.container, "crowdstrike:events:sensor");
    assert.equal(entry.from.platform, "splunk");
    assert.equal(entry.from.scope, "main");
    assert.match(entry.from.search.text, /event_simpleName=ProcessRollup2/);
    await closePopup();
  });
});

test("Insert from the pattern block writes the term into the search bar through the editor bridge", async (t) => {
  await shot(t, page, async () => {
    await h.setStorage({ "reach.modules": { enabled: { pattern: true } } });
    const before = await page.evaluate(() => window.__fixtureEditor.getValue());
    const section = await openValuePopup(page, leaf("RawProcessId"));
    // The pattern builder is a closed secondary band; open it by its registry title.
    await section.locator('[data-band="pattern"] > summary', { hasText: "Pattern" }).click();
    await section.locator(".reach-pattern__actions button", { hasText: "Insert" }).click();
    await section.locator(".reach-pattern__notice", { hasText: "Added to the search" }).waitFor({ timeout: 5000 });
    const after = await page.evaluate(() => window.__fixtureEditor.getValue());
    assert.equal(after, `${before} RawProcessId="4036"`);
    assert.match(await page.locator(".search-bar-input .ace_line").first().textContent(), /RawProcessId="4036"$/);
    await closePopup();
  });
});

test("with the side panel open, a value click becomes a hop on the trail and pins nothing in the notebook or the pinned store", async (t) => {
  await shot(t, page, async () => {
    await h.clearStorage();
    // No automation can drive the native side panel surface; app.js decides
    // it is the panel by chrome.tabs.getCurrent() resolving to no tab
    // (followPanel, app.js), so a plain extension tab with that one call
    // spoofed exercises the same branch a real panel does.
    const panel = await h.context.newPage();
    await panel.addInitScript(() => {
      chrome.tabs.getCurrent = () => Promise.resolve(undefined);
    });
    await panel.goto(h.url("index.html?platform=splunk#/"));
    await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });

    await page.locator(leaf("SHA256HashData")).first().click();
    // The panel took the click: Splunk's own popup shows the one-line
    // handoff, never the full REACH section.
    await page.locator(`${POPUP} .reach-section--panelline`).waitFor({ timeout: 5000 });
    assert.equal(await page.locator(`${POPUP} .reach-section.reach-value`).count(), 0);
    await panel.waitForFunction(() => location.hash.startsWith("#/f/"), { timeout: 5000 });

    const doc = await h.storage().then((d) => d["reach.notebook"]);
    const pins = doc ? doc.investigations.flatMap((i) => i.entries).filter((e) => e.kind === "pin").length : 0;
    assert.equal(pins, 0, "no pin in the notebook from a click the panel took");

    const pinnedStore = await panel.evaluate(() => localStorage.getItem("reach.pinned"));
    assert.equal(pinnedStore, null, "nothing auto-pinned into the cross-session store either");

    // A click holds nothing: the tab's held facts (investigation.js) stay
    // empty too. The value rides in the route and is drawn as the trail's
    // tail chip, never inside Holding.
    const tabFacts = await panel.evaluate(() => JSON.parse(sessionStorage.getItem("reach.investigation") || "{}"));
    assert.deepEqual(tabFacts, {}, "no held fact from a click");
    assert.match(await panel.evaluate(() => location.hash), /[?&]value=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436(&|$)/, "the route carries the value");
    const tail = await panel.$eval(".r-trail__chip--here", (c) => ({ text: c.textContent, title: c.title }));
    assert.match(tail.title, /^SHA256HashData=ba4038fd/);
    assert.equal(await panel.$$eval(".r-holding__chip", (els) => els.length), 0, "nothing listed under Holding from a click");
    assert.equal(await panel.$eval(".r-holding", (el) => el.classList.contains("r-holding--empty")), true);

    await panel.close();
    await page.mouse.click(4, 4);
    await page.locator(POPUP).waitFor({ state: "detached", timeout: 2000 }).catch(() => {});
  });
});
