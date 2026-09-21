// The workflow and runbook pages in the side panel as the extension serves
// them: the title block first with the scope line and the action row on
// the first screen at 320 x 600 with two values held, the trail above it,
// and nothing past the edge at 380 with every fold open (C1, C7). The FDR
// workflows are Splunk's, the pack hunt and the runbook page are one view
// on both.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, SECTION_WAIT } from "./harness.mjs";

let h;
const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
const HELD = { aid: "abc123def4567890abc123def4567890", SHA256HashData: HASH };
const RUNBOOK_SPLUNK = "#/runbook/escu%3Aname%3Adisabled%20kerberos%20preauthentication%20discovery%20with%20getaduser?rule=Disabled%20Kerberos%20Pre-Authentication%20Discovery%20With%20Get-ADUser&st=stash&dest=WIN-DC01&user=jdoe&src=10.1.2.3&aid=f0778584e83c4efc9cf026bc1e7f0489";
const RUNBOOK_SENTINEL = "#/runbook/sentinel-rules%3Aname%3Agitlab%20bruteforce%20attempts?rule=GitLab%20-%20Brute-force%20Attempts&st=SecurityAlert&CompromisedEntity=10.1.2.3&Entities=%5B%7B%22%24id%22%3A%222%22%2C%22Address%22%3A%2210.1.2.3%22%2C%22Type%22%3A%22ip%22%7D%2C%7B%22%24id%22%3A%223%22%2C%22Name%22%3A%22jdoe%22%2C%22Type%22%3A%22account%22%7D%5D";
const HUNT = "#/w/hunt_mac_signing";
const ROUTES = {
  splunk: [`#/w/ioc?value=${HASH}`, "#/w/pid", HUNT, RUNBOOK_SPLUNK],
  sentinel: [HUNT, RUNBOOK_SENTINEL],
};

before(async () => {
  h = await launch({ viewport: { width: 380, height: 600 } });
});
after(async () => {
  if (h) await h.close();
});

// A runbook page reads the bundle before it draws its seeded block; the
// placeholder's chip says so until then.
async function settle(page, route) {
  await page.waitForTimeout(400);
  if (route.startsWith("#/runbook/")) await page.waitForFunction(() => !/reading the bundle/.test(document.querySelector(".r-title__chips")?.textContent || ""), null, { timeout: SECTION_WAIT });
}

function firstScreen() {
  const main = document.querySelector("main");
  const view = main.firstElementChild;
  const title = view && view.firstElementChild;
  const bottom = (s) => { const el = document.querySelector(s); return el ? Math.round(el.getBoundingClientRect().bottom) : null; };
  return {
    firstClass: title ? title.className : null,
    titles: document.querySelectorAll(".r-title").length,
    h1: bottom("h1"),
    scope: bottom(".r-scope"),
    actions: bottom(".r-actions"),
    actionLabels: [...document.querySelectorAll(".r-actions > *")].map((n) => n.textContent.trim()),
    trail: Boolean(document.querySelector(".r-trail")),
    frameTitle: (document.querySelector(".r-frame__title") || {}).textContent || "",
    oldHead: Boolean(document.querySelector(".r-hold__head")),
  };
}

function overflow() {
  const d = document;
  d.querySelectorAll("details").forEach((x) => (x.open = true));
  d.querySelectorAll(".r-settings").forEach((x) => (x.open = true));
  const cw = d.documentElement.clientWidth;
  const hits = [];
  for (const el of d.querySelectorAll("body *")) {
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height || r.right <= 0) continue;
    if (r.right > cw + 1 || r.left < -1) {
      if (hits.some((x) => x.el.contains(el))) continue;
      hits.push({ el, text: `${el.tagName.toLowerCase()}.${Array.from(el.classList).slice(0, 2).join(".")} +${Math.round(r.right - cw)}px` });
    }
  }
  return { page: d.scrollingElement.scrollWidth - cw, hits: hits.map((x) => x.text) };
}

test("at 320 x 600 with two values held, the workflow and runbook pages draw the title block first with the scope line and the action row inside the viewport, under the trail", async (t) => {
  for (const [platform, routes] of Object.entries(ROUTES)) {
    const page = await h.extensionPage(`index.html?platform=${platform}#/`, { viewport: { width: 320, height: 600 } });
    try {
      await shot(t, page, async () => {
        await page.waitForSelector("main", { timeout: 5000 });
        await page.evaluate((held) => localStorage.setItem("reach.pinned", JSON.stringify(held)), HELD);
        await page.reload();
        await page.waitForSelector(".r-holding", { timeout: 5000 });
        for (const route of routes) {
          await page.evaluate((r) => { location.hash = r; }, route);
          await settle(page, route);
          const first = await page.evaluate(firstScreen);
          assert.match(first.firstClass || "", /^r-title\b/, `${platform} ${route}: the title block is the view's first child`);
          assert.equal(first.titles, 1, `${platform} ${route}: one title block`);
          assert.equal(first.oldHead, false, `${platform} ${route}: no bare page head`);
          assert.ok(first.trail, `${platform} ${route}: the trail`);
          assert.ok(first.h1 && first.h1 <= 600, `${platform} ${route}: h1 bottom ${first.h1}`);
          assert.ok(first.scope && first.scope <= 600, `${platform} ${route}: scope line bottom ${first.scope}`);
          assert.ok(first.actions && first.actions <= 600, `${platform} ${route}: action row bottom ${first.actions}`);
          if (route.startsWith("#/w/")) assert.deepEqual(first.actionLabels.slice(0, 2), ["Run", platform === "sentinel" ? "Copy KQL" : "Copy SPL"], `${platform} ${route}`);
          else assert.deepEqual(first.actionLabels.slice(0, 3), ["Hold", "Mark benign", platform === "sentinel" ? "Copy KQL" : "Run"], `${platform} ${route}: ${first.actionLabels}`);
          await page.evaluate(() => window.scrollTo(0, 2000));
          await page.waitForTimeout(100);
          // The compact title on these routes is the workflow's id or the route's name, not the h1's form.
          const compact = await page.$eval(".r-frame__title", (el) => ({ text: el.textContent.trim(), bottom: Math.round(el.getBoundingClientRect().bottom) }));
          assert.ok(compact.bottom <= 44, `${platform} ${route}: compact title "${compact.text}" at ${compact.bottom} after a scroll`);
          await page.evaluate(() => window.scrollTo(0, 0));
        }
      });
    } finally {
      await page.close();
    }
  }
});

test("at 380 with every fold open, neither page pushes past the panel's edge", async (t) => {
  for (const [platform, routes] of Object.entries(ROUTES)) {
    const page = await h.extensionPage(`index.html?platform=${platform}#/`);
    try {
      await shot(t, page, async () => {
        await page.waitForSelector("main", { timeout: 5000 });
        const failures = [];
        for (const route of routes) {
          await page.evaluate((r) => { location.hash = r; }, route);
          await settle(page, route);
          const r = await page.evaluate(overflow);
          if (r.page > 0) failures.push(`${platform} ${route}: page +${r.page}px`);
          for (const hit of r.hits) failures.push(`${platform} ${route}: ${hit}`);
        }
        assert.deepEqual(failures, []);
      });
    } finally {
      await page.close();
    }
  }
});
