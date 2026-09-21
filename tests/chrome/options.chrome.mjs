// The options page as the extension serves it: it draws the module list
// for the platform its URL names, the same membership the panel's Settings
// fold draws there, and a setup link's hash lands on that module's head.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot } from "./harness.mjs";

let h;
let page;

before(async () => {
  h = await launch({ viewport: { width: 380, height: 900 } });
  page = await h.extensionPage("options.html?platform=splunk");
  await page.waitForSelector(".r-module", { timeout: 5000 });
});
after(async () => {
  if (h) await h.close();
});

async function heads(p) {
  return page.evaluate(async (p) => {
    location.href = `options.html?platform=${p}`;
    await new Promise((r) => setTimeout(r, 50));
    return null;
  }, p).catch(() => null).then(async () => {
    await page.waitForSelector(".r-module", { timeout: 5000 });
    await page.waitForTimeout(150);
    return page.evaluate(() => [...document.querySelectorAll(".r-module")].map((m) => m.dataset.module));
  });
}

async function expected(p) {
  return page.evaluate((p) => import(chrome.runtime.getURL("app/lib/modules.js")).then((m) => m.MODULES.filter((x) => x.platforms.includes(p)).map((x) => x.id)), p);
}

test("options.html draws the platform's own module list on each platform, the fold's membership", async (t) => {
  await shot(t, page, async () => {
    for (const p of ["sentinel", "splunk"]) {
      const ids = await heads(p);
      assert.deepEqual(ids, await expected(p), `${p}: the platform's modules, in registry order`);
      assert.match(await page.locator("#platform").textContent(), p === "sentinel" ? /^The modules for Microsoft Sentinel\./ : /^The modules for Splunk\./);
    }
    const sentinel = await heads("sentinel");
    assert.ok(sentinel.includes("workflows"), "pack workflows mount on Sentinel, so the module lists there");
    assert.equal(await page.locator(".r-module__tier", { hasText: /only$/ }).count(), 0, "no module is tagged one platform's on a platform's own list");
  });
});

test("a setup link's hash lands the page scrolled to that module's head", async (t) => {
  await shot(t, page, async () => {
    await page.goto(h.url("options.html?platform=splunk#module-selfhosted"));
    await page.waitForSelector("#module-selfhosted", { timeout: 5000 });
    await page.waitForTimeout(200);
    const r = await page.evaluate(() => {
      const el = document.getElementById("module-selfhosted");
      const b = el.getBoundingClientRect();
      return { top: Math.round(b.top), bottom: Math.round(b.bottom), ih: innerHeight, atEnd: Math.ceil(scrollY + innerHeight) >= document.documentElement.scrollHeight, scrollY: Math.round(scrollY) };
    });
    assert.ok(r.scrollY > 0, "the page scrolled to the head");
    assert.ok(r.top >= 0 && r.bottom <= r.ih, `the whole head is in view: ${JSON.stringify(r)}`);
    assert.ok(r.top < 60 || r.atEnd, `the head sits at the top unless the page ends first: ${JSON.stringify(r)}`);
  });
});
