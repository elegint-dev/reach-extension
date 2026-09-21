// The side panel page (index.html, the manifest's side_panel) as the
// extension serves it, at the panel's width: it renders on the chrome
// storage backend and no route pushes the page past the panel's edge.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shot, SECTION_WAIT } from "./harness.mjs";

let h;
let page;
const WIDTH = 380;
const ROUTES = ["#/", "#/catalogue", "#/discover", "#/packs", "#/notebook", "#/st/crowdstrike:events:sensor", "#/f/ImageFileName?on=crowdstrike:events:sensor", "#/f/SHA256HashData?st=crowdstrike:events:sensor&on=ProcessRollup2&value=8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4", "#/v/198.51.100.7", "#/v/CVE-2025-39964", "#/w/ioc?value=198.51.100.7", "#/w/pid"];

before(async () => {
  h = await launch({ viewport: { width: WIDTH, height: 900 } });
  page = await h.extensionPage("index.html?platform=splunk#/");
  await page.waitForSelector("nav, .r-nav, main", { timeout: 5000 });
});
after(async () => {
  if (h) await h.close();
});

// The panel-validator sweep, in one page: details and settings open, then
// page overflow and any element past the edge. `p` defaults to the shared
// 380 px page; a caller checking another width passes its own.
async function sweep(route, p = page) {
  await p.evaluate((r) => { location.hash = r; }, route);
  await p.waitForTimeout(250);
  return p.evaluate(() => {
    const d = document;
    d.querySelectorAll("details").forEach((x) => (x.open = true));
    d.querySelectorAll(".r-settings").forEach((x) => (x.open = true));
    const cw = d.documentElement.clientWidth;
    const hits = [];
    for (const el of d.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      if (r.right <= 0) continue; // parked off the left edge on purpose (the skip link)
      if (r.right > cw + 1 || r.left < -1) {
        if (hits.some((h) => h.el.contains(el))) continue;
        hits.push({ el, text: `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}.${Array.from(el.classList).slice(0, 2).join(".")} +${Math.round(r.right - cw)}px` });
      }
    }
    return { page: d.scrollingElement.scrollWidth - cw, hits: hits.map((h) => h.text), text: d.body.textContent.replace(/\s+/g, " ").trim().length };
  });
}

test("the side panel page renders from the extension at 380 px on the chrome storage backend", async (t) => {
  await shot(t, page, async () => {
    assert.equal(await page.evaluate(() => matchMedia("(max-width: 599px)").matches), true, "the panel surface");
    assert.equal(await page.evaluate(() => import(chrome.runtime.getURL("app/lib/store.js")).then((m) => m.backend())), "chrome");
    const text = await page.evaluate(() => document.body.textContent.replace(/\s+/g, " ").trim());
    assert.ok(text.length > 200, "the start page has content");
    assert.match(text, /Reach/);
  });
});

test("no route pushes the panel page past its edge at 380 px with every fold open", async (t) => {
  await shot(t, page, async () => {
    const failures = [];
    for (const route of ROUTES) {
      const r = await sweep(route);
      if (r.text < 20) failures.push(`${route}: did not render`);
      if (r.page > 0) failures.push(`${route}: page +${r.page}px`);
      for (const hit of r.hits) failures.push(`${route}: ${hit}`);
    }
    assert.deepEqual(failures, []);
  });
});

test("the bundled-CVE value page does not push past the panel's edge at 320 px either", async (t) => {
  const narrow = await h.newPage({ viewport: { width: 320, height: 900 } });
  try {
    await narrow.goto(h.url("index.html?platform=splunk#/"));
    await narrow.waitForSelector("nav, .r-nav, main", { timeout: 5000 });
    await shot(t, narrow, async () => {
      const r = await sweep("#/v/CVE-2025-39964", narrow);
      const failures = [];
      if (r.text < 20) failures.push("did not render");
      if (r.page > 0) failures.push(`page +${r.page}px`);
      for (const hit of r.hits) failures.push(hit);
      assert.deepEqual(failures, []);
    });
  } finally {
    await narrow.close();
  }
});

// C1 on the start route: the lede sits above the first h2 (Setup while it
// shows, else Workflows), landing state, drawers closed.
test("the start page's first h2 sits inside the 400 px budget at 320 on both platforms", async (t) => {
  for (const platform of ["splunk", "sentinel"]) {
    const narrow = await h.newPage({ viewport: { width: 320, height: 900 } });
    try {
      await narrow.goto(h.url(`index.html?platform=${platform}#/`));
      await narrow.waitForSelector("main h1", { timeout: 5000 });
      await shot(t, narrow, async () => {
        const first = await narrow.evaluate(() => {
          const h2 = [...document.querySelectorAll("main h2")].find((n) => n.textContent.trim() && n.getBoundingClientRect().height > 0);
          const line = document.querySelector(".r-empty__title");
          return { top: h2 ? Math.round(h2.getBoundingClientRect().top) : null, text: h2 ? h2.textContent.trim() : null, teach: line ? line.textContent.trim() : null };
        });
        assert.equal(first.teach, "What are you looking at?", `${platform}: the teach-state prompt`);
        assert.ok(first.top !== null && first.top <= 400, `${platform}: first h2 "${first.text}" top ${first.top}`);
      });
    } finally {
      await narrow.close();
    }
  }
});

// C1 at 320: every entity page draws the title block's action row inside
// the first screen, a bare value page (no field named) included; the tool
// pages packs and search draw none (the tool template defines none). On
// Sentinel a bare value route is absent and the unknown template's row stands.
test("at 320 x 600 on both platforms every entity route draws the title block's action row inside the viewport, and a bare value page draws Hold", async (t) => {
  const ENTITY = ["#/v/936", "#/v/CVE-2025-39964", "#/v/198.51.100.7", "#/st/crowdstrike:events:sensor", "#/f/SHA256HashData?st=crowdstrike:events:sensor&on=ProcessRollup2&value=8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4"];
  const TOOL = ["#/packs", "#/search?q=Process"];
  for (const platform of ["splunk", "sentinel"]) {
    const narrow = await h.newPage({ viewport: { width: 320, height: 600 } });
    try {
      await narrow.goto(h.url(`index.html?platform=${platform}#/`));
      await narrow.waitForSelector("main", { timeout: 5000 });
      await shot(t, narrow, async () => {
        const routes = platform === "sentinel" ? ENTITY.map((r) => r.replace("crowdstrike:events:sensor", "ReachCrowdStrike_CL")) : ENTITY;
        // Each route is awaited by its own title block: the h1 of the route before is gone.
        const go = async (route) => {
          const before = await narrow.evaluate(() => (document.querySelector("main h1") || {}).textContent || "");
          await narrow.evaluate((r) => { location.hash = r; }, route);
          await narrow.waitForFunction((was) => { const h1 = document.querySelector("main .r-title h1"); return h1 && h1.textContent !== was; }, before, { timeout: SECTION_WAIT });
        };
        for (const route of routes) {
          await go(route);
          await narrow.waitForSelector("main .r-title .r-actions", { timeout: SECTION_WAIT }).catch(() => null);
          const seen = await narrow.evaluate(() => {
            const row = document.querySelector("main .r-title .r-actions");
            return { bottom: row ? Math.round(row.getBoundingClientRect().bottom) : null, labels: row ? [...row.querySelectorAll("button, a")].map((n) => n.textContent.trim()) : [] };
          });
          assert.ok(seen.bottom !== null, `${platform} ${route}: the title block's action row`);
          assert.ok(seen.bottom <= 600, `${platform} ${route}: action row bottom ${seen.bottom}`);
          // A bare value page is Splunk's carriers ledger; on Sentinel the route is absent and draws the unknown template's own row.
          if (platform === "splunk" && route.startsWith("#/v/") && !route.includes("name=")) assert.equal(seen.labels[0], "Hold", `${platform} ${route}: ${seen.labels}`);
        }
        for (const route of platform === "sentinel" ? [] : TOOL) {
          await go(route);
          assert.equal(await narrow.evaluate(() => document.querySelector("main .r-title .r-actions")), null, `${route}: a tool page draws no action row`);
        }
      });
    } finally {
      await narrow.close();
    }
  }
});

test("a fresh trail's back button is disabled until a navigation, then returns to the start page", async (t) => {
  await shot(t, page, async () => {
    // A fresh trail, not just a hash change: earlier tests in this file left
    // hops behind (the same page, per the before() above), and a reload
    // alone keeps them (sessionStorage reach.trail).
    await page.evaluate(() => { location.hash = "#/"; });
    await page.waitForTimeout(250);
    await page.evaluate(() => sessionStorage.removeItem("reach.trail"));
    await page.reload();
    await page.waitForSelector(".r-navctl__btn[aria-label=Back]", { timeout: 5000 });
    assert.equal(await page.$eval(".r-navctl__btn[aria-label=Back]", (b) => b.disabled), true, "nothing to go back to yet");
    await page.evaluate(() => { location.hash = "#/catalogue"; });
    await page.waitForTimeout(250);
    assert.equal(await page.$eval(".r-navctl__btn[aria-label=Back]", (b) => b.disabled), false);
    await page.click(".r-navctl__btn[aria-label=Back]");
    await page.waitForTimeout(250);
    assert.equal(await page.evaluate(() => location.hash), "#/");
  });
});

test("the pinned frame is three rows inside 100 px, the compact title stays on screen after a scroll, and the trail is one line", async (t) => {
  await shot(t, page, async () => {
    // Nothing held: two rows, 72. With a pin: the Holding line makes three, 100.
    await page.evaluate(() => { localStorage.removeItem("reach.pinned"); location.hash = "#/f/ImageFileName?on=crowdstrike:events:sensor"; });
    await page.reload();
    await page.waitForSelector(".r-trail", { timeout: 5000 });
    const bare = await page.$eval(".r-bar", (el) => Math.round(el.getBoundingClientRect().height));
    assert.equal(bare, 72);
    await page.evaluate(() => localStorage.setItem("reach.pinned", JSON.stringify({ aid: "abc123" })));
    await page.reload();
    await page.waitForSelector(".r-holding__line", { timeout: 5000 });
    const rows = await page.evaluate(() => {
      const r = (s) => document.querySelector(s).getBoundingClientRect();
      return { bar: Math.round(r(".r-bar").height), row1: Math.round(r(".r-frame__row").height), trail: Math.round(r(".r-trail").height), hold: Math.round(r(".r-holding__line").height) };
    });
    assert.deepEqual(rows, { bar: 100, row1: 44, trail: 28, hold: 28 });
    await page.evaluate(() => window.scrollTo(0, 2000));
    await page.waitForTimeout(100);
    const title = await page.$eval(".r-frame__title", (el) => ({ text: el.textContent, top: Math.round(el.getBoundingClientRect().top), bottom: Math.round(el.getBoundingClientRect().bottom) }));
    assert.equal(title.text, "ImageFileName");
    assert.ok(title.top >= 0 && title.bottom <= 44, `compact title at ${title.top}-${title.bottom} after the scroll`);
    const chips = await page.$$eval(".r-trail__chip, .r-trail__sep", (els) => els.reduce((a, el) => a + el.getBoundingClientRect().width, 0));
    assert.ok(chips <= 348, `trail chips sum ${chips}`);
    await page.evaluate(() => { window.scrollTo(0, 0); localStorage.removeItem("reach.pinned"); });
  });
});

test("Holding's Add form closes on Cancel and on Escape, clearing what was typed", async (t) => {
  await shot(t, page, async () => {
    // Not the start page: with nothing held, WIDE_ROUTES folds Holding away
    // entirely there (app.js layout()) to give the catalogue the width.
    // The rail is behind the frame's Holding line, drawn while something
    // is held or pinned; the line opens it in place.
    await page.evaluate(() => { localStorage.setItem("reach.pinned", JSON.stringify({ aid: "abc123" })); location.hash = "#/v/198.51.100.7"; });
    await page.reload();
    await page.waitForSelector(".r-holding__line", { timeout: 5000 });
    await page.click(".r-holding__line");
    await page.click(".r-holding__addtoggle");
    assert.equal(await page.$eval(".r-holding__addtoggle", (b) => b.textContent), "Close");
    await page.fill(".r-holding__add input[aria-label='Fact key']", "aid");
    await page.click(".r-holding__addcancel");
    assert.equal(await page.$eval(".r-holding", (el) => el.classList.contains("is-adding")), false);
    assert.equal(await page.$eval(".r-holding__addtoggle", (b) => b.textContent), "Add");
    assert.equal(await page.$eval(".r-holding__add input[aria-label='Fact key']", (i) => i.value), "");

    await page.click(".r-holding__addtoggle");
    await page.fill(".r-holding__add input[aria-label='Fact key']", "aid");
    await page.keyboard.press("Escape");
    assert.equal(await page.$eval(".r-holding", (el) => el.classList.contains("is-adding")), false);
    assert.equal(await page.$eval(".r-holding__add input[aria-label='Fact key']", (i) => i.value), "");
    await page.evaluate(() => localStorage.removeItem("reach.pinned"));
  });
});

test("a page reached from a host click's landing survives a panel reload on both platforms: the route, its bands and the trail stay, and the worker's replay does not move it", async (t) => {
  // The native panel cannot be driven; a 320 x 600 extension tab with
  // chrome.tabs.getCurrent() spoofed walks the same handoff (followPanel).
  // Both fixtures carry the corpus-matched contactsd hash on a Mac row.
  const MAC = "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9";
  const cases = [
    { platform: "splunk", open: () => h.splunkPage(), click: (host) => host.locator('.shared-eventsviewer-list-body-row:nth-of-type(4) .json-tree .f-v[data-field-name="SHA256HashData"]').first().click(), st: "crowdstrike:events:sensor", value: MAC },
    { platform: "sentinel", open: () => h.bladePage(), click: (host) => host.locator('.ag-root [role="row"][aria-rowindex="5"] [role="gridcell"][aria-colindex="6"]').click({ button: "right" }), st: "ReachCrowdStrike_CL", value: MAC },
  ];
  for (const c of cases) {
    const panel = await h.newPage({ viewport: { width: 320, height: 600 } });
    const host = await c.open();
    try {
      await shot(t, panel, async () => {
        await panel.addInitScript(() => {
          chrome.tabs.getCurrent = () => Promise.resolve(undefined);
        });
        await panel.goto(h.url(`index.html?platform=${c.platform}#/`));
        await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
        // A fresh panel takes the window's last click on hello (the other
        // platform's, from the case before): let that land first.
        await panel.waitForTimeout(800);
        await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
        await c.click(host);
        await panel.waitForFunction((st) => location.hash.startsWith(`#/f/SHA256HashData?st=${encodeURIComponent(st)}`), c.st, { timeout: SECTION_WAIT });
        await panel.waitForSelector(".r-title__held a.r-idlink", { timeout: 5000 });
        // The field page's value line links the value page: the product's own hop.
        await panel.click(".r-title__held a.r-idlink");
        await panel.waitForFunction(() => location.hash.startsWith("#/v/"), { timeout: 5000 });
        await panel.waitForSelector('main section[data-band="meaning"]', { timeout: 5000 });
        const before = await panel.evaluate(() => ({ hash: location.hash, bands: [...document.querySelectorAll("main section[data-band]")].map((s) => s.dataset.band), chips: [...document.querySelectorAll(".r-trail__chip")].map((n) => n.textContent.trim()) }));
        assert.equal(before.hash, `#/v/${c.value}?st=${encodeURIComponent(c.st)}&name=SHA256HashData`, `${c.platform}: the value page`);
        assert.ok(before.bands.includes("meaning") && before.bands.includes("pivots"), `${c.platform}: ${before.bands.join(", ")}`);
        await panel.reload();
        await panel.waitForFunction(() => document.documentElement.dataset.surface === "panel", { timeout: 5000 });
        await panel.waitForSelector('main section[data-band="meaning"]', { timeout: 5000 });
        // The worker replays the last click on hello; give it time to arrive.
        await panel.waitForTimeout(600);
        const after = await panel.evaluate(() => ({ hash: location.hash, bands: [...document.querySelectorAll("main section[data-band]")].map((s) => s.dataset.band), chips: [...document.querySelectorAll(".r-trail__chip")].map((n) => n.textContent.trim()), back: document.querySelector(".r-navctl__btn[aria-label=Back]").disabled }));
        assert.equal(after.hash, before.hash, `${c.platform}: the route after the reload`);
        assert.deepEqual(after.bands, before.bands, `${c.platform}: the bands after the reload`);
        assert.deepEqual(after.chips, before.chips, `${c.platform}: the trail after the reload`);
        assert.equal(after.back, false, `${c.platform}: back still leads to the field page`);
      });
    } finally {
      await host.close();
      await panel.close();
    }
  }
});

test("the paste drawer's empty state names what it is, not a bare 'Paste'/'select a row'", async (t) => {
  await shot(t, page, async () => {
    // Not the start page: WIDE_ROUTES hides the drawer there entirely
    // (app.js layout()), same as it folds Holding away on an empty one.
    await page.evaluate(() => { location.hash = "#/f/ImageFileName?on=crowdstrike:events:sensor"; });
    await page.waitForTimeout(250);
    assert.equal(await page.$eval(".r-drawer", (el) => el.hidden), false, "the drawer shows on a field route");
    const kicker = await page.$eval(".r-drawer__kicker", (el) => el.textContent);
    assert.equal(kicker, "Query");
    const empty = await page.$eval(".r-drawer__empty", (el) => el.textContent);
    assert.match(empty, /SPL/);
    assert.doesNotMatch(empty, /ready to paste/);
  });
});

test("the drawer's open action is Run in Splunk from the base URL, and Open in portal on Sentinel once the blade named a workspace, a hint until then", async (t) => {
  await shot(t, page, async () => {
    // A filled drawer built directly (drawer.js has no pack dependency),
    // so this does not lean on a route resolving a real pivot.
    await page.evaluate(() => localStorage.setItem("reach.splunkBase", "https://splunk.example.com:8000"));
    const splunkRun = await page.evaluate(async () => {
      const mod = await import(chrome.runtime.getURL("app/components/drawer.js"));
      const d = mod.drawer({ state: "filled", spl: "index=main sourcetype=x | stats count" });
      return { hidden: d.querySelector(".r-drawer__run").hidden, text: d.querySelector(".r-drawer__run").textContent.trim() };
    });
    assert.equal(splunkRun.hidden, false);
    assert.equal(splunkRun.text, "Run in Splunk ↗");

    const sentinelPage = await h.extensionPage("index.html?platform=sentinel#/");
    try {
      const RID = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
      const sentinelRun = await sentinelPage.evaluate(async (rid) => {
        // A Splunk base URL means nothing here: the link needs the workspace
        // the Logs blade was seen on, and says so until there is one.
        localStorage.setItem("reach.splunkBase", "https://splunk.example.com:8000");
        const mod = await import(chrome.runtime.getURL("app/components/drawer.js"));
        const recipe = await import(chrome.runtime.getURL("app/lib/recipe.js"));
        const store = await import(chrome.runtime.getURL("app/lib/store.js"));
        await store.remove(recipe.WORKSPACES_KEY);
        const read = (d) => ({ hidden: d.querySelector(".r-drawer__run").hidden, text: d.querySelector(".r-drawer__run").textContent.trim(), href: d.querySelector(".r-drawer__run").getAttribute("href"), hintHidden: d.querySelector(".r-drawer__runhint").hidden, hint: d.querySelector(".r-drawer__runhint").textContent });
        const wait = () => new Promise((r) => setTimeout(r, 200));
        const none = mod.drawer({ state: "filled", spl: "SecurityEvent | take 10" });
        await wait();
        const before = read(none);
        await recipe.rememberWorkspace(rid, { name: "sentinel" });
        const known = mod.drawer({ state: "filled", spl: "SecurityEvent | take 10" });
        await wait();
        const after = read(known);
        await store.remove(recipe.WORKSPACES_KEY);
        return { before, after };
      }, RID);
      assert.equal(sentinelRun.before.hidden, true, "no link without a workspace");
      assert.equal(sentinelRun.before.hintHidden, false);
      assert.match(sentinelRun.before.hint, /Open the Logs blade once/);
      assert.equal(sentinelRun.after.hidden, false, "the link once the blade named a workspace");
      assert.equal(sentinelRun.after.text, "Open in portal ↗");
      assert.match(sentinelRun.after.href, /^https:\/\/portal\.azure\.com\/#view\/Microsoft_Azure_Monitoring_Logs\/LogsBlade\/resourceId\//);
      assert.equal(sentinelRun.after.hintHidden, true);
    } finally {
      await sentinelPage.close();
    }
  });
});

// Scenario 4's first row through the page: the pack's window default binds
// (earliest=-24h, ago(24h)) with the input still drawn, prefilled, so the
// run link carries a search and no placeholder; clearing the window leaves
// $earliest$ in the text and Copy and the run link wait for it, naming it.
test("a pivot with a time parameter opens on the pack's window with the input prefilled, and an unbound window disables Copy and the run link with the reason on both platforms", async (t) => {
  const ARN = "arn:aws:iam::123456789012:user/alice";
  const cases = [
    { platform: "splunk", route: `#/f/userIdentity.arn?st=aws:cloudtrail&value=${encodeURIComponent(ARN)}`, bound: /earliest=-24h/, label: "earliest", placeholder: /earliest=\$earliest\$/ },
    { platform: "sentinel", route: `#/f/PrincipalArn?st=ReachCloudTrail_CL&value=${encodeURIComponent(ARN)}`, bound: /TimeGenerated > ago\(24h\)/, label: "since", placeholder: /TimeGenerated > \$earliest\$/ },
  ];
  for (const c of cases) {
    const p = await h.extensionPage(`index.html?platform=${c.platform}#/`);
    try {
      await shot(t, p, async () => {
        await p.waitForSelector("main", { timeout: 5000 });
        await p.evaluate(async () => {
          localStorage.setItem("reach.splunkBase", "https://splunk.example.com:8000");
          const scope = await import(chrome.runtime.getURL("app/lib/scope.js"));
          scope.setIndex("main");
        });
        await p.evaluate((r) => { location.hash = r; }, c.route);
        await p.waitForSelector(".r-packpivots tr[data-row-id]", { timeout: 5000 });
        await p.locator(".r-packpivots tr[data-row-id]").first().click();
        await p.waitForFunction(() => (document.querySelector(".r-spl__code") || {}).textContent, null, { timeout: 5000 });
        const read = () => p.evaluate(() => {
          const d = document.querySelector(".r-drawer");
          const input = [...d.querySelectorAll(".r-drawer__params input")].find((i) => i.name === "earliest");
          const run = d.querySelector(".r-drawer__run");
          return { text: d.querySelector(".r-spl__code").textContent, window: input ? { value: input.value, label: input.labels && input.labels[0] ? input.labels[0].textContent.trim() : "" } : null, copy: { disabled: d.querySelector(".r-drawer__copy").disabled, title: d.querySelector(".r-drawer__copy").title }, run: { hidden: run.hidden, href: run.getAttribute("href") || "" }, hint: { hidden: d.querySelector(".r-drawer__runhint").hidden, text: d.querySelector(".r-drawer__runhint").textContent } };
        });
        const opened = await read();
        assert.match(opened.text, c.bound, `${c.platform}: the window bound from the pack`);
        assert.ok(opened.window, `${c.platform}: the window input stays drawn`);
        assert.equal(opened.window.value, "-24h", `${c.platform}: prefilled`);
        assert.equal(opened.copy.disabled, false, `${c.platform}: Copy with everything bound`);
        if (c.platform === "splunk") {
          assert.equal(opened.run.hidden, false, "Run in Splunk with the base URL set");
          assert.ok(!/%24earliest%24|%24index%24/.test(opened.run.href), `no placeholder in q=: ${opened.run.href}`);
        }
        const input = p.locator(".r-drawer__params input[name=earliest]");
        await input.fill("");
        await p.waitForFunction(() => /\$earliest\$/.test((document.querySelector(".r-spl__code") || {}).textContent || ""), null, { timeout: 5000 });
        const cleared = await read();
        assert.match(cleared.text, c.placeholder, `${c.platform}: the placeholder once cleared`);
        assert.equal(cleared.copy.disabled, true, `${c.platform}: Copy waits`);
        assert.match(cleared.copy.title, new RegExp(`^Not copied: ${c.label} is unbound`), `${c.platform}: ${cleared.copy.title}`);
        assert.equal(cleared.run.hidden, true, `${c.platform}: no run link with a placeholder`);
        assert.equal(cleared.hint.hidden, false);
        assert.match(cleared.hint.text, new RegExp(`No run link yet: ${c.label} is unbound`), `${c.platform}: ${cleared.hint.text}`);
        await input.fill("-7d");
        await p.waitForFunction(() => !/\$earliest\$/.test((document.querySelector(".r-spl__code") || {}).textContent || ""), null, { timeout: 5000 });
        const rebound = await read();
        assert.equal(rebound.copy.disabled, false, `${c.platform}: Copy once rebound`);
        assert.match(rebound.text, c.platform === "splunk" ? /earliest=-7d/ : /ago\(7d\)/);
      });
    } finally {
      await p.close();
    }
  }
});

test("a bundled CVE's value page draws the enrich band with the CISA KEV row, not the name-only branch", async (t) => {
  await shot(t, page, async () => {
    await page.evaluate(() => { location.hash = "#/v/CVE-2025-39964"; });
    await page.waitForFunction(() => location.hash === "#/v/CVE-2025-39964", { timeout: 5000 });
    await page.waitForSelector('main section[data-band="enrich"]', { timeout: 5000 });
    const kev = await page.locator('main section[data-band="enrich"] .reach-enrich__row', { hasText: "CISA KEV" });
    await kev.waitFor({ timeout: 5000 });
    assert.match(await kev.textContent(), /CISA KEV/);
    const kicker = await page.locator(".r-title .r-chip", { hasText: "a name, not a value" }).count();
    assert.equal(kicker, 0, "a CVE reads as a value, not the catalogue-name miss");
    await page.evaluate(() => { location.hash = "#/"; });
  });
});
