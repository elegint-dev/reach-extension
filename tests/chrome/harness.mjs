// The Chrome-native harness: the unpacked build from the worktree root,
// loaded into Playwright's Chromium (new headless, persistent context: the
// one mode that takes extensions), with the content scripts registered on
// two fixture origins and the fixture pages served from
// tests/fixtures/pages/ by request interception (no server, no DNS, no
// certificate: the pages are answered before any connection is made).
//
// The build is staged into a temp dir with one manifest change: the two
// fixture origins as host_permissions, since the product grants host
// access per origin from the popup's native prompt, which no automation
// can click. Registration itself then goes the product's way: the same
// entries background.js registers, from an extension page.
//
//   const h = await launch();          // { context, id, ... }
//   const page = await h.newPage({ viewport: { width: 320, height: 600 } }); // a page at that size
//   const page = await h.splunkPage(); // the search page with the T1003.001 rows
//   const notable = await h.notablePage(); // the search page with one notable-shaped row
//   const blade = await h.bladePage(); // the Logs blade grid slice
//   const alerts = await h.bladePage("/alerts"); // the blade on a SecurityAlert query
//   await h.storage();                 // chrome.storage.local, read from an extension page
//   await h.setStorage({ ... });       // chrome.storage.local, written from an extension page
//   await h.close();
//
// Failing tests get one screenshot each under tests/chrome/screenshots/
// (untracked): wrap the body in `shot(t, page, fn)`.
import { chromium } from "playwright";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, "..", "..");
export const FIXTURES = path.join(ROOT, "tests", "fixtures", "pages");
export const SCREENSHOTS = path.join(here, "screenshots");

// The budget for a wait that follows a click on a host page: the first
// click after launch loads the bundle, and under the parallel suite (every
// file launching its own Chromium) it has been measured at 13 s. Negative
// waits (a menu detaching) keep their own short budgets.
export const SECTION_WAIT = 30000;

export const SPLUNK_ORIGIN = "https://splunk.fixture.test";
export const BLADE_ORIGIN = "https://sandbox-1.reactblade.portal.azure.net";

// CONTENT_SCRIPTS, SENTINEL and the id prefix, read from the file the
// product registers from, so the harness cannot drift from it.
export function contentConfig() {
  const out = {};
  const src = fs.readFileSync(path.join(ROOT, "content-config.js"), "utf8");
  vm.runInNewContext(`${src}\nout.CONTENT_SCRIPTS = CONTENT_SCRIPTS; out.SENTINEL = SENTINEL; out.PREFIX = CONTENT_SCRIPT_ID_PREFIX;`, { out });
  return out;
}

// What ships, copied from the worktree: everything git archive would pack
// (the export-ignore set from .gitattributes is mirrored here by name).
const NOT_SHIPPED = new Set([".git", "node_modules", "tests", "tools", "docs", ".claude", ".githooks", "README.md", "SECURITY.md", "package.json", "package-lock.json"]);

// REACH_EXT_DIR points the harness at an already-built directory (for
// instance the unzipped store package) instead of copying this worktree;
// the default stays the worktree root.
const EXT_SOURCE = process.env.REACH_EXT_DIR ? path.resolve(process.env.REACH_EXT_DIR) : ROOT;

export function stageExtension(origins) {
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), "reach-ext-"));
  fs.cpSync(EXT_SOURCE, stage, {
    recursive: true,
    filter: (src) => src === EXT_SOURCE || (!NOT_SHIPPED.has(path.basename(src)) && !src.endsWith(".zip")),
  });
  const file = path.join(stage, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  manifest.host_permissions = origins;
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2));
  return stage;
}

function fixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name));
}

export function splunkUrl(name = "splunk-search") {
  const meta = JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), "utf8"));
  const u = new URL(meta.path, SPLUNK_ORIGIN);
  for (const [k, v] of Object.entries(meta.query)) u.searchParams.set(k, v);
  return u.toString();
}

// The Splunk fixture a search URL answers with: the notable page on its own
// sid (splunk-notable.json), the T1003.001 rows otherwise.
function splunkFixtureFor(u) {
  const notable = JSON.parse(fs.readFileSync(path.join(FIXTURES, "splunk-notable.json"), "utf8"));
  return u.searchParams.get("sid") === notable.query.sid ? "splunk-notable.html" : "splunk-search.html";
}

// extraOrigins: host_permissions a test needs beyond the two fixtures (for
// instance VirusTotal's, so a module's fetch-mode relay is permitted
// without chrome.permissions.request(), which never resolves headless).
export async function launch({ viewport = { width: 1280, height: 900 }, extraOrigins = [] } = {}) {
  const cfg = contentConfig();
  const stage = stageExtension([`${SPLUNK_ORIGIN}/*`, ...cfg.SENTINEL.patterns, ...extraOrigins]);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "reach-profile-"));
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    viewport,
    args: [`--disable-extensions-except=${stage}`, `--load-extension=${stage}`],
  });
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker");
  const id = new URL(worker.url()).host;

  // The fixtures, answered at the two origins.
  await context.route(`${SPLUNK_ORIGIN}/**`, (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === "/en-US/app/search/search") return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fixture(splunkFixtureFor(u)) });
    return route.fulfill({ status: 404, contentType: "text/plain", body: "not in the fixture" });
  });
  // The blade: the seeded table's grid on /logs, a SecurityAlert grid on /alerts.
  await context.route(`${BLADE_ORIGIN}/**`, (route) => {
    const u = new URL(route.request().url());
    return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fixture(u.pathname === "/alerts" ? "sentinel-alerts.html" : "sentinel-logs.html") });
  });

  // Registration, the way the worker does it after a grant.
  const setup = await context.newPage();
  await setup.goto(`chrome-extension://${id}/index.html`);
  await setup.evaluate(
    async ({ origin, cfg }) => {
      const entries = [{ id: cfg.PREFIX + origin, matches: [`${origin}/*`], js: cfg.CONTENT_SCRIPTS, runAt: "document_idle" }, ...cfg.SENTINEL.entries];
      await chrome.scripting.registerContentScripts(entries);
      await chrome.storage.local.set({ trustedOrigins: [origin, cfg.SENTINEL.origin] });
    },
    { origin: SPLUNK_ORIGIN, cfg },
  );
  await setup.close();

  const h = {
    context,
    id,
    stage,
    profile,
    worker,
    url: (p) => `chrome-extension://${id}/${p.replace(/^\//, "")}`,
    // A persistent context ignores newPage({ viewport }): every page opens
    // at the launch size. A page that claims a width sets it here, so a
    // "320 x 600" case runs at 320 and not at the launch viewport.
    async newPage({ viewport: size = null } = {}) {
      const page = await context.newPage();
      if (size) await page.setViewportSize(size);
      return page;
    },
    async extensionPage(p = "index.html", opts = {}) {
      const page = await h.newPage(opts);
      await page.goto(h.url(p));
      return page;
    },
    async splunkPage() {
      const page = await context.newPage();
      await page.goto(splunkUrl());
      await page.waitForSelector('.json-tree .f-v[data-reach-tagged]', { timeout: 5000 });
      return page;
    },
    async bladePage(pathname = "/logs") {
      const page = await context.newPage();
      await page.goto(`${BLADE_ORIGIN}${pathname}`);
      await page.waitForSelector(".ag-root", { timeout: 5000 });
      return page;
    },
    // The notable-shaped row (splunk-notable.html): one event, sourcetype stash.
    async notablePage() {
      const page = await context.newPage();
      await page.goto(splunkUrl("splunk-notable"));
      await page.waitForSelector('.json-tree .f-v[data-reach-tagged]', { timeout: 5000 });
      return page;
    },
    async storage() {
      const page = await context.newPage();
      await page.goto(h.url("index.html"));
      const out = await page.evaluate(() => chrome.storage.local.get(null));
      await page.close();
      return out;
    },
    // Write chrome.storage.local from an extension page: the module set
    // (reach.modules) a test needs on before it opens a popup.
    async setStorage(obj) {
      const page = await context.newPage();
      await page.goto(h.url("index.html"));
      await page.evaluate((o) => chrome.storage.local.set(o), obj);
      await page.close();
    },
    async clearStorage() {
      const page = await context.newPage();
      await page.goto(h.url("index.html"));
      await page.evaluate(async () => {
        const all = await chrome.storage.local.get(null);
        await chrome.storage.local.remove(Object.keys(all).filter((k) => k !== "trustedOrigins"));
      });
      await page.close();
    },
    async close() {
      await context.close().catch(() => {});
      fs.rmSync(stage, { recursive: true, force: true });
      fs.rmSync(profile, { recursive: true, force: true });
    },
  };
  return h;
}

// One screenshot per failing test, named for the test, nothing on a pass.
export async function shot(t, page, fn) {
  try {
    return await fn();
  } catch (err) {
    try {
      fs.mkdirSync(SCREENSHOTS, { recursive: true });
      const file = path.join(SCREENSHOTS, `${t.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.png`);
      await page.screenshot({ path: file, fullPage: true });
      err.message += `\n  screenshot: ${file}`;
    } catch {
      /* the failure stands on its own */
    }
    throw err;
  }
}

// The REACH section rendered for a click on a field value: Splunk's popup
// opens on the click, the section is appended under Splunk's items once
// the bundle is in, or opens as Reach's own panel beside the popup when it
// does not fit under them (the popup is never moved); either way the
// section's content is the same.
export async function openValuePopup(page, selector) {
  await (typeof selector === "string" ? page.locator(selector).first() : selector).click();
  const section = page.locator(".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown .reach-section, .reach-panel .reach-section");
  await section.waitFor({ timeout: SECTION_WAIT });
  return section;
}
