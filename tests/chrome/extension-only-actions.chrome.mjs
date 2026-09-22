// it_88b661de part 4: one live case per extension-only action the audit's
// table found undriven. Where an action genuinely cannot run headless
// (chrome.permissions.request()'s native prompt: harness.mjs says why),
// the case is written as far as it goes and skipped with that reason; its
// branch is covered in node instead (tests/chrome-fake.test.js,
// tests/relay.test.js).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { launch, shot } from "./harness.mjs";

let h;
before(async () => {
  h = await launch({ extraOrigins: ["https://www.virustotal.com/*"] });
});
after(async () => {
  if (h) await h.close();
});

// ---------------------------------------------------------------------------
// The toolbar popup, rendered for real: no chrome.mjs case opened
// popup.html before. Classification (which button text a marker or an
// origin earns) stays covered in node (tests/popup.test.js); this asserts
// the page actually renders and wires its links, which node's DOM stub
// cannot.

test("popup.html renders for real and wires its links", async (t) => {
  const page = await h.extensionPage("popup.html");
  await shot(t, page, async () => {
    // Opened directly as a chrome-extension:// tab (not over a Splunk or
    // Azure origin), so render() settles on "Not available here": the
    // same non-http(s) case tests/popup.test.js drives against the node
    // fake. What that node test cannot show is that the real page
    // actually reaches this render at all and wires its other links.
    await page.waitForFunction(() => document.getElementById("toggle").textContent !== "Checking…", null, { timeout: 5000 });
    assert.equal(await page.locator("#toggle").textContent(), "Not available here");
    assert.equal(await page.locator("#toggle").isDisabled(), true);
    assert.equal(await page.locator("#appLink").getAttribute("href"), "#");
    assert.equal(await page.locator("#panelLink").getAttribute("href"), "#");
    assert.equal(await page.locator("#settingsLink").getAttribute("href"), "#");
  });
  await page.close();
});

// ---------------------------------------------------------------------------
// Permission grant AND revoke, checked live: harness.mjs's stageExtension()
// can only put an origin into the staged manifest's required
// host_permissions (auto-granted, and chrome.permissions.remove() on a
// required permission is a real, verified no-op: tried live below) or leave
// it unrequested. Reaching a genuinely optional-and-granted state needs
// either chrome.permissions.request()'s native prompt (tried live: a real
// trusted Playwright click on it left the promise unsettled for 3s, the
// same hang harness.mjs's own comment names) or seeding the profile's
// Preferences before launch, out of scope here. Both branches (request
// granting and notifying onAdded; remove revoking; a required permission
// surviving remove()) are covered in node: tests/chrome-fake.test.js,
// tests/relay.test.js, and modules-permission-buttons.test.js below.

test("a required host permission (the only kind this harness can pre-grant without a native prompt) is not touched by chrome.permissions.remove(), confirming the Revoke button needs a genuinely optional grant to test live", async (t) => {
  await h.setStorage({ "reach.modules": { enabled: { virustotal: true } }, vtApiKey: "fake-test-key-0000000000000000000000000000000000000000000000000000000000" });
  const page = await h.extensionPage("options.html?platform=splunk");
  await shot(t, page, async () => {
    await page.waitForSelector('.r-module[data-module="virustotal"]', { timeout: 5000 });
    const row = page.locator('.r-module[data-module="virustotal"]');
    await row.locator("summary").click();
    const permLine = row.locator(".r-module__permission");
    await page.waitForFunction(
      () => /granted/.test(document.querySelector('.r-module[data-module="virustotal"] .r-module__permission')?.textContent || ""),
      null,
      { timeout: 5000 },
    );
    await permLine.locator("button").click(); // Revoke, on the real extension
    await page.waitForTimeout(500);
    const stillGranted = await h.worker.evaluate(() => chrome.permissions.contains({ origins: ["https://www.virustotal.com/*"] }));
    assert.equal(stillGranted, true, "a required host permission cannot be revoked at runtime; the button's own click handler ran and reported no change");
  });
  await page.close();
});

test(
  "Grant and Revoke of a genuinely optional permission are not driven: chrome.permissions.request()'s native prompt never resolves headless",
  { skip: "verified live: a real trusted click on request() left the promise unsettled after 3s; no way to reach a granted-optional state without it in this harness" },
  () => {},
);

// ---------------------------------------------------------------------------
// chrome.sidePanel.setOptions: background.js's reach:app:opened handler
// disables the panel for the tab index.html opened as a top-level page in.

test("opening index.html as a top-level tab really disables the side panel for that tab (chrome.sidePanel.setOptions)", async (t) => {
  const page = await h.extensionPage("index.html?platform=splunk");
  await shot(t, page, async () => {
    const tabId = await page.evaluate(() => new Promise((resolve) => chrome.tabs.getCurrent((t) => resolve(t && t.id))));
    // announceTopLevelOpen() fires once, off the tab read; poll rather than
    // a fixed wait, since the round trip through the worker can take
    // longer under a loaded parallel run.
    let opts;
    for (let i = 0; i < 20; i++) {
      opts = await h.worker.evaluate((tid) => chrome.sidePanel.getOptions({ tabId: tid }), tabId);
      if (opts.enabled === false) break;
      await page.waitForTimeout(250);
    }
    assert.equal(opts.enabled, false, "the real chrome.sidePanel API reports this tab disabled");
  });
  await page.close();
});

// ---------------------------------------------------------------------------
// chrome.sidePanel.open(): popup.js's panelLink, driven by a real click.
// Playwright does not track a side panel in context.pages() (it is not a
// normal tab), so it is confirmed the way the browser itself would list
// it, through a raw CDP Target.getTargets from an unrelated page (the
// popup's own page target is gone once window.close() runs).

test("panelLink's click really opens the side panel (chrome.sidePanel.open), remembering this tab's platform first", async (t) => {
  const page = await h.newPage();
  await page.goto(h.url("popup.html"));
  await shot(t, page, async () => {
    await page.waitForFunction(() => document.getElementById("toggle").textContent !== "Checking…", null, { timeout: 5000 });
    await page.locator("#panelLink").click();
    // The click's own .then(() => window.close()) closes this page once
    // sidePanel.open() resolves; poll off the page, not on it, since the
    // round trip can take longer under a loaded parallel run.
    const probe = await h.context.newPage();
    const session = await h.context.newCDPSession(probe);
    let panel;
    for (let i = 0; i < 20 && !panel; i++) {
      const targets = await session.send("Target.getTargets");
      panel = targets.targetInfos.find((tgt) => tgt.type === "page" && tgt.url.endsWith("/index.html"));
      if (!panel) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    assert.ok(panel, "no side panel target found");
    // Same extension origin as the panel; read the same localStorage key
    // rememberPlatform() wrote before sidePanel.open() was called.
    await probe.goto(h.url("index.html"));
    const remembered = await probe.evaluate(() => localStorage.getItem("reach.platform"));
    assert.equal(remembered, "splunk", "rememberPlatform() landed before the panel opened");
    await probe.close();
  });
  await page.close().catch(() => {});
});

// ---------------------------------------------------------------------------
// Clipboard readback: search-history.chrome.mjs clicks Copy KQL and checks
// the resulting notebook entry, but never reads the clipboard itself back.

test("the drawer's Copy KQL really writes the clipboard, read back through navigator.clipboard", async (t) => {
  await h.context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
  const page = await h.extensionPage(`index.html?platform=sentinel#/f/SHA256HashData?st=ReachCrowdStrike_CL&value=${HASH}`);
  await shot(t, page, async () => {
    await page.waitForSelector(".r-packpivots tr[data-row-id]", { timeout: 8000 });
    await page.click(".r-packpivots tr[data-row-id]");
    await page.waitForFunction(() => (document.querySelector(".r-spl__code") || {}).textContent?.includes("ReachCrowdStrike_CL"), null, { timeout: 8000 });
    const kql = await page.$eval(".r-spl__code", (e) => e.textContent);
    await page.click(".r-drawer__copy");
    await page.waitForTimeout(300);
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    assert.equal(clip, kql, "the real clipboard, read back, holds exactly the KQL the drawer showed");
  });
  await page.close();
});

// ---------------------------------------------------------------------------
// A real download event: app/components/download.js's <a download> + Blob.

test("Export runbook really downloads a file (a real download event, not just the Blob URL being built)", async (t) => {
  await h.setStorage({ "reach.modules": { enabled: { share: true } } }); // share() gates the Export runbook button
  const hash = "escu%3Aname%3Adisabled%20kerberos%20preauthentication%20discovery%20with%20getaduser";
  const page = await h.extensionPage(`index.html?platform=splunk#/runbook/${hash}?rule=Disabled%20Kerberos%20Pre-Authentication%20Discovery%20With%20Get-ADUser&st=stash`);
  await shot(t, page, async () => {
    const exportBtn = page.locator("button", { hasText: "Export runbook" });
    await exportBtn.waitFor({ timeout: 5000 });
    const [download] = await Promise.all([page.waitForEvent("download", { timeout: 5000 }), exportBtn.click()]);
    assert.match(download.suggestedFilename(), /^reach-runbook-.*\.json$/);
  });
  await page.close();
});

// ---------------------------------------------------------------------------
// A real file picker: the Falcon dictionary import on options.html.

test("the Falcon dictionary row really imports a picked file (a real <input type=file>, not a synthetic FileList)", async (t) => {
  const page = await h.extensionPage("options.html?platform=splunk");
  await shot(t, page, async () => {
    await page.waitForSelector(".r-module__falcon", { timeout: 5000 });
    const dir = mkdtempSync(path.join(tmpdir(), "reach-falcon-"));
    const file = path.join(dir, "falcon.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        source: "falcon-fdr-schema",
        pulled_at: "2026-01-01T00:00:00Z",
        fields: { SHA256HashData: { description: "sha256" } },
        events: { ProcessRollup2: { variants: [{ description: "process start" }] } },
      }),
    );
    await page.locator(".r-module__falcon input[type=file]").setInputFiles(file);
    await page.locator(".r-module__falcon button", { hasText: "Import a Falcon dictionary" }).click();
    await page.waitForFunction(() => /1 fields, 1 events/.test(document.querySelector(".r-module__falcon")?.textContent || ""), null, { timeout: 5000 });
    assert.match(await page.locator(".r-module__falcon").textContent(), /1 fields, 1 events, pulled 2026-01-01/);
  });
  await page.close();
});
