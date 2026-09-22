// The settings surface is one list drawn from the registry: the panel's
// gear fold and options.html draw the same modules in the same order with
// the same heads, a core module carries a fixed marker (never a pill),
// an optional module's pill starts at its live on/off state, and each
// head carries the anchor a popup's "set it up" link lands on.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
const modules = await import("../app/lib/modules.js");
const { moduleList } = await import("../app/components/moduleList.js");
const { settingsBar } = await import("../app/components/settingsBar.js");
await modules.hydrate();

function heads(list) {
  return dom.walk(list, (n) => n.attributes && n.attributes["data-module"]).map((n) => ({
    id: n.attributes["data-module"],
    tier: n.attributes["data-tier"],
    anchor: n.id,
    pill: dom.text(dom.walk(n, (c) => c.classList && c.classList.contains("r-module__pill"))[0] || { textContent: "" }),
    fixed: dom.walk(n, (c) => c.classList && c.classList.contains("r-module__fixed")).length,
    label: dom.text(dom.walk(n, (c) => c.classList && c.classList.contains("r-module__label"))[0]),
    sends: dom.text(dom.walk(n, (c) => c.classList && c.classList.contains("r-module__sends"))[0]),
  }));
}

test("the panel fold and the options page draw the same module list on each platform", () => {
  for (const platform of ["splunk", "sentinel"]) {
    const panel = heads(moduleList({ platform, context: "panel" }));
    const options = heads(moduleList({ platform, context: "options" }));
    assert.deepEqual(panel, options, `${platform}: same heads, tiers and sends lines`);
    assert.deepEqual(
      panel.map((m) => m.id),
      modules.MODULES.filter((m) => m.platforms.includes(platform)).map((m) => m.id),
      `${platform}: the platform's modules, no other`,
    );
  }
  const bar = settingsBar();
  assert.deepEqual(heads(bar), heads(moduleList({ platform: "splunk", context: "panel" })), "settingsBar wraps the same list");
});

test("options.js scopes its list to the page's platform, and every setup link names the platform it came from", async () => {
  const options = await readFile(new URL("../options.js", import.meta.url), "utf8");
  assert.match(options, /moduleList\(\{ platform: PLATFORM/, "options.html draws the current platform's list, the panel's");
  const section = await readFile(new URL("../app/lib/click-section.js", import.meta.url), "utf8");
  const page = await readFile(new URL("../app/views/value.js", import.meta.url), "utf8");
  assert.match(section, /optionsUrl\(platform, /, "the popups' one assembler names the click's platform");
  assert.match(page, /optionsUrl\(PLATFORM, /);
});

test("a core module carries the fixed marker and no pill; every other module carries a pill and no fixed marker; each head is the module's anchor", () => {
  for (const m of heads(moduleList({ platform: "splunk" }))) {
    const entry = modules.get(m.id);
    if (entry.tier === "core") {
      assert.equal(m.fixed, 1, `${m.id}: fixed marker`);
      assert.equal(m.pill, "", `${m.id}: no pill`);
    } else {
      assert.equal(m.fixed, 0, `${m.id}: no fixed marker`);
      assert.match(m.pill, /^(On|Off)$/, `${m.id}: pill text`);
    }
    assert.equal(m.anchor, modules.anchor(m.id));
    assert.equal(m.label, entry.label);
    assert.match(m.sends, /^Sends: /);
  }
});

test("a module's pill starts at its live state, and flips with modules.setEnabled", async () => {
  const restore = fakeChrome({ storage: false }).install();
  try {
    const before = heads(moduleList({ platform: "splunk" }));
    assert.equal(before.find((m) => m.id === "virustotal").pill, "Off");
    assert.equal(before.find((m) => m.id === "benign").pill, "On");
    await modules.setEnabled("virustotal", true);
    const after = heads(moduleList({ platform: "splunk" }));
    assert.equal(after.find((m) => m.id === "virustotal").pill, "On");
    await modules.setEnabled("virustotal", false);
  } finally {
    restore();
  }
});

test("VirusTotal, CIRCL, EPSS and the self-hosted relay sit together, after the bundled enrichment", () => {
  const ids = heads(moduleList({ platform: "splunk" })).map((m) => m.id);
  const i = ids.indexOf("enrich-bundled");
  assert.ok(i >= 0);
  assert.ok(ids.indexOf("virustotal") > i && ids.indexOf("circl") > i && ids.indexOf("epss") > i && ids.indexOf("selfhosted") > i);
  assert.deepEqual(ids.slice(ids.indexOf("virustotal"), ids.indexOf("virustotal") + 4), ["virustotal", "circl", "epss", "selfhosted"]);
});

test("every module lists on both platforms once workflows carry pack hunts on Sentinel", () => {
  const sentinel = heads(moduleList({ platform: "sentinel" })).map((m) => m.id);
  assert.ok(sentinel.includes("workflows"), "pack workflows mount on Sentinel");
  assert.deepEqual(sentinel, heads(moduleList({ platform: "splunk" })).map((m) => m.id));
});

test("options.js mounts moduleList and settingsBar.js wraps it: one component, two places", async () => {
  const options = await readFile(new URL("../options.js", import.meta.url), "utf8");
  const bar = await readFile(new URL("../app/components/settingsBar.js", import.meta.url), "utf8");
  const html = await readFile(new URL("../options.html", import.meta.url), "utf8");
  assert.match(options, /moduleList\(/);
  assert.match(bar, /moduleList\(/);
  assert.ok(!/id="vtApiKey"|id="csIndex"/.test(html), "the hand-written options form is gone");
  assert.match(html, /app\/styles\/components\.css/, "options.html draws with the app's stylesheet");
});

test.after(() => restore());
