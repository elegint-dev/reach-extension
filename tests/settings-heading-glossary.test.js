// settings-contract.md §3: four new headings, Core, Modules, Environment,
// Data, each an h2 with its own data-heading value, on both surfaces and
// both platforms; not part of app/lib/headings.js's registry (the panel's
// main content glossary is untouched by this contract).
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import { moduleList } from "../app/components/moduleList.js";
import { HEADINGS } from "../app/lib/headings.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
const fake = fakeChrome({ storage: false });
fake.install();
await modules.hydrate();

const GLOSSARY = { core: "Core", modules: "Modules", environment: "Environment", data: "Data" };

for (const context of ["panel", "options"]) {
  for (const platform of ["splunk", "sentinel"]) {
    test(`the four settings headings resolve exactly (${context}, ${platform})`, () => {
      const list = moduleList({ platform, context });
      const h2s = dom.walk(list, (n) => n.tagName === "H2");
      const byHeading = Object.fromEntries(h2s.map((n) => [n.dataset.heading, dom.text(n)]));
      for (const [id, text] of Object.entries(GLOSSARY)) assert.equal(byHeading[id], text, id);
      assert.deepEqual(Object.keys(byHeading).sort(), Object.keys(GLOSSARY).sort());
    });
  }
}

test("headings.js's own environment entry (the tool pages' Splunk instance / Workspace) is untouched: a coincidence of id, not a settings-surface entry", () => {
  const env = HEADINGS.find((e) => e.id === "environment");
  assert.ok(env, "headings.js still has its own environment entry");
  assert.equal(env.level, "h2");
  assert.notEqual(env.text({ Env: "Splunk instance" }), GLOSSARY.environment, "not the settings heading's text");
});

test.after(() => restore());
