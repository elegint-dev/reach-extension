// it_88b661de part 2 (the audit's #1): the Environment group's App
// namespace field reads a chrome.storage.local value asynchronously at
// mount; it used to paint blank for one tick and stayed editable through
// that window, so a namespace typed fast enough was clobbered by the late
// read. It is now disabled until the read resolves, closing both bugs at
// once: nothing wrong ever paints as certain, and nothing typed can be
// overwritten. (The matching fix for Sentinel's always-panel checkbox is
// tests/sentinel-always-panel-paint-before-resolve.test.js, its own file:
// app/lib/sentinel-settings.js caches its hydrate() promise for the life
// of the process, so a second moduleList() call in the same file would
// read a stale cache, not the bug.)
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as store from "../app/lib/store.js";
import { KEYS } from "../app/lib/storage-keys.js";
import { moduleList } from "../app/components/moduleList.js";

dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

function tick(n = 30) {
  return new Promise((resolve) => setTimeout(resolve, n));
}

function nsInputOf(list) {
  return dom.walk(list, (n) => n.tagName === "INPUT" && n.attributes["aria-label"] === "App namespace")[0];
}

test("App namespace: disabled and blank until the stored value resolves, then enabled and filled", async () => {
  const restore = fakeChrome().install();
  try {
    await store.setLiteral({ [KEYS.spAppNamespace]: "acme" });
    const list = moduleList({ platform: "splunk", context: "options" });
    const nsInput = nsInputOf(list);
    assert.equal(nsInput.disabled, true, "disabled at mount, before the read resolves");
    assert.equal(nsInput.value, "", "no wrong value painted while disabled");
    await tick();
    assert.equal(nsInput.disabled, false, "enabled once the stored value is known");
    assert.equal(nsInput.value, "acme");
  } finally {
    restore();
  }
});

test("App namespace: a value typed before the stored read resolves is never reachable (the field is disabled)", async () => {
  const restore = fakeChrome().install();
  try {
    await store.setLiteral({ [KEYS.spAppNamespace]: "acme" });
    const list = moduleList({ platform: "splunk", context: "options" });
    const nsInput = nsInputOf(list);
    // Even set directly (a disabled field ignores nothing in this DOM
    // stub, only a real browser refuses input on it), the late .then no
    // longer has a race to lose: it runs once, while nothing else can.
    assert.equal(nsInput.disabled, true);
    await tick();
    assert.equal(nsInput.value, "acme", "the stored value landed with nothing to clobber it");
  } finally {
    restore();
  }
});
