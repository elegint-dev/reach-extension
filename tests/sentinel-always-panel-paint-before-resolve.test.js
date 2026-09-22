// it_88b661de part 2 (the audit's #4): the Environment group's Sentinel
// "always open Reach beside the menu" checkbox used to paint unchecked for
// one tick even when the stored value was true (sentinel-settings.js's
// alwaysPanel() is "false until hydrate() resolves" by its own doc
// comment). Disabled until hydrate() resolves closes it: the wrong default
// is never shown as an actionable, certain state.
//
// Its own file: app/lib/sentinel-settings.js caches hydrate()'s promise
// for the life of the process (module-singleton `hydrated`), so a second
// moduleList() call anywhere else in this process would read that cache
// instead of exercising the read again.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as store from "../app/lib/store.js";
import { KEYS } from "../app/lib/storage-keys.js";
import { moduleList } from "../app/components/moduleList.js";

globalThis.REACH_PLATFORM = "sentinel";
dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

function tick(n = 30) {
  return new Promise((resolve) => setTimeout(resolve, n));
}

function alwaysPanelInputOf(list) {
  const label = dom.walk(list, (n) => n.tagName === "LABEL" && /beside the menu/.test(dom.text(n)))[0];
  return dom.walk(label, (n) => n.tagName === "INPUT" && n.attributes.type === "checkbox")[0];
}

test("Sentinel always-panel checkbox: disabled and unchecked-by-default until hydrate() resolves, then enabled and reflects the stored value", async () => {
  const restore = fakeChrome().install();
  try {
    await store.setLiteral({ [KEYS.sentinelAlwaysPanel]: true });
    const list = moduleList({ platform: "sentinel", context: "options" });
    const box = alwaysPanelInputOf(list);
    assert.equal(box.disabled, true, "disabled at mount, before hydrate() resolves");
    assert.equal(box.checked, false, "the cached default, not yet the stored true");
    await tick();
    assert.equal(box.disabled, false, "enabled once hydrate() resolves");
    assert.equal(box.checked, true, "reflects the stored value once known");
  } finally {
    restore();
  }
});
