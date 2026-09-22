// it_88b661de part 2 (the audit's #5): moduleList.js's storage-keys line
// guards its initial paint against the unresolved modules.keysStoredOf()
// read with line.hidden = true, but no test asserted the guard itself
// held while that read was still in flight, only that the line showed the
// right count once tick() had already let it resolve.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import { moduleList } from "../app/components/moduleList.js";

dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

function rowFor(list, id) {
  const rows = dom.walk(list, (n) => n.attributes && n.attributes["data-module"]);
  return rows.find((n) => n.attributes["data-module"] === id);
}
function keysLine(row) {
  return dom.walk(row, (n) => n.classList && n.classList.contains("r-module__keys"))[0];
}

test("the storage-keys line stays hidden while modules.keysStoredOf() is still in flight, not just before tick() is awaited", async () => {
  const restore = fakeChrome().install();
  try {
    await modules.reset();
    await modules.hydrate();
    const list = moduleList({ platform: "splunk", context: "options" });
    const line = keysLine(rowFor(list, "discovery"));
    // Synchronously, right after mount: the read is definitely still
    // pending (the fake answers storage on a macrotask), so the line must
    // not have painted any count yet.
    assert.equal(line.hidden, true, "hidden while the read is in flight, not only until the next tick");
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(line.hidden, false, "unhidden once the read resolves");
  } finally {
    restore();
  }
});
