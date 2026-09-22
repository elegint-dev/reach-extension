// it_88b661de part 4: the module fold's own Grant/Revoke button
// (app/components/moduleList.js's permissionLine, backed by
// modules.permitted/requestHosts/revokeHosts) was checked only through
// tests/_chrome.js's auto-granting request() stub, never asserted end to
// end as a click. chrome.permissions.request()'s native prompt cannot be
// driven live (tests/chrome/extension-only-actions.chrome.mjs), so this is
// where the branch is actually proven: Grant flips the line to granted and
// its own button to Revoke; Revoke flips it back.
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

function tick(n = 30) {
  return new Promise((resolve) => setTimeout(resolve, n));
}
function rowFor(list, id) {
  const rows = dom.walk(list, (n) => n.attributes && n.attributes["data-module"]);
  return rows.find((n) => n.attributes["data-module"] === id);
}
function permLineOf(row) {
  return dom.walk(row, (n) => n.classList && n.classList.contains("r-module__permission"))[0];
}
async function fresh() {
  modules.reset();
  await modules.hydrate();
}

test("Grant requests the module's hosts and flips the line to granted; Revoke removes them and flips it back", async () => {
  const restore = fakeChrome().install();
  try {
    await fresh();
    const list = moduleList({ platform: "splunk", context: "options" });
    const row = rowFor(list, "virustotal");
    row.querySelector(".r-module__fold").open = true;
    await tick();
    const permLine = permLineOf(row);
    assert.match(dom.text(permLine), /not granted/);
    const grantBtn = dom.walk(permLine, (n) => n.tagName === "BUTTON")[0];
    assert.equal(grantBtn.textContent, "Grant");

    dom.fire(grantBtn, "click");
    await tick();
    assert.match(dom.text(permLineOf(row)), /: granted\./, "the line reads granted once request() resolves");
    const revokeBtn = dom.walk(permLineOf(row), (n) => n.tagName === "BUTTON")[0];
    assert.equal(revokeBtn.textContent, "Revoke");
    assert.equal(await modules.permitted("virustotal"), true);

    dom.fire(revokeBtn, "click");
    await tick();
    assert.match(dom.text(permLineOf(row)), /not granted/, "revoke() removes it and the line is re-read, not left stale");
    assert.equal(await modules.permitted("virustotal"), false);
  } finally {
    restore();
  }
});
