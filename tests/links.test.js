// app/components/links.js: the one shape of an identifier link across the
// views, and the views that used to draw their own now import it.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as dom from "./_dom.js";
import { stLink, fieldLink, eventLink, plural } from "../app/components/links.js";

function withDom(fn) {
  const restore = dom.install();
  try {
    return fn();
  } finally {
    restore();
  }
}

test("stLink, fieldLink and eventLink draw an r-idlink anchor around the name in code, on the app's hash routes", () => {
  withDom(() => {
    const st = stLink("aws:cloudtrail");
    assert.equal(st.tagName, "A");
    assert.equal(st.getAttribute("href"), "#/st/aws%3Acloudtrail");
    assert.equal(st.className, "r-idlink");
    assert.equal(st.children[0].tagName, "CODE");
    assert.equal(dom.text(st), "aws:cloudtrail");
    assert.equal(fieldLink("userIdentity.arn", "aws:cloudtrail").getAttribute("href"), "#/f/userIdentity.arn?st=aws%3Acloudtrail");
    assert.equal(eventLink("ProcessRollup2").getAttribute("href"), "#/e/ProcessRollup2");
  });
});

test("fieldLink without a sourcetype carries no query, so a name-only field page opens", () => {
  withDom(() => {
    assert.equal(fieldLink("aid").getAttribute("href"), "#/f/aid");
    assert.equal(fieldLink("aid", null).getAttribute("href"), "#/f/aid");
    assert.equal(fieldLink("aid", "").getAttribute("href"), "#/f/aid");
  });
});

test("plural picks the singular at exactly one", () => {
  assert.equal(plural(1, "field", "fields"), "1 field");
  assert.equal(plural(0, "field", "fields"), "0 fields");
  assert.equal(plural(3, "pack", "packs"), "3 packs");
});

test("no view or component keeps its own stLink, fieldLink, eventLink or plural", () => {
  const files = ["discover-splunk", "discover-sentinel", "coverage", "sourcetype", "event", "field", "catalogue", "packs", "share", "value"].map((v) => `app/views/${v}.js`).concat(["app/components/provenance.js", "app/components/health.js"]);
  for (const name of files) {
    const src = readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url)), "utf8");
    assert.ok(!/^function (stLink|fieldLink|eventLink|plural)\(/m.test(src), `${name} defines no link helper`);
    assert.ok(/from "(\.\.\/components|\.)\/links\.js"/.test(src), `${name} imports links.js`);
  }
});
