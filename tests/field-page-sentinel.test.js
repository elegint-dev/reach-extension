// The same field template on Sentinel: table and column words, the
// concept's caution in the title block's callout slot, the platform note
// where no pivot exists, and the Pivots line where one does.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { ENTITY_ORDER, matcher } from "../app/lib/headings.js";
import { TERMS } from "../app/lib/platform.js";
import { render } from "../app/views/field.js";

await catalogue.load();
dom.install();

const TABLE = "ReachCrowdStrike_CL";
const resolve = matcher(TERMS);

function draw(params) {
  const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
  const el = render({ fields, catalogue, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
  document.body.replaceChildren(el);
  return el;
}

const isSubsequence = (seq, master) => {
  let i = 0;
  for (const x of seq) {
    i = master.indexOf(x, i);
    if (i < 0) return false;
    i += 1;
  }
  return true;
};

test("a Sentinel column page draws the title block first, registry headings in the master order, and no FDR ledger", () => {
  for (const name of ["SHA256HashData", "RawProcessId", "TemplateDisposition"]) {
    const el = draw({ name, st: TABLE });
    assert.equal(el.children[0].className.split(" ")[0], "r-title", `${name}: the title block first`);
    const ids = el.querySelectorAll("h2").map((n) => {
      const e = resolve(dom.text(n));
      assert.ok(e, `${name}: h2 "${dom.text(n)}"`);
      return e.id;
    });
    assert.ok(isSubsequence(ids, ENTITY_ORDER), `${name}: ${ids.join(" > ")}`);
    assert.equal(el.querySelectorAll(".r-ledger__band").length, 0, `${name}: no ledger on Sentinel`);
    assert.equal(el.querySelectorAll("h4").length, 0);
    assert.match(dom.text(el.querySelector(".r-scope")), /^on ReachCrowdStrike_CL/);
  }
});

test("the concept's caution on RawProcessId sits in the callout slot, above the sections, and once only after the values sidecar lands", async () => {
  const el = draw({ name: "RawProcessId", st: TABLE });
  const slot = el.querySelector(".r-title__callout");
  assert.ok(slot, "the callout slot");
  assert.match(dom.text(slot), /RawProcessId/);
  assert.ok(slot.querySelector(".r-callout"), "drawn as a callout");
  await catalogue.loadValues(TABLE);
  await new Promise((r) => setTimeout(r, 20));
  const caution = dom.text(slot.querySelector(".r-callout__body"));
  assert.equal(dom.text(el).split(caution).length - 1, 1, "the caution is not repeated under Values");
});

test("with no pivot from the column the platform note is the callout; with one, Pivots (N) carries the line", async () => {
  await catalogue.loadValues(TABLE);
  const none = draw({ name: "WindowTitle", st: TABLE });
  assert.equal(none.querySelector(".r-pivots"), null);
  assert.match(dom.text(none.querySelector(".r-title__callout")), /No guided workflow on Sentinel.*Filter the grid on this value instead\./);
  assert.ok(none.querySelectorAll(".r-chip").map(dom.text).includes("no decode"), "the negative is on screen");
  const some = draw({ name: "SHA256HashData", st: TABLE });
  const pivots = some.querySelector(".r-pivots");
  assert.ok(pivots, "Pivots (N) on the bound column");
  assert.match(dom.text(pivots.querySelector("h2")), /^Pivots \([1-9]\d*\)$/);
  assert.match(dom.text(pivots.querySelector(".r-pivots__platform")), /^No guided workflow on Sentinel: these pivots carry the value\. Copy KQL/);
  assert.equal(some.querySelector(".r-title__callout"), null, "no platform note when the pivots carry the value");
  assert.equal(some.querySelectorAll("h2").map(dom.text).includes("Workflows"), false, "no Workflows on Sentinel");
});
