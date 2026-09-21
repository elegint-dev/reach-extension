// The workflow page on Sentinel: a workflow a loaded pack declares in SPL
// only draws the unknown template with the off-platform chip, an id no
// pack knows keeps "no such workflow", and a pack workflow with a KQL
// search renders its page.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import * as workflows from "../app/lib/workflows.js";
import { render } from "../app/views/workflow.js";

globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });

await catalogue.load();

function ctx(params) {
  return { fields, catalogue, route: "workflow", params, drawer: { fill() {}, fail() {}, copy() {} }, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

const FDR_FIVE = ["pid", "process", "host", "detection", "ioc"];

test("each of the FDR five on Sentinel is known to the pack but renders nowhere: the chip says not on Microsoft Sentinel and the why names KQL", () => {
  const restore = dom.install();
  try {
    for (const id of FDR_FIVE) {
      const known = workflows.elsewhere(id);
      assert.equal(known && known.packId, "crowdstrike-falcon", `${id} is the Falcon pack's`);
      assert.equal(workflows.get(id, { params: {} }), null, `${id} renders nowhere on Sentinel`);
      const el = render(ctx({ id }));
      const title = el.children[0];
      assert.equal(dom.text(title.querySelector("h1")), known.title);
      assert.equal(dom.text(title.querySelector(".r-chip--state")), "not on Microsoft Sentinel", id);
      assert.match(dom.text(title.querySelector(".r-scope")), new RegExp(`^no KQL search in the crowdstrike-falcon pack's ${id} workflow; the pivots on a value or column page carry the value into KQL$`));
      assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Back", "Start"]);
      assert.ok(el.querySelectorAll("a").some((a) => a.getAttribute("href") === "#/w/hunt_mac_signing"), "the workflows this platform renders are listed");
    }
  } finally {
    restore();
  }
});

test("an id no pack knows still draws no such workflow on Sentinel", () => {
  assert.equal(workflows.elsewhere("nope"), null);
  const restore = dom.install();
  try {
    const title = render(ctx({ id: "nope" })).children[0];
    assert.equal(dom.text(title.querySelector("h1")), "nope");
    assert.equal(dom.text(title.querySelector(".r-chip--state")), "no such workflow");
  } finally {
    restore();
  }
});

test("a pack workflow with a KQL search renders its page on Sentinel", () => {
  assert.equal(workflows.elsewhere("hunt_mac_signing"), null);
  const restore = dom.install();
  try {
    const el = render(ctx({ id: "hunt_mac_signing" }));
    assert.ok(el.classList.contains("r-view--workflow"));
    assert.equal(el.querySelector(".r-chip--state"), null);
    assert.equal(el.querySelectorAll("h1").length, 1);
  } finally {
    restore();
  }
});
