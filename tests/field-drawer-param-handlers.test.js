// A Falcon field page mounts two drawer owners on the same route: a pack's
// pivot list (app/components/packPivots.js) and the FDR ledger
// (app/views/field.js fdrLedger). A typed drawer param must reach whichever
// one a row selection last put in charge, not always the one that
// registered last.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { render } from "../app/views/field.js";

await catalogue.load();
dom.install();

const ST = "crowdstrike:events:sensor";

function ctxFor(params) {
  let onParam = () => {};
  let lastFill = null;
  const drawer = {
    fill(spec) {
      lastFill = spec;
    },
    fail() {},
  };
  const ctx = {
    fields,
    catalogue,
    params,
    drawer,
    setUrl: () => "",
    navigate() {},
    href: () => "#",
    openSettings() {},
    // app.js registers one handler per route; this mirrors that contract.
    setDrawerParamHandler: (fn) => {
      onParam = fn;
    },
    setDrawerCopyHandler: () => {},
  };
  return { ctx, param: (n, v) => onParam(n, v), lastFill: () => lastFill };
}

function draw(params) {
  const { ctx, param, lastFill } = ctxFor(params);
  const el = render(ctx);
  document.body.replaceChildren(el);
  return { el, param, lastFill };
}

function textOf(fill) {
  return String(fill && (fill.spl.inline || fill.spl));
}

test("typing a pack pivot's param rebinds its own text, even after the FDR ledger has also had a row selected", () => {
  const { el, param, lastFill } = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo", value: "5497396" });

  // Select a ledger row first (one that fills the drawer in place, not the
  // "here" band, which navigates to a new route instead), so its handler is
  // the one that would win under a single last-write-wins slot.
  const ledgerRow = el.querySelectorAll("[data-row-id]").find((r) => r.dataset.bandId && r.dataset.bandId !== "here");
  assert.ok(ledgerRow, "an FDR ledger row that fills the drawer in place is drawn");
  dom.fire(ledgerRow, "click");

  // Then select the pack pivot row.
  const packRow = el.querySelectorAll('[data-row-id="cs_process_children"]')[0];
  assert.ok(packRow, "the pack pivot row (Processes this process started) is drawn");
  dom.fire(packRow, "click");

  assert.match(textOf(lastFill()), /aid="\$aid\$"/, "unbound aid still shows the placeholder on the pack pivot");

  param("aid", "aid-under-test-1");

  const after = lastFill();
  assert.match(after.subtitle || "", /TargetProcessId/, "the drawer still shows the pack pivot's own fill, not the ledger's");
  assert.match(textOf(after), /aid-under-test-1/, "the pack pivot's own fill picked up the typed aid");
  assert.doesNotMatch(textOf(after), /aid="\$aid\$"/, "the placeholder is gone once aid is bound");
});

test("typing a ledger row's param rebinds its own text after a pack pivot has also been selected", () => {
  const { el, param, lastFill } = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo", value: "5497396" });

  const packRow = el.querySelectorAll('[data-row-id="cs_process_children"]')[0];
  dom.fire(packRow, "click");

  const ledgerRow = el.querySelectorAll("[data-row-id]").find((r) => r.dataset.bandId && r.dataset.bandId !== "here");
  dom.fire(ledgerRow, "click");

  param("value", "some-other-value");

  const after = lastFill();
  assert.match(after.title || "", /manual fallback/, "the drawer shows the ledger row's own fill once it is the one selected last");
  assert.match(textOf(after), /some-other-value/, "the ledger row's own fill picked up the typed value");
});
