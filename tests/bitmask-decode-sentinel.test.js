// The bitmask and enum tables are concept-level, so the Sentinel sample
// table reads them through its own bindings: ReachCrowdStrike_CL's
// DesiredAccess is crowdstrike-falcon/desired_access and TemplateDisposition
// is crowdstrike-falcon/template_disposition, with the FDR bundle empty on
// this platform. Platform is pinned by the first import.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { PLATFORM } from "../app/lib/platform.js";
import { valueEntry } from "../app/lib/popup-ui.js";
import { render } from "../app/views/field.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

const TABLE = "ReachCrowdStrike_CL";

test("ReachCrowdStrike_CL's DesiredAccess and TemplateDisposition decode through the Falcon concepts with no FDR table on Sentinel", () => {
  assert.equal(fields.decode("TemplateDisposition"), null, "the FDR bundle is empty on Sentinel");
  assert.equal(catalogue.fieldOn(TABLE, "DesiredAccess").concept.key, "crowdstrike-falcon/desired_access");
  assert.equal(catalogue.fieldOn(TABLE, "TemplateDisposition").concept.key, "crowdstrike-falcon/template_disposition");
  assert.equal(catalogue.valueOn(TABLE, "DesiredAccess", "2097151").meaning, "PROCESS_ALL_ACCESS (0x1FFFFF)");
  assert.equal(catalogue.valueOn(TABLE, "DesiredAccess", "1040").meaning, "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION");
  assert.equal(catalogue.valueOn(TABLE, "DesiredAccess", "4194320").meaning, "PROCESS_VM_READ +0x400000");
  assert.equal(catalogue.valueOn(TABLE, "DesiredAccess", "16384"), null);
  assert.equal(catalogue.valueOn(TABLE, "TemplateDisposition", "30").meaning, "TEMPLATE_DISPOSITION_PREVENT");
  assert.equal(catalogue.fieldOn(TABLE, "TemplateDisposition").dictionary.count, 8);
  assert.equal(catalogue.fieldOn(TABLE, "DesiredAccess").dictionary.count, 20);
});

test("the grid menu's value band and the Sentinel column page read the same decode for the handle-open row's DesiredAccess", async () => {
  await catalogue.loadValues(TABLE);
  const restore = dom.install();
  try {
    const view = catalogue.fieldOn(TABLE, "DesiredAccess");
    const row = valueEntry({ catalogue, container: TABLE, field: "DesiredAccess", value: "2097151", view });
    assert.equal(row.kind, "entry");
    assert.equal(row.meaning, "PROCESS_ALL_ACCESS (0x1FFFFF)");
    assert.equal(row.source, "pack");
    const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
    const el = render({ fields, catalogue, params: { name: "DesiredAccess", st: TABLE, on: "ProcessHandleOpDetectInfo", value: "2097151" }, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
    const fold = el.querySelector(".r-title__held .r-title__flags");
    assert.ok(fold && !fold.open, "the flag list is folded closed on the Sentinel column page too");
    assert.match(dom.text(fold.querySelector("summary")), /^value 2097151 · PROCESS_ALL_ACCESS · 19 flags/);
    assert.equal(fold.querySelectorAll(".r-title__flaglist li").length, 19);
    const chips = el.querySelectorAll(".r-chip").map(dom.text);
    assert.ok(chips.includes("19 flags"), chips.join(", "));
    const td = render({ fields, catalogue, params: { name: "TemplateDisposition", st: TABLE, value: "30" }, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
    assert.match(dom.text(td.querySelector(".r-title__held")), /^value 30 · TEMPLATE_DISPOSITION_PREVENT/);
    assert.ok(td.querySelectorAll(".r-chip").map(dom.text).includes("decode (8)"));
  } finally {
    restore();
  }
});
