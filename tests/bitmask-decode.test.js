// A bitmask concept decodes by one rule (values.js decodeBitmask): an exact
// values key reads its own name with the hex, else the set flags ascending
// by mask, bits no flag covers as a remainder, and nothing when no flag is
// set. The Falcon pack's desired_access and template_disposition carry the
// tables, bound on the Splunk sourcetype here and on the Sentinel sample
// table in bitmask-decode-sentinel.test.js; every surface reads them through
// catalogue.valueOn, so the popup band, the field page and the value page
// agree by construction.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as values from "../app/lib/values.js";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { valueEntry, valueBlock } from "../app/lib/popup-ui.js";
import { render } from "../app/views/field.js";

await catalogue.load();

const ST = "crowdstrike:events:sensor";
const RIGHTS = packs.pack("crowdstrike-falcon").concepts.desired_access.decode;

test("the bitmask rule: an exact value reads its name with the hex, else the set flags ascending by mask with the remainder, and no flag set reads nothing", () => {
  assert.equal(values.decodeBitmask(RIGHTS, "2097151"), "PROCESS_ALL_ACCESS (0x1FFFFF)");
  assert.equal(values.decodeBitmask(RIGHTS, "1040"), "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION");
  assert.equal(values.decodeBitmask(RIGHTS, "4194320"), "PROCESS_VM_READ +0x400000");
  assert.equal(values.decodeBitmask(RIGHTS, "16384"), null, "an unassigned bit alone: no decode");
  assert.equal(values.decodeBitmask(RIGHTS, 1040), "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION", "a number reads as its literal");
  assert.equal(values.decodeBitmask(RIGHTS, "0x410"), null, "only a decimal integer decodes");
  assert.equal(values.decodeBitmask(RIGHTS, "PROCESS_VM_READ"), null);
  assert.equal(values.decodeBitmask(RIGHTS, "0"), null);
});

test("the Falcon pack's desired_access carries the nineteen process rights as single-bit flags whose union leaves exactly the two unassigned bits, and template_disposition the FDR bundle's eight values entry for entry", () => {
  const pack = packs.pack("crowdstrike-falcon");
  assert.deepEqual(packs.validate(pack), []);
  const da = pack.concepts.desired_access;
  assert.equal(da.type, "bitmask");
  assert.equal(Object.keys(da.decode.flags).length, 19);
  let union = 0;
  for (const k of Object.keys(da.decode.flags)) {
    const mask = Number.parseInt(k.slice(2), 16);
    assert.equal(mask & (mask - 1), 0, `${k} sets one bit`);
    union |= mask;
  }
  assert.equal(union, 0x1f3fff);
  assert.equal(0x1fffff - union, 0xc000, "bits 0x4000 and 0x8000 are unassigned and read as remainder");
  assert.deepEqual(da.decode.values, { 2097151: "PROCESS_ALL_ACCESS" });
  assert.match(da.cite.url, /^https:\/\/learn\.microsoft\.com\//);
  const td = pack.concepts.template_disposition;
  assert.equal(td.type, "enum");
  assert.deepEqual(td.decode.values, fields.decode("TemplateDisposition").values, "equal to the FDR sidecar's table");
  assert.equal(Object.keys(td.decode.values).length, 8);
  assert.equal(fields.decode("DesiredAccess"), null, "the FDR sidecar has no DesiredAccess table: the pack's is the only one");
  for (const [col, id] of [["DesiredAccess", "desired_access"], ["TemplateDisposition", "template_disposition"]]) {
    assert.equal(catalogue.fieldOn(ST, col).concept.key, `crowdstrike-falcon/${id}`, col);
  }
});

test("the loader refuses flags off a bitmask concept, a flags key that is not one bit of eight hex digits, and a flags table that is not an object", () => {
  const base = () => ({ format: "reach-pack", version: 2, id: "t", name: "t", pack_version: "0.0.1", description: "t", source: "t", params: {}, feed: { id: "t", label: "t", description: "t", tags: [], discriminator: "m" }, concepts: { m: { label: "m", type: "bitmask", description: "m", decode: { values: {}, flags: { "0x00000001": "ONE" } } } }, containers: { "t:x": { platform: "splunk", kind: "custom", description: "t" } }, bindings: [{ platform: "splunk", container: "t:x", column: "m", concept: "m" }], hazards: {}, edges: [], templates: [] });
  assert.deepEqual(packs.validate(base()), []);
  const off = base();
  off.concepts.m.type = "enum";
  assert.match(packs.validate(off).join("; "), /flags: only a bitmask concept/);
  const two = base();
  two.concepts.m.decode.flags = { "0x00000003": "TWO" };
  assert.match(packs.validate(two).join("; "), /exactly one bit set/);
  const short = base();
  short.concepts.m.decode.flags = { "0x1": "ONE" };
  assert.match(packs.validate(short).join("; "), /eight hex digits/);
  const list = base();
  list.concepts.m.decode.flags = ["0x00000001"];
  assert.match(packs.validate(list).join("; "), /must be an object/);
  const flagsOnly = base();
  delete flagsOnly.concepts.m.decode.values;
  assert.deepEqual(packs.validate(flagsOnly), [], "flags alone is a decode");
});

test("catalogue.valueOn reads DesiredAccess and TemplateDisposition on the Splunk sourcetype through the one path, and the dictionary counts values and flags", () => {
  const all = catalogue.valueOn(ST, "DesiredAccess", "2097151");
  assert.equal(all.meaning, "PROCESS_ALL_ACCESS (0x1FFFFF)");
  assert.equal(all.source, "pack");
  assert.equal(all.provenance, "documented");
  assert.equal(all.concept, "crowdstrike-falcon/desired_access");
  assert.equal(catalogue.valueOn(ST, "DesiredAccess", "1040").meaning, "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION");
  assert.equal(catalogue.valueOn(ST, "DesiredAccess", "4194320").meaning, "PROCESS_VM_READ +0x400000");
  assert.equal(catalogue.valueOn(ST, "DesiredAccess", "16384"), null);
  assert.equal(catalogue.valueOn(ST, "TemplateDisposition", "30").meaning, "TEMPLATE_DISPOSITION_PREVENT", "an enum reads its meaning without a hex suffix");
  assert.equal(catalogue.valueOn(ST, "IntegrityLevel", "12288").meaning, "High (elevated)");
  const dict = catalogue.fieldOn(ST, "DesiredAccess").dictionary;
  assert.equal(dict.count, 20);
  assert.equal(Object.keys(dict.flags).length, 19);
  assert.equal(catalogue.fieldOn(ST, "TemplateDisposition").dictionary.count, 8);
});

test("the popup's value band draws the flag set for DesiredAccess and the value line on the field page reads value · decode", async () => {
  await catalogue.loadValues(ST);
  const restore = dom.install();
  try {
    const view = catalogue.fieldOn(ST, "DesiredAccess");
    const row = valueEntry({ catalogue, container: ST, field: "DesiredAccess", value: "1040", view });
    assert.equal(row.kind, "entry");
    assert.equal(row.meaning, "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION");
    const band = valueBlock({ field: "DesiredAccess", value: "2097151", container: ST, platform: "splunk", catalogue, view });
    assert.match(dom.text(band.querySelector(".reach-value__body")), /^2097151: PROCESS_ALL_ACCESS \(0x1FFFFF\)/);
    assert.equal(valueEntry({ catalogue, container: ST, field: "DesiredAccess", value: "16384", view }), null, "no flag set: no row");

    const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
    const draw = (params) => render({ fields, catalogue, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} });
    // The title block has one line: the value's own name and the flag
    // count, the flag names folded closed under it; the popup band and the
    // value page keep the joined list.
    const el = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo", value: "2097151" });
    const fold = el.querySelector(".r-title__held .r-title__flags");
    assert.ok(fold && fold.tagName.toLowerCase() === "details" && !fold.open, "the flag list is a closed fold");
    assert.match(dom.text(fold.querySelector("summary")), /^value 2097151 · PROCESS_ALL_ACCESS · 19 flags/);
    assert.doesNotMatch(dom.text(fold.querySelector("summary")), /0xC000/, "a named whole value shows no remainder");
    assert.deepEqual(fold.querySelectorAll(".r-title__flaglist li").map(dom.text).slice(0, 2), ["PROCESS_TERMINATE", "PROCESS_CREATE_THREAD"]);
    assert.equal(fold.querySelectorAll(".r-title__flaglist li").length, 19);
    assert.ok(el.querySelectorAll(".r-chip").map(dom.text).includes("19 flags"), "the chip counts the flags");
    const flags = el.querySelectorAll(".r-dict__flag").map(dom.text);
    assert.equal(flags.length, 19, "the dictionary block keeps the full list");
    assert.match(flags[0], /^0x00000001 PROCESS_TERMINATE/);
    const some = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo", value: "4194320" });
    assert.match(dom.text(some.querySelector(".r-title__held summary")), /^value 4194320 · 1 flag · \+0x400000/);
    assert.deepEqual(some.querySelectorAll(".r-title__flaglist li").map(dom.text), ["PROCESS_VM_READ"]);
    const two = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo", value: "1040" });
    assert.match(dom.text(two.querySelector(".r-title__held summary")), /^value 1040 · 2 flags →/);
    const none = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo", value: "16384" });
    assert.equal(none.querySelector(".r-title__flags"), null, "no flag set: no fold");
    assert.match(dom.text(none.querySelector(".r-title__held")), /^value 16384 →/);
  } finally {
    restore();
  }
});
