// The popups and the value page assemble one band list (modules.js BANDS)
// with no list of exceptions: walkBands draws each id in order or
// nothing, titles every section from the heading registry, folds carry the
// title in their summary, and a field click (no value, no verdict, no
// action row) comes out as Meaning, Other sourcetypes, Pivots.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { h } from "../app/components/h.js";
import { HEAD, SECTIONS, BANDS } from "../app/lib/modules.js";
import { walkBands, band, bandTitle, BAND_HEADING } from "../app/lib/popup-ui.js";
import { heading, get } from "../app/lib/headings.js";
import { termsFor } from "../app/lib/platform.js";

const restore = dom.install();
test.after(() => restore());

const titles = (parts) =>
  parts.map((p) => {
    const own = dom.walk(p, (n) => n.classList && n.classList.contains("reach-row__title"))[0];
    return own && (own.parentNode === p || (own.parentNode.tagName === "SUMMARY" && own.parentNode.parentNode === p)) ? dom.text(own) : null;
  });

function draw(blocks) {
  return (id) => {
    if (!(id in blocks)) return null;
    const v = blocks[id];
    if (v === null) return null;
    if (HEAD.includes(id)) return h("div", { class: `head-${id}` }, id);
    return { el: h("div", { class: `block-${id}` }, id), n: v.n, fold: v.fold === true };
  };
}

test("every band with a title maps to a registry entry, and the section ids are exactly SECTIONS minus the value line", () => {
  for (const id of Object.keys(BAND_HEADING)) assert.equal(get(BAND_HEADING[id]).level, "h2", id);
  assert.deepEqual(Object.keys(BAND_HEADING).sort(), SECTIONS.filter((s) => s !== "value").sort());
  const union = new Set([...HEAD, ...SECTIONS]);
  assert.equal(BANDS.length, union.size);
  for (const b of BANDS) assert.ok(union.has(b), `BANDS carries ${b}, not in HEAD or SECTIONS`);
});

test("a value click walks BANDS in order: verdict ahead of Meaning, Hold and Known benign after Meaning, the rest under their registry titles, value and meaning under one Meaning", () => {
  const blocks = { scope: {}, hold: {}, benign: {}, value: {}, meaning: {}, everywhere: { n: 2, fold: true }, verdict: {}, enrich: {}, pivots: { n: 3, fold: true }, workflows: { fold: true }, pattern: { fold: true } };
  const parts = walkBands(BANDS, draw(blocks), { platform: "splunk" });
  assert.deepEqual(parts.map((p) => p.className.split(" ")[0]), ["head-scope", "reach-band", "reach-band", "head-hold", "head-benign", "reach-details", "reach-band", "reach-details", "reach-details", "reach-details"]);
  assert.deepEqual(titles(parts), [null, "Verdict", "Meaning", null, null, "Other sourcetypes (2)", "Enrichment", "Pivots (3)", "Workflows", "Pattern"]);
  assert.deepEqual(parts.map((p) => p.dataset.band), [undefined, "verdict", "meaning", undefined, undefined, "everywhere", "enrich", "pivots", "workflows", "pattern"]);
  const meaning = parts[2];
  assert.deepEqual(dom.walk(meaning, (n) => n.className && n.className.startsWith("block-")).map((n) => n.className), ["block-meaning", "block-value"], "the field's meaning draws first, the value line under it");
});

test("a field click (no value, no verdict, no action row) is Meaning, Other sourcetypes, Pivots and nothing else", () => {
  const blocks = { scope: {}, hold: null, benign: null, value: null, meaning: {}, everywhere: { n: 1, fold: true }, verdict: null, enrich: null, pivots: { n: 2 }, workflows: null, pattern: null };
  const parts = walkBands(BANDS, draw(blocks), { platform: "sentinel" });
  assert.deepEqual(titles(parts), [null, "Meaning", "Other tables (1)", "Pivots (2)"]);
});

test("an id outside the bands list is never asked for, so an off module's block cannot be drawn", () => {
  const asked = [];
  walkBands(["scope", "meaning", "pivots"], (id) => { asked.push(id); return null; }, { platform: "splunk" });
  assert.deepEqual(asked, ["scope", "meaning", "pivots"]);
});

test("a band's title is the registry string under the platform's words, and a fold's summary carries it", () => {
  assert.equal(bandTitle("everywhere", 3, "sentinel"), heading("other-sourcetypes", 3, termsFor("sentinel")));
  assert.equal(bandTitle("pivots", 1, "splunk"), "Pivots (1)");
  assert.throws(() => bandTitle("value"), /no heading/);
  const folded = band("pattern", { el: h("div", null, "x"), fold: true, platform: "splunk" });
  assert.equal(folded.tagName, "DETAILS");
  assert.equal(dom.text(folded.children[0]), "Pattern");
  assert.equal(band("verdict", { el: null }), null, "a band with nothing to say is absent");
});

test("one assembler walks the shared band list for every popup; the content scripts call it and draw no band of their own", async () => {
  const { readFileSync } = await import("node:fs");
  const section = readFileSync(new URL("../app/lib/click-section.js", import.meta.url), "utf8");
  assert.match(section, /ui\.walkBands\(modules\.bands\(platform\)/, "click-section.js walks modules.bands through walkBands");
  assert.doesNotMatch(section, /reach-row__title/, "click-section.js leaves band titles to the registry");
  for (const file of ["value-popup.js", "field-info-popup.js", "sentinel-grid.js"]) {
    const src = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    assert.match(src, /\.sectionFor\(\{ platform: "(?:splunk|sentinel)"/, `${file} calls sectionFor`);
    assert.doesNotMatch(src, /walkBands|Block\(|reach-row__title|"Reaches: |`On: /, `${file} draws no band of its own`);
  }
});
