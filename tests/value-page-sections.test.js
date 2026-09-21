// The value page's section order is the popups' band order: plan() walks
// BANDS and keeps only the titled sections (SECTIONS) with a block, value
// and meaning as one Meaning, and every heading it draws resolves from the
// registry in the entity master's order (C4, C5). The carriers ledger
// reads as one registry band, each row naming its reading when the shape
// is ambiguous.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { h } from "../app/components/h.js";
import { HEAD, SECTIONS, BANDS } from "../app/lib/modules.js";
import { ENTITY_ORDER, heading, matcher } from "../app/lib/headings.js";
import { BAND_HEADING, SENTINEL_PIVOTS_LINE, SENTINEL_PIVOTS_LINE_PAGE, SENTINEL_NO_PIVOTS_NOTE, walkBands, plan as bandPlan } from "../app/lib/popup-ui.js";
import { classify } from "../app/lib/search.js";

await catalogue.load();
const restore = dom.install();
const { plan, carriers } = await import("../app/views/value.js");
test.after(() => restore());

const all = { hold: 1, benign: 1, value: 1, meaning: 1, everywhere: 1, verdict: 1, enrich: 1, pivots: 1, workflows: 1, pattern: 1 };

test("with every block present the page draws the sections in BANDS order, value and meaning as one Meaning", () => {
  assert.deepEqual(plan(BANDS, all), ["verdict", "meaning", "everywhere", "enrich", "pivots", "workflows", "pattern"]);
  assert.deepEqual(plan(BANDS, all), BANDS.filter((s) => s !== "value" && SECTIONS.includes(s)));
});

test("an absent block is an absent section, never a placeholder; the value line alone still makes Meaning", () => {
  assert.deepEqual(plan(BANDS, { value: 1, pivots: 1 }), ["meaning", "pivots"]);
  assert.deepEqual(plan(BANDS, { meaning: 1 }), ["meaning"]);
  assert.deepEqual(plan(BANDS, {}), []);
});

test("a band whose module is off is not drawn even with a block in hand", () => {
  const bands = BANDS.filter((b) => b !== "pattern" && b !== "workflows");
  assert.deepEqual(plan(bands, all), ["verdict", "meaning", "everywhere", "enrich", "pivots"]);
});

test("the page's plan is the popups' walk: for the same blocks the section ids equal the band ids walkBands draws", () => {
  const blocks = { hold: 1, benign: 1, value: 1, meaning: 1, everywhere: 1, verdict: 0, enrich: 1, pivots: 1, workflows: 0, pattern: 1 };
  const draw = (id) => (!blocks[id] ? null : HEAD.includes(id) ? h("div", { class: `head-${id}` }) : { el: h("div"), n: 2, fold: id === "pivots" });
  const walked = walkBands(BANDS, draw, { platform: "splunk" }).map((p) => p.dataset.band).filter(Boolean);
  assert.deepEqual(plan(BANDS, blocks), walked);
  assert.deepEqual(plan(BANDS, blocks), bandPlan(BANDS, (id) => Boolean(blocks[id])).filter((id) => SECTIONS.includes(id)));
  const off = BANDS.filter((b) => b !== "everywhere");
  assert.deepEqual(plan(off, blocks), walkBands(off, draw, { platform: "splunk" }).map((p) => p.dataset.band).filter(Boolean));
});

test("the page's h2 sequence is a subsequence of the entity master and every heading resolves from the registry", () => {
  const ids = plan(BANDS, all).map((id) => BAND_HEADING[id]);
  let at = -1;
  for (const id of ids) {
    const i = ENTITY_ORDER.indexOf(id);
    assert.ok(i > at, `${id} out of order`);
    at = i;
  }
  const m = matcher();
  for (const id of ids) assert.equal(m(heading(id, 4)), m(heading(id)), id);
});

test("the carriers ledger is the registry's One join away band; an ambiguous shape names each row's reading", () => {
  const idx = fields.searchIndex();
  const one = carriers({ fields, value: "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436", candidates: classify("ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436", idx).candidates });
  assert.ok(one.rows.length > 0);
  assert.ok(one.rows.every((r) => !/^as /.test(r.cells[1].text)), "one reading: no prefix");
  assert.ok(one.rows.every((r) => one.specs.has(r.id)));
  const md5 = classify("f0778584e83c4efc9cf026bc1e7f0489", idx);
  assert.ok(md5.ambiguous);
  const two = carriers({ fields, value: "f0778584e83c4efc9cf026bc1e7f0489", candidates: md5.candidates });
  const readings = new Set(two.rows.map((r) => r.cells[1].text.match(/^as ([^·]+) · /)?.[1]));
  assert.ok(readings.has("MD5 file hash") && readings.has("CrowdStrike agent id (host)"), [...readings].join(", "));
  assert.equal(heading("one-join-away"), "One join away");
});

test("the Sentinel lines name what the analyst presses on each surface and never a workflow", () => {
  for (const line of [SENTINEL_PIVOTS_LINE, SENTINEL_PIVOTS_LINE_PAGE, SENTINEL_NO_PIVOTS_NOTE]) {
    assert.match(line, /^No guided workflow on Sentinel/);
    assert.ok(!line.includes(String.fromCodePoint(8212)), "no em dash");
  }
  assert.match(SENTINEL_PIVOTS_LINE, /Copy KQL or Open as query tab\.$/);
  assert.match(SENTINEL_NO_PIVOTS_NOTE, /Filter the grid on this value instead\.$/);
});
