// The sourcetype page on the panel: the title block first with its scope
// line and action row, the sections in the entity master order under
// registry headings, one code path for the record types, the role groups
// folded, and the measured chip that says when discovery last looked or
// that it never did.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { ENTITY_ORDER, matcher } from "../app/lib/headings.js";
import { termsFor } from "../app/lib/platform.js";
import { deltaBlock } from "../app/components/health.js";
import { render, measuredChip, recordTypes, isFleetBaselineTable } from "../app/views/sourcetype.js";

// The panel surface: every fold starts closed there.
globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });

await catalogue.load();

const ST = "crowdstrike:events:sensor";
const T = termsFor("splunk");
const resolve = matcher(T);

function ctx(params, extra = {}) {
  return { fields, catalogue, route: "sourcetype", params, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, ...extra };
}

function sectionHeadings(el) {
  const out = [];
  for (const s of el.querySelectorAll("section")) {
    for (const n of s.children) {
      if (n.tagName === "H2") out.push(dom.text(n));
      else if (n.tagName === "DETAILS") {
        const sum = n.children.find((c) => c.tagName === "SUMMARY");
        if (sum) out.push(dom.text(sum));
      }
    }
  }
  return out;
}

function subsequence(ids, order) {
  let at = 0;
  for (const id of ids) {
    const i = order.indexOf(id, at);
    if (i < 0) return false;
    at = i + 1;
  }
  return true;
}

test("the title block is the view's first child: name, chips, scope with the field count, described count and record-type field, then Describe, Discover, Bind fields and the fleet baseline (this is the Falcon sourcetype)", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"), "the title block comes first");
    assert.equal(title.getAttribute("data-kind"), "sourcetype");
    assert.equal(dom.text(title.querySelector("h1")), ST);
    const scope = dom.text(title.querySelector(".r-scope"));
    assert.match(scope, /^\d[\d,]* fields · record type event_simpleName · \d[\d,]* described$/);
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Describe", "Discover", "Bind fields", "Baseline: what my fleet runs"]);
    assert.equal(title.querySelector(".r-actions"), title.children[title.children.length - 1], "the action row is the block's last row");
    const hrefs = title.querySelector(".r-actions").querySelectorAll("a").map((a) => a.getAttribute("href"));
    assert.deepEqual(hrefs, ["#/discover", "#/coverage?st=crowdstrike%3Aevents%3Asensor"]);
  } finally {
    restore();
  }
});

test("the fleet baseline action and section draw only for the sourcetype it measures, on either platform", () => {
  const restore = dom.install();
  try {
    assert.equal(isFleetBaselineTable("crowdstrike:events:sensor", { catalogue, sentinel: false }), true, "the FDR sourcetype, on Splunk");
    assert.equal(isFleetBaselineTable("aws:cloudwatchlogs:guardduty", { catalogue, sentinel: false }), false, "any other sourcetype, on Splunk");
    assert.equal(isFleetBaselineTable(null, { catalogue, sentinel: false }), false);
    assert.equal(isFleetBaselineTable("crowdstrike:events:sensor", { catalogue: null, sentinel: true }), false, "the colon-bearing name is never a real KQL table on Sentinel");

    const el = render(ctx({ name: "aws:cloudwatchlogs:guardduty" }));
    assert.ok(!el.querySelector(".r-actions").children.map(dom.text).includes("Baseline: what my fleet runs"), "not on a sourcetype the baseline does not measure");
    assert.equal(el.querySelector("#fleet-baseline"), null, "no section either");

    const on = render(ctx({ name: ST }));
    assert.ok(on.querySelector(".r-actions").children.map(dom.text).includes("Baseline: what my fleet runs"));
    assert.ok(on.querySelector("#fleet-baseline"), "the section is drawn, under the fleet-baseline heading");
  } finally {
    restore();
  }
});

test("every h2 and section-level summary is a registry heading, in the entity master order: Meaning, Baseline, Workflows, Record types (N), Fields (N)", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const texts = sectionHeadings(el);
    const ids = [];
    for (const t of texts) {
      const e = resolve(t);
      assert.ok(e, `"${t}" is not in the heading registry`);
      if (!ids.includes(e.id)) ids.push(e.id);
    }
    assert.deepEqual(ids, ["meaning", "fleet-baseline", "workflows", "record-types", "fields"]);
    assert.ok(subsequence(ids, ENTITY_ORDER));
    for (const h2 of el.querySelectorAll("h2")) assert.ok(resolve(dom.text(h2)), `h2 "${dom.text(h2)}"`);
    assert.equal(el.querySelectorAll("h2").filter((n) => /Guided|What moved|Fields on this/.test(dom.text(n))).length, 0);
  } finally {
    restore();
  }
});

test("the record types are one list: pack events link to their page, discovery's counts sort it, and a value only discovery saw is plain text", () => {
  const rec = { recordTypes: [{ value: "ProcessRollup2", count: 900 }, { value: "OnlyInTenant", count: 5 }, { value: "DnsRequest", count: 1200 }] };
  const t = recordTypes(rec, ["ProcessRollup2", "DnsRequest", "EndOfProcess"]);
  assert.equal(t.total, 4);
  assert.equal(t.counted, true);
  assert.deepEqual(
    t.rows.map((r) => [r.name, r.count, r.link]),
    [["DnsRequest", 1200, true], ["ProcessRollup2", 900, true], ["OnlyInTenant", 5, false], ["EndOfProcess", null, true]],
  );
  const bare = recordTypes({}, ["B", "A"]);
  assert.deepEqual(bare.rows.map((r) => r.name), ["A", "B"]);
  assert.equal(bare.counted, false);
  assert.equal(recordTypes(rec, ["ProcessRollup2"], { eventRoute: false }).rows[0].link, false, "no link while the event route is not mounted");

  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const lists = el.querySelectorAll(".r-typelist");
    assert.equal(lists.length, 1, "one code path draws the record types");
    const wrap = el.querySelector(".r-typelist__wrap");
    assert.equal(wrap.tagName, "DETAILS");
    assert.equal(wrap.open, false, "folded on the panel");
    assert.match(dom.text(wrap.querySelector("summary")), /^Record types \(\d+\)$/);
    assert.equal(wrap.querySelector("summary").querySelector("h2").getAttribute("data-heading"), "record-types");
    assert.equal(lists[0].querySelectorAll("a").filter((a) => a.getAttribute("href") === "#/e/ProcessRollup2").length, 1);
  } finally {
    restore();
  }
});

test("Fields (N) folds every role group closed on the panel with the role and its count in the summary, and keeps the filter, the role select and the Bind link above them", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const section = el.querySelectorAll("section").find((s) => s.querySelector("h2") && /^Fields \(/.test(dom.text(s.querySelector("h2"))));
    assert.ok(section);
    const groups = section.querySelectorAll(".r-rolelist__group");
    assert.ok(groups.length > 3);
    for (const g of groups) {
      assert.equal(g.tagName, "DETAILS");
      assert.equal(g.open, false);
      assert.match(dom.text(g.querySelector("summary")), /^[a-z_]+ \d+$/);
      assert.equal(g.querySelector("summary"), g.children[0]);
    }
    const controls = section.querySelector(".r-rolelist__controls");
    assert.equal(controls.querySelector("input").getAttribute("type"), "search");
    assert.equal(controls.querySelector("select").tagName, "SELECT");
    assert.equal(dom.text(controls.querySelector(".r-rolelist__bind")), "Bind fields");
    assert.equal(controls.querySelector("input").getAttribute("style"), null, "no inline width: the stylesheet fits it to the panel");
  } finally {
    restore();
  }
});

test("the measured chip: not measured links to Discover when discovery never looked, measured <age> once it profiled, and nothing beside a health chip", () => {
  const restore = dom.install();
  try {
    const none = measuredChip({ name: "x" }, { discoverHref: "#/discover" });
    assert.equal(none.tagName, "A");
    assert.equal(none.getAttribute("href"), "#/discover");
    assert.equal(dom.text(none), "not measured");
    assert.ok(none.classList.contains("r-chip"));
    const plain = measuredChip({ name: "x" });
    assert.equal(plain.tagName, "SPAN");
    assert.equal(dom.text(plain), "not measured");
    const now = Date.parse("2026-09-19T12:00:00Z");
    const measured = measuredChip({ profiledAt: "2026-09-16T12:00:00Z" }, { now });
    assert.equal(dom.text(measured), "measured 3d ago");
    assert.match(measured.getAttribute("title"), /^profiled /);
    assert.equal(measuredChip({ lastSeen: now / 1000 }), null, "the health chip already speaks");
    assert.equal(measuredChip({ missingSince: "2026-09-10T00:00:00Z" }), null);

    const el = render(ctx({ name: ST }));
    const chips = el.querySelector(".r-title__chips");
    const links = chips.querySelectorAll("a").filter((a) => a.getAttribute("href") === "#/discover");
    assert.equal(links.length, 1, "the bundle's sourcetype was never measured here");
    assert.equal(dom.text(links[0]), "not measured");
  } finally {
    restore();
  }
});

test("Describe in the action row opens the editor inside Meaning", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const meaning = el.querySelectorAll("section")[0];
    assert.equal(dom.text(meaning.querySelector("h2")), "Meaning");
    assert.equal(meaning.querySelector("textarea"), null);
    const describe = el.querySelector(".r-actions").children.find((b) => dom.text(b) === "Describe");
    dom.fire(describe, "click");
    assert.ok(meaning.querySelector("textarea"), "the form opened where the description is read");
  } finally {
    restore();
  }
});

test("a sourcetype the catalogue does not know draws the title block with the chip, the why in the scope line, Describe and Discover, and Meaning with the editor", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: "acme:unknown" }));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.equal(dom.text(title.querySelector(".r-chip")), "not in the catalogue");
    assert.match(dom.text(title.querySelector(".r-scope")), /nothing in the catalogue knows this sourcetype yet/);
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Describe", "Discover"]);
    assert.deepEqual(el.querySelectorAll("h2").map(dom.text), ["Meaning"]);
    assert.ok(el.querySelector("section").querySelector("button"), "the editor's button is under Meaning");
  } finally {
    restore();
  }
});

test("Field changes (N) is the delta section's heading, N counting new, gone and shifted fields; Discover and Bind are not drawn while their modules are off", () => {
  const restore = dom.install();
  try {
    const delta = { at: "2026-09-18T10:00:00Z", previous_at: "2026-09-11T10:00:00Z", added: ["a", "b"], gone: ["c"], fill: [{ field: "d", from: 0.5, to: 0.9 }] };
    const block = deltaBlock(delta, ST);
    assert.equal(dom.text(block.querySelector("h2")), "Field changes (4)");
    assert.equal(block.querySelector("h2").getAttribute("data-heading"), "field-changes");
    assert.equal(deltaBlock(null, ST), null);

    const off = render(ctx({ name: ST }, { modules: { routes: () => ["catalogue", "sourcetype", "field", "value", "event"] } }));
    assert.deepEqual(off.querySelector(".r-actions").children.map(dom.text), ["Describe", "Baseline: what my fleet runs"], "the fleet baseline is not gated on the discover or coverage routes");
    assert.equal(off.querySelector(".r-rolelist__bind"), null);
    assert.equal(off.querySelector(".r-title__chips").querySelector("a"), null, "not measured is a plain chip with no Discover to link");
  } finally {
    restore();
  }
});

test("a concept's description carries once in Fields, even when the pack binds it to several aliased columns on the sourcetype; the rest show their own binding note or nothing", () => {
  const restore = dom.install();
  try {
    const gd = "aws:cloudwatchlogs:guardduty";
    const el = render(ctx({ name: gd }));
    const section = el.querySelectorAll("section").find((s) => s.querySelector("h2") && /^Fields \(/.test(dom.text(s.querySelector("h2"))));
    assert.ok(section);
    const rows = section.querySelectorAll(".r-fieldgrid__row");
    const typeRows = rows.filter((r) => /^(detail\.type|type|findingType|signature|raw_gd_type|app)$/.test(dom.text(r.querySelector("code"))));
    assert.equal(typeRows.length, 6, "the finding-type concept is bound on six columns of this sourcetype");
    const descSpans = typeRows.map((r) => r.querySelector(".r-fieldgrid__desc"));
    const full = descSpans.filter((s) => s && s.getAttribute("title") && s.getAttribute("title").includes("ThreatPurpose"));
    assert.equal(full.length, 1, "the finding-type concept description is drawn on exactly one of the six aliased rows");
  } finally {
    restore();
  }
});
