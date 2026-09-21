// The field page on the shared frame: its title block is main's first
// child, its headings resolve from the registry, and its h2 sequence is a
// subsequence of the entity master (C4), with the clicked value's verdict
// and enrichment drawn on the page a SIEM click lands on. The value is the
// route's, never a held store's: a click holds nothing.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as investigation from "../app/lib/investigation.js";
import * as lastEvent from "../app/lib/last-event.js";
import * as modules from "../app/lib/modules.js";
import * as store from "../app/lib/store.js";
import { ENTITY_ORDER, matcher } from "../app/lib/headings.js";
import { TERMS } from "../app/lib/platform.js";
import { render } from "../app/views/field.js";

await catalogue.load();

// One document for the file: the verdict, enrichment and notebook blocks
// keep drawing into their nodes after a test ends.
dom.install();

const ST = "crowdstrike:events:sensor";
const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
const resolve = matcher(TERMS);

function ctxFor(params, cat = catalogue) {
  const drawer = { fill() {}, fail() {} };
  return { fields, catalogue: cat, params, drawer, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

function draw(params, cat) {
  const el = render(ctxFor(params, cat));
  document.body.replaceChildren(el);
  return el;
}

// The keep row's re-sync runs off a queued microtask (keepRow in value.js).
const flush = () => new Promise((r) => setTimeout(r, 0));

const h2s = (el) => el.querySelectorAll("h2").map(dom.text);
const isSubsequence = (seq, master) => {
  let i = 0;
  for (const x of seq) {
    i = master.indexOf(x, i);
    if (i < 0) return false;
    i += 1;
  }
  return true;
};

const ROUTES = [
  { name: "SHA256HashData", st: ST, on: "ProcessRollup2" },
  { name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo" },
  { name: "TemplateDisposition", st: ST },
  { name: "RawProcessId", st: ST },
  { name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo" },
  { name: "eventType", st: "aws:cloudtrail" },
];

// Folds directly under a section, or under Meaning's and Values' bodies,
// are the registry's summaries; a fold inside a table cell is data.
const SECTION_BODY = ["r-dict__body", "r-meaning", "r-ann", "r-meaning-section"];
function sectionSummaries(el) {
  return el.querySelectorAll("summary").filter((node) => {
    const fold = node.parentNode;
    const host = fold && fold.parentNode;
    if (!host || !(host.tagName === "SECTION" || SECTION_BODY.some((c) => host.classList.contains(c)))) return false;
    if (node.querySelector("h2")) return false; // a fold whose summary is the section's own h2
    return !fold.classList.contains("r-ledger__fold"); // the band's h3 is checked as one
  });
}

test("every h2, ledger h3 and section fold on a field page resolves from the registry, and the h2s follow the entity master", () => {
  for (const params of ROUTES) {
    const el = draw(params);
    assert.equal(el.children[0].className.split(" ")[0], "r-title", `${params.name}: the title block first`);
    const ids = [];
    for (const node of el.querySelectorAll("h2")) {
      const e = resolve(dom.text(node));
      assert.ok(e, `${params.name}: h2 "${dom.text(node)}" is not in the registry`);
      ids.push(e.id);
    }
    assert.ok(ids.length >= 2, `${params.name}: ${ids.join(", ")}`);
    assert.ok(isSubsequence(ids, ENTITY_ORDER), `${params.name}: ${ids.join(" > ")} is not in the master order`);
    for (const node of el.querySelectorAll(".r-ledger__title")) assert.ok(resolve(dom.text(node)), `${params.name}: band "${dom.text(node)}"`);
    for (const node of sectionSummaries(el)) assert.ok(resolve(dom.text(node)), `${params.name}: summary "${dom.text(node)}" is not in the registry`);
    assert.equal(el.querySelectorAll("h4").length, 0, `${params.name}: no h4 headings`);
  }
});

test("a timestamp field draws no epoch widget; a decode field draws the decode widget inside Values", () => {
  const stamp = fields.searchIndex().fields.find((n) => fields.field(n).role === "timestamp" && fields.field(n).observed);
  const el = draw({ name: stamp, st: ST });
  assert.equal(el.querySelectorAll(".r-convert").length, 0, `${stamp}: no widget`);
  const dec = draw({ name: "TemplateDisposition", st: ST });
  const widgets = dec.querySelectorAll(".r-convert");
  assert.equal(widgets.length, 1);
  assert.ok(widgets[0].closest("section").querySelector("h2") && dom.text(widgets[0].closest("section").querySelector("h2")) === "Values", "the decode widget lives in Values");
});

test("Profile, Extraction and Query advisor draw from a measured view with the advisor on, in the master order after Workflows", async () => {
  await store.set(modules.KEY, { enabled: { advisor: true } });
  modules.reset();
  await modules.hydrate();
  try {
    const measured = new Proxy(catalogue, {
      get(target, key) {
        if (key !== "fieldOn") return target[key];
        return (st, name) => {
          const v = target.fieldOn(st, name);
          if (!v || name !== "TargetProcessId") return v;
          return {
            ...v,
            profile: { fill: 0.98, distinct: 1204, distinct_exact: true, count: 4900, sample: 5000, numeric: true, min: 1, max: 9999, mean: 500, top: [{ value: "5497396", count: 12 }], measured_at: "2026-09-17T09:00:00Z", window: "-7d" },
            provenance: [{ kind: "alias", from: "TargetProcessId_raw", app: "TA-crowdstrike", statement: "FIELDALIAS-tpid = TargetProcessId_raw AS TargetProcessId" }],
          };
        };
      },
    });
    const el = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo" }, measured);
    const ids = h2s(el).map((t) => resolve(t).id);
    for (const id of ["profile", "extraction", "query-advisor"]) assert.ok(ids.includes(id), `${id} in ${ids.join(", ")}`);
    assert.ok(ids.indexOf("workflows") < ids.indexOf("profile") && ids.indexOf("profile") < ids.indexOf("extraction") && ids.indexOf("extraction") < ids.indexOf("cim-mapping") && ids.indexOf("cim-mapping") < ids.indexOf("query-advisor"), ids.join(" > "));
    assert.ok(isSubsequence(ids, ENTITY_ORDER));
    const chips = el.querySelector(".r-title").querySelectorAll(".r-chip").map(dom.text);
    assert.ok(chips.includes("98% · 1,204 distinct"), chips.join(", "));
  } finally {
    await store.remove(modules.KEY);
    modules.reset();
    await modules.hydrate();
  }
});

test("the FDR ledger's five bands are folded under Pivots (N), the pack's pivots before them, and N counts the moves", () => {
  const el = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo" });
  const pivots = el.querySelector(".r-pivots");
  assert.ok(pivots, "a Pivots section");
  const title = dom.text(pivots.querySelector("h2"));
  assert.match(title, /^Pivots \(\d+\)$/);
  const bands = pivots.querySelectorAll(".r-ledger__band");
  assert.equal(bands.length, 5);
  assert.deepEqual(
    bands.map((b) => dom.text(b.querySelector(".r-ledger__title"))),
    ["On the record", "Search-time lookups", "One join away", "Suggested joins", "Not reachable"],
  );
  for (const b of bands) assert.ok(b.querySelector("details"), "every band folds");
  const list = pivots.querySelector(".r-packpivots__list");
  assert.ok(list, "the pack's pivots are drawn");
  assert.ok(pivots.children.indexOf(list) < pivots.children.indexOf(pivots.querySelector(".r-ledger")), "pack pivots before the ledger");
  const n = Number(/\((\d+)\)/.exec(title)[1]);
  const ledgerMoves = pivots.querySelectorAll(".r-ledger__row").filter((r) => !r.attributes["aria-disabled"] && !["here", "suggested"].includes(r.attributes["data-band-id"])).length;
  const packMoves = list.querySelectorAll("tr").filter((r) => r.attributes["data-row-id"]).length;
  assert.equal(n, ledgerMoves + packMoves, "N is the number of rows that fill the drawer");
});

test("the title block carries the value the route names, its decode, the decode chip, and the Hold, Mark benign and Note actions, and the render writes no held store", async () => {
  // Before the pack's values sidecar lands the chip is pending on a field
  // with no inline table; after, it counts or says no.
  const pending = draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo" });
  assert.ok(pending.querySelectorAll(".r-chip").map(dom.text).includes("decode …"));
  await catalogue.loadValues(ST);
  investigation.clear();
  const el = draw({ name: "TemplateDisposition", st: ST, value: "30" });
  const title = el.querySelector(".r-title");
  const valueLine = title.querySelector(".r-title__held");
  assert.ok(valueLine, "the value line");
  assert.match(dom.text(valueLine), /^value 30 · TEMPLATE_DISPOSITION_PREVENT/);
  assert.doesNotMatch(dom.text(valueLine), /^held/, "the notebook's word is not the click's");
  assert.deepEqual(investigation.all(), {}, "a route with a value holds nothing");
  const chips = title.querySelectorAll(".r-chip").map(dom.text);
  assert.ok(chips.some((c) => /^decode \(\d+\)$/.test(c)), `decode chip in ${chips.join(", ")}`);
  const verdictChip = title.querySelectorAll(".r-chip").find((c) => /verdict/.test(c.getAttribute("title") || ""));
  if (verdictChip) assert.doesNotMatch(verdictChip.getAttribute("title"), /held/);
  const actions = title.querySelector(".r-actions").querySelectorAll("button, a").map(dom.text);
  assert.deepEqual(actions.slice(0, 3), ["Hold", "Mark benign", "Note"]);
  assert.equal(title.querySelectorAll("h2").length, 0, "no heading in the title block");
  // No value on the route: no Hold, no Mark benign; a bitmask field's chip counts its flags.
  const bare = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo" });
  const bareActions = bare.querySelector(".r-actions").querySelectorAll("button, a").map(dom.text);
  assert.ok(!bareActions.includes("Hold") && !bareActions.includes("Mark benign"), bareActions.join(", "));
  assert.ok(bare.querySelectorAll(".r-chip").map(dom.text).includes("19 flags"));
  assert.ok(draw({ name: "TargetProcessId", st: ST, on: "ProcessHandleOpDetectInfo" }).querySelectorAll(".r-chip").map(dom.text).includes("no decode"));
});

test("a value held earlier is not the page's value: the field page reads the route, then the last click on this field, never the held store", () => {
  investigation.set("TemplateDisposition", "30");
  lastEvent.clear();
  try {
    const held = draw({ name: "TemplateDisposition", st: ST });
    assert.equal(held.querySelector(".r-title__held"), null, "a held fact draws no value line");
    lastEvent.remember({ platform: "splunk", container: ST, fields: { event_simpleName: "ProcessRollup2" }, clicked: { field: "TemplateDisposition", value: "40" } });
    const clicked = draw({ name: "TemplateDisposition", st: ST });
    assert.match(dom.text(clicked.querySelector(".r-title__held")), /^value 40\b/, "the last click on this field, when the route names none");
    const other = draw({ name: "DesiredAccess", st: ST, on: "ProcessHandleOpDetectInfo" });
    assert.equal(other.querySelector(".r-title__held"), null, "another field's page takes nothing from that click");
    const routed = draw({ name: "TemplateDisposition", st: ST, value: "30" });
    assert.match(dom.text(routed.querySelector(".r-title__held")), /^value 30\b/, "the route wins");
  } finally {
    investigation.clear();
    lastEvent.clear();
  }
});

test("the page's value binds its pivots without a held store: the pack pivot's $value$ and the ledger's aliased name carry it", () => {
  investigation.clear();
  const spls = [];
  const ctx = ctxFor({ name: "SHA256HashData", st: ST, on: "ProcessRollup2", value: HASH });
  ctx.drawer.fill = (q) => spls.push(q.spl);
  const el = render(ctx);
  document.body.replaceChildren(el);
  const packRow = el.querySelector(".r-packpivots__list").querySelectorAll("tr").find((r) => r.attributes["data-row-id"]);
  dom.fire(packRow, "click");
  assert.ok(spls.length, "the pack pivot filled the drawer");
  assert.ok(spls[spls.length - 1].includes(HASH), spls[spls.length - 1]);
  assert.ok(!spls[spls.length - 1].includes("$value$"), "the value is bound from the page, not asked for");
  assert.deepEqual(investigation.all(), {}, "filling a pivot holds nothing");
});

test("a clicked hash with the row's sibling fields draws Verdict and Enrichment on the field page, in the master order", () => {
  lastEvent.remember({ platform: "splunk", container: ST, fields: { event_platform: "Mac", SHA256HashData: HASH, ImageFileName: "/usr/bin/ssh", event_simpleName: "ProcessRollup2" } });
  try {
    const el = draw({ name: "SHA256HashData", st: ST, on: "ProcessRollup2", value: HASH });
    const ids = h2s(el).map((t) => resolve(t).id);
    assert.ok(ids.includes("verdict"), ids.join(", "));
    assert.ok(ids.includes("enrichment"), ids.join(", "));
    assert.ok(ids.indexOf("verdict") < ids.indexOf("enrichment") && ids.indexOf("enrichment") < ids.indexOf("pivots"));
    const chip = el.querySelector(".r-chip--verdict");
    assert.ok(chip, "the verdict tier chip in the title block");
    assert.equal(chip.getAttribute("title"), "the known-good verdict for this value");
    // Without the row's fields the verdict is absent, never a placeholder.
    lastEvent.clear();
    const without = draw({ name: "SHA256HashData", st: ST, on: "ProcessRollup2", value: HASH });
    assert.ok(!h2s(without).includes("Verdict"));
  } finally {
    lastEvent.clear();
  }
});

test("the title block's chip row stays short: the route chip draws its short form with the label as its title, and the join hazard is a label and one line with the rest in Meaning", async () => {
  try {
    const el = draw({ name: "RawProcessId", st: ST, value: "936" });
    const route = el.querySelector(".r-title__chips").querySelector(".r-chip--route");
    assert.ok(route, "the route chip");
    assert.match(dom.text(route), /^\S+\s?(here|one join|dead end)$/, dom.text(route));
    assert.ok(route.getAttribute("title"), "the route's label is the chip's title");
    const slot = el.querySelector(".r-title__callout");
    assert.equal(dom.text(slot.querySelector(".r-callout__label")), "Not safe to join on");
    assert.equal(dom.text(slot.querySelector(".r-callout__body")), "Scope by aid and a time window.");
    const line = el.querySelector(".r-meaning-section").querySelector(".r-meaning__unsafe");
    assert.match(dom.text(line), /^Not safe to join on: Expect multiple matches: the generated search requires both\.$/);
    // The Hold and Mark benign editors take no height until one is pressed.
    const keep = el.querySelector(".r-title__keep");
    assert.equal(keep.hidden, true);
    el.querySelector(".r-actions").querySelector(".r-action-benign").click();
    await flush();
    assert.equal(keep.hidden, false);
  } finally {
    investigation.clear();
  }
});
