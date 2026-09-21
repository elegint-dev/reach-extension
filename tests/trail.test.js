// The frame's trail row: chips for the last entity hops only, tool pages
// between them adding none, with the current entity page as the tail
// when it is one, a value-carrying hop named by its value, every chip one
// line.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as navstack from "../app/lib/navstack.js";
import { trail, chipLabel, CHIP_MAX } from "../app/components/trail.js";

const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";

test("a value chip within the chip budget reads the value alone for real container and record type names, the longer forms only when they fit, and its title carries field=value on sourcetype · record type; any other hop reads its name", () => {
  const hop = { hash: "#/f/x", kind: "field", name: "RawProcessId", field: "RawProcessId", value: "936", st: "crowdstrike:events:sensor", on: "ProcessHandleOpDetectInfo" };
  assert.deepEqual(chipLabel(hop, CHIP_MAX.wide), { text: "936", title: "RawProcessId=936 on crowdstrike:events:sensor · ProcessHandleOpDetectInfo" });
  assert.equal(chipLabel(hop, CHIP_MAX.narrow).text, "936");
  assert.equal(chipLabel({ ...hop, on: "PR2" }, CHIP_MAX.wide).text, "PR2 · 936", "a record type short enough to fit beside the value is shown");
  assert.equal(chipLabel({ ...hop, st: "st", on: "PR2" }, CHIP_MAX.wide).text, "PR2 · 936", "the container joins only when the whole fits");
  assert.equal(chipLabel({ ...hop, st: "st", on: "t" }, CHIP_MAX.wide).text, "st · t · 936");
  assert.deepEqual(chipLabel({ hash: "#/f/x", kind: "field", name: "RawProcessId", field: "RawProcessId", value: "936", st: "crowdstrike:events:sensor" }), { text: "936", title: "RawProcessId=936 on crowdstrike:events:sensor" });
  assert.deepEqual(chipLabel({ hash: "#/st/x", kind: "sourcetype", name: "crowdstrike:events:sensor" }), { text: "crowdstrike:events:sensor", title: "crowdstrike:events:sensor" });
  assert.deepEqual(chipLabel({ hash: "#/", kind: "page", name: "Reach" }), { text: "Reach", title: "Reach" });
  assert.equal(chipLabel({ hash: "#/zzz" }).text, "#/zzz", "an unlabelled entry falls back to its hash");
});

test("a route with no entity hop yet, such as the start page, draws no trail row", () => {
  const restore = dom.install();
  try {
    const el = trail();
    const s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
    el.update(s);
    assert.equal(el.querySelectorAll(".r-trail__chip").length, 0);
    assert.equal(el.hidden, true, "the row is hidden when there are no entity hops");
  } finally {
    restore();
  }
});

test("the row draws the last entity hops oldest first with the current one as the tail chip, links on the others", () => {
  const restore = dom.install();
  try {
    const el = trail();
    let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
    s = navstack.label(navstack.advance(s, "#/f/RawProcessId?value=936"), { kind: "field", name: "RawProcessId", field: "RawProcessId", value: "936", entity: true });
    s = navstack.label(navstack.advance(s, "#/f/TargetProcessId?value=5497396"), { kind: "field", name: "TargetProcessId", field: "TargetProcessId", value: "5497396", entity: true });
    s = navstack.label(navstack.advance(s, "#/st/crowdstrike:events:sensor"), { kind: "sourcetype", name: "crowdstrike:events:sensor", entity: true });
    el.update(s);
    const chips = el.querySelectorAll(".r-trail__chip");
    assert.equal(el.hidden, false);
    assert.deepEqual(chips.map((c) => c.tagName), ["A", "A", "SPAN"], "two hops link back, the tail does not");
    assert.deepEqual(chips.map((c) => dom.text(c)), ["936", "5497396", "crowds…ensor"], "in node there is no window, so the wide budget applies");
    assert.equal(chips[0].getAttribute("href"), "#/f/RawProcessId?value=936", "a chip click is a navigation, a new hop");
    assert.equal(chips[2].getAttribute("title"), "crowdstrike:events:sensor", "the full name in title once ellipsized");
    assert.equal(chips[0].getAttribute("title"), "RawProcessId=936");
    assert.ok(chips[2].classList.contains("r-trail__chip--here"));
    assert.equal(el.querySelectorAll(".r-trail__sep").length, 2);
    assert.equal(el.getAttribute("aria-label"), "Trail");
  } finally {
    restore();
  }
});

test("a long value middle-ellipsizes to the chip's character budget with the full value in title", () => {
  const restore = dom.install();
  try {
    const el = trail();
    const s = navstack.label(navstack.initial(`#/v/${HASH}`), { kind: "value", name: HASH, field: "SHA256HashData", value: HASH, st: "crowdstrike:events:sensor", entity: true });
    el.update(s);
    const chip = el.querySelector(".r-trail__chip");
    const text = dom.text(chip);
    assert.ok(text.length <= CHIP_MAX.wide, `${text} is ${text.length} characters`);
    assert.ok(text.includes("…"));
    assert.equal(chip.getAttribute("title"), `SHA256HashData=${HASH} on crowdstrike:events:sensor`);
  } finally {
    restore();
  }
});

test("a tool page reached between two entity hops adds no chip of its own", () => {
  const restore = dom.install();
  try {
    const el = trail();
    let s = navstack.label(navstack.initial("#/f/RawProcessId?value=936"), { kind: "field", name: "RawProcessId", field: "RawProcessId", value: "936", entity: true });
    s = navstack.label(navstack.advance(s, "#/share"), { kind: "page", name: "Share" }); // a tool page: no entity flag
    s = navstack.label(navstack.advance(s, "#/v/5497396?name=TargetProcessId"), { kind: "value", name: "5497396", field: "TargetProcessId", value: "5497396", entity: true });
    el.update(s);
    const chips = el.querySelectorAll(".r-trail__chip");
    assert.deepEqual(chips.map((c) => dom.text(c)), ["936", "5497396"], "the tool page between them is not a hop");
    assert.ok(chips[1].classList.contains("r-trail__chip--here"), "the current entity page is the tail");
  } finally {
    restore();
  }
});

test("a tool page open right now leaves the last entity hop a link, not marked current", () => {
  const restore = dom.install();
  try {
    const el = trail();
    let s = navstack.label(navstack.initial("#/f/RawProcessId?value=936"), { kind: "field", name: "RawProcessId", field: "RawProcessId", value: "936", entity: true });
    s = navstack.label(navstack.advance(s, "#/share"), { kind: "page", name: "Share" });
    el.update(s);
    const chips = el.querySelectorAll(".r-trail__chip");
    assert.equal(chips.length, 1, "the tool page draws no chip of its own");
    assert.equal(chips[0].tagName, "A", "the only entity hop so far is a link, since the panel is not on it now");
    assert.equal(chips[0].classList.contains("r-trail__chip--here"), false);
    assert.equal(chips[0].getAttribute("aria-current"), null);
  } finally {
    restore();
  }
});

test("the same entity page reached again right after a tool page counts once", () => {
  const restore = dom.install();
  try {
    const el = trail();
    let s = navstack.label(navstack.initial(`#/v/${HASH}`), { kind: "value", name: HASH, field: "SHA256HashData", value: HASH, st: "crowdstrike:events:sensor", entity: true });
    s = navstack.label(navstack.advance(s, "#/share"), { kind: "page", name: "Share" });
    s = navstack.label(navstack.advance(s, `#/v/${HASH}`), { kind: "value", name: HASH, field: "SHA256HashData", value: HASH, st: "crowdstrike:events:sensor", entity: true });
    el.update(s);
    const chips = el.querySelectorAll(".r-trail__chip");
    assert.equal(chips.length, 1, "the value page repeats after Share, not a second chip");
    assert.ok(chips[0].classList.contains("r-trail__chip--here"));
  } finally {
    restore();
  }
});

test("a runbook opened from an alert row is an entity hop; a runbook opened from the nav is not", () => {
  const restore = dom.install();
  try {
    const el = trail();
    let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
    s = navstack.label(navstack.advance(s, "#/runbook/x?rule=Suspicious%20Login"), { kind: "runbook", name: "Suspicious Login", entity: true });
    el.update(s);
    assert.deepEqual([...el.querySelectorAll(".r-trail__chip")].map((c) => dom.text(c)), ["Suspic…Login"]);

    s = navstack.label(navstack.advance(s, "#/runbook/x"), { kind: "runbook", name: "x", entity: false });
    el.update(s);
    const chips = el.querySelectorAll(".r-trail__chip");
    assert.deepEqual(chips.map((c) => dom.text(c)), ["Suspic…Login"], "the nav-opened runbook draws no chip; the alert's hop is still the tail");
    assert.equal(chips[0].classList.contains("r-trail__chip--here"), false, "the panel is on the nav runbook now, not the alert's hop");
  } finally {
    restore();
  }
});

test("the chip budget is the row sum the frame allows: 3 chips and 2 separators inside 288 at 320 and 348 at 380", () => {
  // 7.2px per character plus 14 of padding and border (components.css),
  // the separator 8 wide with a 4px gap either side.
  const width = (chars) => chars * 7.2 + 14;
  assert.ok(3 * Math.min(80, width(CHIP_MAX.narrow)) + 2 * (8 + 8) <= 288);
  assert.ok(3 * Math.min(104, width(CHIP_MAX.wide)) + 2 * (8 + 8) <= 348);
});
