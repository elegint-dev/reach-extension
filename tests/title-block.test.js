// The title block: the first thing in main, in a fixed order, with the
// action row last and every empty row absent.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { h } from "../app/components/h.js";
import { titleBlock, midEllipsis, H1_MAX } from "../app/components/titleBlock.js";

const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";

test("the rows come in the contract's order: h1, chips, scope, callout, held line, actions last", () => {
  const restore = dom.install();
  try {
    const el = titleBlock({
      kind: "field",
      h1: "RawProcessId",
      chips: [h("span", { class: "r-chip" }, "L1"), null, h("span", { class: "r-chip" }, "raw")],
      scope: [h("a", { href: "#/st/x" }, "on crowdstrike:events:sensor"), "ProcessRollup2", null],
      callout: h("div", { class: "r-callout" }, "Not safe to join on"),
      held: h("span", null, "held 936"),
      actions: [h("button", null, "Hold"), h("button", null, "Mark benign")],
    });
    assert.ok(el.classList.contains("r-title"));
    assert.equal(el.getAttribute("data-kind"), "field");
    const rows = el.children.map((c) => `${c.tagName.toLowerCase()}.${c.className.split(" ")[0]}`);
    assert.deepEqual(rows, ["h1.r-title__h1", "div.r-title__chips", "p.r-scope", "div.r-title__callout", "p.r-title__held", "div.r-actions"]);
    assert.equal(dom.text(el.querySelector("h1")), "RawProcessId");
    assert.equal(el.querySelectorAll(".r-chip").length, 2, "a null chip is skipped");
    assert.equal(dom.text(el.querySelector(".r-scope")), "on crowdstrike:events:sensor · ProcessRollup2");
    assert.equal(el.querySelectorAll(".r-scope__sep").length, 1, "one separator between two items");
    assert.deepEqual(el.querySelector(".r-actions").querySelectorAll("button").map(dom.text), ["Hold", "Mark benign"]);
  } finally {
    restore();
  }
});

test("a row with nothing to say is absent, never a placeholder", () => {
  const restore = dom.install();
  try {
    const el = titleBlock({ h1: "Packs", scope: ["3 packs"] });
    assert.deepEqual(el.children.map((c) => c.tagName), ["H1", "P"]);
    assert.equal(el.querySelector(".r-actions"), null);
    assert.equal(el.querySelector(".r-title__chips"), null);
    assert.equal(el.getAttribute("data-kind"), "page");
  } finally {
    restore();
  }
});

test("a long id or hash middle-ellipsizes in the h1 with the full value in title; a short name carries no title", () => {
  const restore = dom.install();
  try {
    const long = titleBlock({ kind: "value", h1: HASH });
    const h1 = long.querySelector("h1");
    assert.ok(dom.text(h1).length <= H1_MAX);
    assert.ok(dom.text(h1).includes("…"));
    assert.equal(h1.getAttribute("title"), HASH);
    const short = titleBlock({ h1: "Reach" });
    assert.equal(short.querySelector("h1").getAttribute("title"), null);
    assert.equal(dom.text(short.querySelector("h1")), "Reach");
  } finally {
    restore();
  }
});

test("a node h1 (the notebook's title input) is placed inside the h1 as it is", () => {
  const restore = dom.install();
  try {
    const input = h("input", { type: "text", value: "Untitled" });
    const el = titleBlock({ kind: "notebook", h1: input });
    assert.equal(el.querySelector("h1").children[0], input);
  } finally {
    restore();
  }
});

test("midEllipsis keeps the head and the tail and never exceeds the budget", () => {
  assert.equal(midEllipsis("short", 10), "short");
  assert.equal(midEllipsis("abcdefghijklmnop", 9), "abcd…mnop");
  assert.equal(midEllipsis(HASH, 12).length, 12);
  assert.equal(midEllipsis(null), "");
  assert.equal(midEllipsis(12345678901234567890n.toString(), 5), "12…90");
});
