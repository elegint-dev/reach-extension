// The drawer fills from one call (fill, fail) and fillFrom holds the one
// error branch: a query error fails the drawer, any other error propagates.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { drawer, fillFrom } from "../app/components/drawer.js";
import { SplError } from "../app/lib/spl.js";

const inputs = (el) => dom.walk(el, (n) => n.tagName === "INPUT").map((n) => n.attributes.name);

test("fill renders the query, its inputs, hazards and macro status in one call and lands on filled", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    el.fill({
      title: "See ProcessRollup2 on real data",
      subtitle: "crowdstrike:events:sensor",
      spl: "index=$index$ aid=$aid$",
      macro: "`cs_index` aid=$aid$",
      params: [{ name: "aid", required: true }],
      hazards: [{ level: "caution", text: "wide window" }],
      macros: { macro: { env: "https://splunk.example", needed: [{ name: "cs_index", defined: false }] } },
    });
    assert.ok(el.classList.contains("r-drawer--filled"));
    assert.equal(dom.text(el.querySelector(".r-drawer__title")), "See ProcessRollup2 on real data");
    assert.equal(dom.text(el.querySelector(".r-spl__code")), "index=$index$ aid=$aid$");
    assert.deepEqual(inputs(el), ["aid"]);
    assert.match(dom.text(el.querySelector(".r-drawer__hazards")), /wide window/);
    el.showTab("macro");
    assert.equal(dom.text(el.querySelector(".r-spl__code")), "`cs_index` aid=$aid$");
    assert.match(dom.text(el.querySelector(".r-drawer__macros")), /cs_index/);
  } finally {
    restore();
  }
});

test("a fill without params keeps the inputs a keystroke refill is typing into; [] clears them", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    el.fill({ title: "t", spl: "a=$value$", params: [{ name: "value" }] });
    const before = dom.walk(el, (n) => n.tagName === "INPUT")[0];
    el.fill({ title: "t", spl: "a=1" });
    assert.equal(dom.walk(el, (n) => n.tagName === "INPUT")[0], before, "the same input node survives the refill");
    el.fill({ title: "t", spl: "a=1", params: [] });
    assert.deepEqual(inputs(el), []);
  } finally {
    restore();
  }
});

test("fail shows the error with no text, no hazards and no macro status left from the last fill", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    el.fill({ title: "t", spl: "a=1", hazards: [{ level: "note", text: "h" }], macros: { inline: { env: "e", needed: [{ name: "m", defined: true }] } } });
    el.fail({ title: "t", subtitle: "s", params: [{ name: "aid" }], error: { code: "unscoped_pid", text: "bind aid" } });
    assert.ok(el.classList.contains("r-drawer--error"));
    assert.match(dom.text(el.querySelector(".r-drawer__error")), /unscoped PID/);
    assert.match(dom.text(el.querySelector(".r-drawer__error")), /bind aid/);
    assert.equal(dom.text(el.querySelector(".r-spl__code")), "");
    assert.equal(el.querySelector(".r-drawer__hazards").hidden, true);
    assert.equal(el.querySelector(".r-drawer__macros").hidden, true);
    assert.deepEqual(inputs(el), ["aid"]);
  } finally {
    restore();
  }
});

test("a fill after a fill with macro status clears it: no macro row leaks into the next query", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    el.fill({ title: "t", spl: "a=1", macros: { inline: { env: "e", needed: [{ name: "m", defined: false }] } } });
    assert.equal(el.querySelector(".r-drawer__macros").hidden, false);
    assert.equal(el.querySelector(".r-drawer__copy").disabled, true, "a missing macro blocks Copy");
    el.fill({ title: "t", spl: "b=2" });
    assert.equal(el.querySelector(".r-drawer__macros").hidden, true);
    assert.equal(el.querySelector(".r-drawer__copy").disabled, false);
  } finally {
    restore();
  }
});

test("fillFrom fills from the generator's output, with the spec's inputs and notes only on a rebuild", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    const spec = { title: "t", subtitle: "s", params: (out) => out.missing.map((n) => ({ name: n })), notes: (out) => [{ level: "note", text: `on ${out.sourcetype}` }] };
    const out = fillFrom(el, spec, () => ({ spl: "x=$aid$", missing: ["aid"], hazards: [], sourcetype: "st" }));
    assert.equal(out.spl, "x=$aid$");
    assert.deepEqual(inputs(el), ["aid"]);
    assert.match(dom.text(el.querySelector(".r-drawer__hazards")), /on st/);
    const seen = dom.walk(el, (n) => n.tagName === "INPUT")[0];
    fillFrom(el, spec, () => ({ spl: "x=1", missing: [], hazards: [], sourcetype: "st" }), false);
    assert.equal(dom.walk(el, (n) => n.tagName === "INPUT")[0], seen, "a refill leaves the inputs");
    assert.equal(dom.text(el.querySelector(".r-spl__code")), "x=1");
  } finally {
    restore();
  }
});

test("fillFrom fails the drawer on a query error with the spec's words and inputs, and lets any other error through", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    const spec = { title: "t", errorParams: () => [{ name: "aid" }], errorText: (err) => `needs a host (${err.message})` };
    const out = fillFrom(el, spec, () => {
      throw new SplError("unscoped_pid", "pid alone");
    });
    assert.equal(out, null);
    assert.ok(el.classList.contains("r-drawer--error"));
    assert.match(dom.text(el.querySelector(".r-drawer__error")), /needs a host \(pid alone\)/);
    assert.deepEqual(inputs(el), ["aid"]);
    assert.throws(
      () =>
        fillFrom(el, spec, () => {
          throw new TypeError("a bug");
        }),
      TypeError,
    );
    fillFrom(el, { title: "t", catchAll: true }, () => {
      throw new TypeError("anything");
    });
    assert.match(dom.text(el.querySelector(".r-drawer__error")), /anything/);
  } finally {
    restore();
  }
});
