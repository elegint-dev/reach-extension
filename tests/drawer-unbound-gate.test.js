// A $NAME$ placeholder in the drawer's text is not a search to copy or
// run: while the generator reports a parameter unbound, Copy is disabled
// with a reason naming it, the run link gives way to the same line, and a
// fill with every parameter bound frees both. The pack pivots default the
// window (earliest) from the pack's own placeholder, so scenario 4's first
// row renders -24h with the input still drawn, prefilled.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { drawer, fillFrom, unboundReason } from "../app/components/drawer.js";
import { windowDefaults } from "../app/components/packPivots.js";

// The run link needs a Splunk base URL from Settings, read off localStorage.
const mem = new Map();
Object.defineProperty(globalThis, "localStorage", { value: { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) }, configurable: true, writable: true });
const settings = await import("../app/lib/settings.js");

const runLink = (el) => el.querySelector(".r-drawer__run");
const runHint = (el) => el.querySelector(".r-drawer__runhint");
const copyBtn = (el) => el.querySelector(".r-drawer__copy");

test("unboundReason names the unbound parameters by their input labels and is empty when nothing is", () => {
  assert.equal(unboundReason([]), "");
  assert.equal(unboundReason(["earliest"]), "earliest is unbound: fill it in above.");
  assert.equal(unboundReason(["earliest", "index"], [{ name: "earliest", label: "since" }]), "since, index are unbound: fill them in above.");
});

test("a fill that reports earliest unbound disables Copy with the reason and hides the run link behind it; a bound refill frees both", () => {
  const restore = dom.install();
  try {
    settings.setSplunkBase("https://splunk.example.com:8000");
    const el = drawer({});
    el.fill({ title: "t", spl: "search index=main earliest=$earliest$", params: [{ name: "earliest", label: "earliest", required: true }], missing: ["earliest"] });
    assert.equal(copyBtn(el).disabled, true, "Copy waits");
    assert.match(copyBtn(el).title, /^Not copied: earliest is unbound/);
    assert.equal(runLink(el).hidden, true, "no run link with a placeholder in the text");
    assert.equal(runHint(el).hidden, false);
    assert.match(dom.text(runHint(el)), /No run link yet: earliest is unbound/);
    el.fill({ title: "t", spl: "search index=main earliest=-24h", missing: [] });
    assert.equal(copyBtn(el).disabled, false, "Copy once bound");
    assert.equal(copyBtn(el).title, "");
    assert.equal(runLink(el).hidden, false, "the run link once bound");
    assert.match(runLink(el).href, /q=search%20index%3Dmain%20earliest%3D-24h/);
  } finally {
    settings.setSplunkBase("");
    restore();
  }
});

test("fillFrom hands the generator's missing list to the drawer", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    fillFrom(el, { title: "t", params: (out) => out.missing.map((n) => ({ name: n })) }, () => ({ spl: "a=$aid$", missing: ["aid"], hazards: [] }));
    assert.equal(copyBtn(el).disabled, true);
    assert.match(copyBtn(el).title, /aid is unbound/);
    fillFrom(el, { title: "t" }, () => ({ spl: "a=1", missing: [], hazards: [] }), false);
    assert.equal(copyBtn(el).disabled, false);
  } finally {
    restore();
  }
});

test("the pack's earliest placeholder is the window a pivot opens on; nothing else is defaulted", () => {
  assert.deepEqual(windowDefaults({ earliest: { placeholder: "-24h" }, aid: { placeholder: "32-hex agent id" } }), { earliest: "-24h" });
  assert.deepEqual(windowDefaults({ aid: { placeholder: "32-hex agent id" } }), {});
  assert.deepEqual(windowDefaults(null), {});
});
