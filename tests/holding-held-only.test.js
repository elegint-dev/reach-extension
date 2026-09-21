// The Holding component lists what the analyst held or pinned, never what
// was merely clicked: a click is a hop on the trail, Hold is what puts a
// value here. The frame's line carries the count and the values.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { holding, heldPins } from "../app/components/holding.js";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
const pinned = await import("../app/lib/pinned.js");

const restore = dom.install();
const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr" };

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  investigation.clear();
  pinned.clear();
});

const chips = (el) => el.querySelectorAll(".r-holding__chip").map((c) => dom.text(c).replace(/(unpin|×)+$/, ""));
const settle = () => new Promise((r) => setTimeout(r, 0));

test("a clicked value draws no chip and counts for nothing; the empty line says Hold", async () => {
  const el = holding();
  investigation.set("aid", "abc123");
  await settle();
  assert.deepEqual(chips(el), []);
  assert.equal(el.count(), 0);
  assert.ok(el.classList.contains("r-holding--empty"));
  assert.match(dom.text(el.querySelector(".r-holding__facts")), /Hold/);
  assert.equal(dom.text(el).includes("This tab"), false);
});

test("a held value (Hold, or the Add form) is listed with its provenance, and the frame's line reads Holding N with the values", async () => {
  const el = holding();
  await notebook.record({ field: "SHA256HashData", value: "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4", from });
  await settle();
  assert.deepEqual(heldPins().map((e) => e.field), ["SHA256HashData"]);
  assert.equal(el.count(), 1);
  assert.ok(!el.classList.contains("r-holding--empty"));
  assert.deepEqual(chips(el).map((t) => t.split("=")[0]), ["SHA256HashData"]);
  const chip = el.querySelector(".r-holding__chip");
  assert.match(chip.getAttribute("title"), /on crowdstrike:events:sensor/);
  assert.match(chip.querySelector("a").getAttribute("href"), /^#\/v\/8ae6.*name=SHA256HashData$/, "a held chip opens the value page");
  const line = el.querySelector(".r-holding__line");
  assert.equal(dom.text(line.querySelector(".r-holding__count")), "1");
  assert.match(dom.text(line.querySelector(".r-holding__summary")), /^SHA256HashData=8ae6.*a3b4$/);
});

test("a long held value middle-ellipsizes in the rail's list with the full value in title, like the frame's line", async () => {
  const el = holding();
  const hash = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
  await notebook.record({ field: "SHA256HashData", value: hash, from });
  pinned.set("aid", "abc123");
  await settle();
  const vals = el.querySelectorAll(".r-holding__val");
  const shown = vals.map((v) => dom.text(v));
  assert.equal(shown[0].length, 20);
  assert.match(shown[0], /^8ae63dda1b…/);
  assert.match(shown[0], /8192a3b4$/);
  assert.equal(vals[0].getAttribute("title"), hash);
  assert.equal(shown[1], "abc123");
  assert.equal(vals[1].getAttribute("title"), null);
  const link = el.querySelector(".r-holding__link");
  assert.equal(link.parentNode.getAttribute("title"), `SHA256HashData=${hash} on crowdstrike:events:sensor in fdr`);
});

test("pinned values count beside held ones, and the same value held twice is one chip", async () => {
  const el = holding();
  pinned.set("aid", "abc123");
  await notebook.record({ field: "TemplateDisposition", value: "30", from });
  await notebook.record({ field: "TemplateDisposition", value: "30", from, reason: "again" });
  await settle();
  assert.equal(el.count(), 2);
  assert.deepEqual(chips(el).sort(), ["TemplateDisposition=30", "aid=abc123"]);
  assert.equal(dom.text(el.querySelector(".r-holding__summary")), "TemplateDisposition=30 · aid=abc123");
});

test("the line opens the rail in place and says so", async () => {
  const el = holding();
  pinned.set("aid", "abc123");
  await settle();
  const line = el.querySelector(".r-holding__line");
  assert.equal(line.getAttribute("aria-expanded"), "false");
  dom.fire(line, "click");
  assert.ok(el.classList.contains("is-open"));
  assert.equal(line.getAttribute("aria-expanded"), "true");
  dom.fire(line, "click");
  assert.ok(!el.classList.contains("is-open"));
});

test("the component and its copy never name a per-tab strip", async () => {
  const { readFileSync } = await import("node:fs");
  for (const f of ["app/components/holding.js", "app/lib/copy.js"]) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), "utf8");
    assert.doesNotMatch(src, /This tab|Clear tab/, f);
  }
});

process.on("exit", restore);
