// The notebook page: the title block first with the name as its h1 input,
// one Copy action with a format choice, then Threads (N), Timeline with the
// trigger as its first row, Investigations and Import an investigation, in
// the registry's order.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { ENTITY_ORDER, matcher } from "../app/lib/headings.js";

const restore = dom.install();
const store = await import("../app/lib/store.js");
const modules = await import("../app/lib/modules.js");
const notebook = await import("../app/lib/notebook.js");
const view = await import("../app/views/notebook.js");

const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr", search: { text: "index=fdr", sid: "1" } };
const ctx = { params: {}, navigate() {} };
const settle = () => new Promise((r) => setTimeout(r, 0));
const resolve = matcher();
const h2s = (el) => el.querySelectorAll("h2").map((n) => dom.text(n));
const ids = (el) => h2s(el).map((t) => (resolve(t) || { id: `unregistered: ${t}` }).id);
const isSubsequence = (seq, master) => {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
};

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  modules.reset();
});

test("with a current investigation the title block is first, its h1 is the name input, and the sections run Threads (N), Timeline, Search history (N), Investigations, Import an investigation", async () => {
  await notebook.start({ title: "Handle opens", from });
  await notebook.record({ field: "TemplateDisposition", value: "30", from });
  await notebook.record({ field: "SHA256HashData", value: "8ae63dda1b3f0a2c4d5e6f708192a3b4", from });
  const el = view.render({ ...ctx });
  await settle();
  const first = el.children[0];
  assert.ok(first.classList.contains("r-title"), "the title block is the view's first child");
  assert.equal(first.getAttribute("data-kind"), "notebook");
  const input = first.querySelector("h1").querySelector("input");
  assert.ok(input, "the name is an input inside the h1");
  assert.equal(input.value, "Handle opens");
  assert.equal(dom.text(first.querySelector(".r-title__chips")), "current");
  assert.match(dom.text(first.querySelector(".r-scope")), /^started .* · last change .* · Splunk · index fdr$/);
  const actions = first.querySelector(".r-actions").children.map((n) => dom.text(n.tagName === "SPAN" ? n.querySelector("button") : n));
  assert.deepEqual(actions, ["Copy ▾", "Close", "Start new"]);
  assert.deepEqual(first.querySelector(".r-nb__copymenu").querySelectorAll("button").map((b) => dom.text(b)), ["Markdown", "Plain text"]);
  assert.deepEqual(h2s(el), ["Threads (2)", "Timeline", "Search history (0)", "Investigations", "Import an investigation"]);
  assert.ok(isSubsequence(ids(el), ENTITY_ORDER), `${ids(el)} is a subsequence of the entity master`);
});

test("the trigger input is Timeline's first row and the thread folds carry the held value and its count", async () => {
  await notebook.start({});
  await notebook.record({ field: "TemplateDisposition", value: "30", from });
  const el = view.render({ ...ctx });
  await settle();
  const timeline = el.querySelector(".r-nb__timeline");
  assert.ok(timeline, "the Timeline section is drawn");
  const rows = timeline.children.filter((n) => n.tagName !== "#TEXT");
  assert.equal(rows[0].tagName, "H2");
  assert.equal(rows[1].tagName, "LABEL");
  assert.ok(rows[1].querySelector(".r-nb__trigger"), "the trigger is the first row under the heading");
  assert.equal(rows[2].tagName, "H3", "then the day");
  assert.match(dom.text(el.querySelector(".r-nb__summary")), /^TemplateDisposition = 30 ?1 entry$/);
});

test("with nothing current the title block stands alone with Start one now; Import an investigation is drawn on a default install, share off or on", async () => {
  assert.equal(modules.on("share"), false, "a default install: share is off");
  const el = view.render({ ...ctx });
  await settle();
  const first = el.children[0];
  assert.ok(first.classList.contains("r-title"));
  assert.equal(dom.text(first.querySelector("h1")), "Notebook");
  assert.deepEqual(first.querySelector(".r-actions").querySelectorAll("button").map((b) => dom.text(b)), ["Start one now"]);
  assert.deepEqual(h2s(el), ["Import an investigation"], "the hold module's own paste-back, ungated");
  await modules.setEnabled("share", true);
  const on = view.render({ ...ctx });
  await settle();
  assert.deepEqual(h2s(on), ["Import an investigation"], "share on changes nothing here");
});

test("an investigation that is not current offers Make current on its action row; a closed one offers Reopen", async () => {
  const a = await notebook.start({ title: "A" });
  const b = await notebook.start({ title: "B" });
  assert.equal(notebook.currentId(), b.id);
  const el = view.render({ ...ctx, params: { id: a.id } });
  await settle();
  const labels = el.querySelector(".r-actions").querySelectorAll("button").map((n) => dom.text(n)).filter((t) => !["Markdown", "Plain text"].includes(t));
  assert.deepEqual(labels, ["Copy ▾", "Close", "Start new", "Make current"]);
  await notebook.close(a.id);
  const el2 = view.render({ ...ctx, params: { id: a.id } });
  await settle();
  assert.ok(el2.querySelector(".r-actions").querySelectorAll("button").map((n) => dom.text(n)).includes("Reopen"));
  assert.equal(dom.text(el2.querySelector(".r-title__chips")), "closed");
});

process.on("exit", restore);
