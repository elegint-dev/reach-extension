// The start page: the title block first, the sections in the tool master's
// order, and a Tools line for every non-core tool route: a link while the
// module is on, "<Module> · off · Settings" while it is off, so the way to
// turn Share on is on screen and no other link to #/share exists.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as fields from "../app/lib/pack-fields.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as modules from "../app/lib/modules.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";
import { render, TOOL_ROUTES } from "../app/views/start.js";

const restore = dom.install();
await catalogue.load();
const resolve = matcher();
const ctx = { fields, catalogue, params: {}, cards: [], openSettings() {}, focusSearch() {} };
const links = (el, href) => el.querySelectorAll("a").filter((a) => a.getAttribute("href") === href);
const isSubsequence = (seq, master) => {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
};

test("counts() carries the routes object on the empty bundle, so unknown.js never reads a route count off undefined", () => {
  const c = fields.counts();
  assert.equal(c.routes.unobserved, 0);
  assert.equal(c.fields, 0);
  assert.equal(c.edges_confirmed, 0);
});

test("the title block comes first with the platform and the two counts as its scope, and every h2 is a registry entry in the tool master's order", () => {
  const el = render(ctx);
  const first = el.children[0];
  assert.ok(first.classList.contains("r-title"));
  assert.equal(dom.text(first.querySelector("h1")), "Reach");
  assert.match(dom.text(first.querySelector(".r-scope")), /^Microsoft Sentinel · \d+ tables? · \d+ packs?$/);
  assert.ok(first.querySelector(".r-actions"), "an action row");
  const ids = el.querySelectorAll("h2").map((n) => (resolve(dom.text(n)) || { id: `unregistered: ${dom.text(n)}` }).id);
  assert.ok(ids.every((id) => !id.startsWith("unregistered")), ids.join(", "));
  assert.ok(isSubsequence(ids, TOOL_ORDER), `${ids} follows the tool master`);
  assert.equal(dom.text(el).includes("What a page looks like"), false, "the mock page is gone");
});

test("Tools lists every tool route's module: Discover and Coverage as links, Share (off by default) as its off line with a Settings link, and nothing else links to #/share", () => {
  modules.reset();
  const el = render(ctx);
  const tools = el.querySelector(".r-tools");
  assert.ok(tools, "a Tools section");
  const lines = tools.querySelectorAll("li").map((li) => dom.text(li));
  assert.equal(lines.length, TOOL_ROUTES.length);
  assert.equal(lines[0], "Discover");
  assert.equal(lines[1], "Coverage");
  assert.equal(lines[2], "Share and import · off · Settings");
  assert.equal(links(tools, "#/discover").length, 1);
  assert.equal(links(el, "#/share").length, 0, "no link to the unmounted route");
  const settings = tools.querySelectorAll("li")[2].querySelector("a");
  assert.equal(dom.text(settings), "Settings");
  let opened = null;
  const el2 = render({ ...ctx, openSettings: (id) => (opened = id) });
  dom.fire(el2.querySelector(".r-tool--off").querySelector("a"), "click");
  assert.equal(opened, "share", "the Settings link opens the fold on the module's head");
});

test("the teach-state prompt asks what you are looking at, not what you are holding: the word is the rail's alone", () => {
  const el = render(ctx);
  const title = el.querySelector(".r-empty__title");
  assert.equal(dom.text(title), "What are you looking at?");
  const line = el.querySelector(".r-empty__line");
  assert.doesNotMatch(dom.text(line), /\bholding\b/i);
});

process.on("exit", restore);
