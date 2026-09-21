// The drawer is not a section: its title is a line, never an h2, so the
// paste fold's summary is the one heading that names the query and the
// page's h2 list stays the registry's.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { drawer } from "../app/components/drawer.js";

test("the drawer draws its title as a p and no h2 anywhere in its subtree, empty or filled", () => {
  const restore = dom.install();
  try {
    for (const title of ["", "See ProcessRollup2 on real data"]) {
      const el = drawer({ title, subtitle: "crowdstrike:events:sensor" });
      assert.equal(dom.walk(el, (n) => n.tagName === "H2").length, 0, `h2 under the drawer with title "${title}"`);
      const t = el.querySelector(".r-drawer__title");
      assert.ok(t, "the title element");
      assert.equal(t.tagName, "P");
      assert.equal(dom.text(t), title);
    }
  } finally {
    restore();
  }
});

test("setTitle keeps the title a p", () => {
  const restore = dom.install();
  try {
    const el = drawer({});
    el.setTitle("Sample of ProcessRollup2", "crowdstrike:events:sensor");
    assert.equal(el.querySelector(".r-drawer__title").tagName, "P");
    assert.equal(dom.text(el.querySelector(".r-drawer__title")), "Sample of ProcessRollup2");
    assert.equal(dom.walk(el, (n) => n.tagName === "H2").length, 0);
  } finally {
    restore();
  }
});
