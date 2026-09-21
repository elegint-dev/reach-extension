// surface.js: the three widths, from a stubbed matchMedia, and the change
// notification the chrome relies on when the side panel is dragged across
// a breakpoint.

import { test } from "node:test";
import assert from "node:assert/strict";

let width = 1200;
const lists = [];
globalThis.matchMedia = (q) => {
  const max = Number(/max-width:\s*(\d+)px/.exec(q)[1]);
  const listeners = new Set();
  const mql = {
    get matches() {
      return width <= max;
    },
    addEventListener: (_type, fn) => listeners.add(fn),
    fire: () => listeners.forEach((fn) => fn()),
  };
  lists.push(mql);
  return mql;
};
function resize(to) {
  width = to;
  for (const l of lists) l.fire();
}

const { surface, isPanel, isStacked, onSurface, pick, BREAKPOINTS } = await import("../app/lib/surface.js");

test("the boundaries are the ones the stylesheets use", () => {
  assert.equal(BREAKPOINTS.panel, 599);
  assert.equal(BREAKPOINTS.narrow, 899);
});

test("surface() reads the width: wide, narrow, panel", () => {
  width = 1200;
  assert.equal(surface(), "wide");
  assert.equal(isStacked(), false);
  width = 899;
  assert.equal(surface(), "narrow");
  assert.equal(isStacked(), true);
  assert.equal(isPanel(), false);
  width = 599;
  assert.equal(surface(), "panel");
  assert.equal(isPanel(), true);
  width = 320;
  assert.equal(surface(), "panel");
});

test("pick() falls back panel -> narrow -> wide", () => {
  width = 320;
  assert.equal(pick({ wide: "w", panel: "p" }), "p");
  assert.equal(pick({ wide: "w", narrow: "n" }), "n");
  assert.equal(pick({ wide: "w" }), "w");
  width = 700;
  assert.equal(pick({ wide: "w", panel: "p" }), "w");
  assert.equal(pick({ wide: "w", narrow: "n", panel: "p" }), "n");
  width = 1200;
  assert.equal(pick({ wide: "w", narrow: "n", panel: "p" }), "w");
});

test("onSurface fires now and on each crossing, once per crossing", () => {
  width = 1200;
  const seen = [];
  onSurface((s) => seen.push(s));
  assert.deepEqual(seen, ["wide"]);
  resize(700);
  assert.deepEqual(seen, ["wide", "narrow"]);
  resize(380);
  assert.deepEqual(seen, ["wide", "narrow", "panel"]);
  resize(320); // same surface: no call
  assert.deepEqual(seen, ["wide", "narrow", "panel"]);
  resize(1200); // both lists change; one call
  assert.deepEqual(seen, ["wide", "narrow", "panel", "wide"]);
});
