// menu-fit.js: whether a section fits under a host's menu, where Reach's
// own panel goes beside it when it does not, and the wheel over the section.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fitBelow, besideMenu, flyoutSide, wheelStep, wheelDelta, ownWheel, usePanel } from "../app/lib/menu-fit.js";

test("usePanel: the always-panel toggle takes the panel regardless of room", () => {
  assert.equal(usePanel({ alwaysPanel: true }), true);
  assert.equal(usePanel({ alwaysPanel: false }), false);
});

test("usePanel: defaults to staying in the menu when nothing is passed", () => {
  assert.equal(usePanel(), false);
  assert.equal(usePanel({}), false);
});

test("fitBelow: a section whose natural height fits under the menu's items mounts there at that height", () => {
  const r = fitBelow({ top: 100, itemsHeight: 135, viewportHeight: 779, wanted: 400 });
  assert.deepEqual(r, { fits: true, maxHeight: 400 });
});

test("fitBelow: the cap, not the natural height, is what must fit", () => {
  const r = fitBelow({ top: 100, itemsHeight: 135, viewportHeight: 900, cap: 0.6, wanted: 900 });
  assert.deepEqual(r, { fits: true, maxHeight: 540 });
});

test("fitBelow: a menu halfway down with a tall section does not fit, and the menu is never asked to move", () => {
  const r = fitBelow({ top: 480, itemsHeight: 135, viewportHeight: 779, cap: 0.7, wanted: 500 });
  assert.equal(r.fits, false);
  assert.equal(r.maxHeight, 156, "the room that was there, for a caller that mounts inline anyway");
  assert.equal("shift" in r, false);
});

test("fitBelow: a clipping layer bounds the room below", () => {
  assert.equal(fitBelow({ top: 300, itemsHeight: 40, viewportHeight: 900, limit: 700, cap: 0.6, wanted: 352 }).fits, true);
  assert.equal(fitBelow({ top: 300, itemsHeight: 40, viewportHeight: 900, limit: 700, cap: 0.6, wanted: 353 }).fits, false);
});

test("besideMenu: the panel sits at the menu's right edge and top, as wide as an inline section, capped", () => {
  const menu = { top: 450, right: 500, bottom: 585, left: 220 };
  const r = besideMenu({ menu, viewportWidth: 1280, viewportHeight: 900, height: 300, cap: 0.7 });
  assert.deepEqual(r, { side: "right", left: 508, top: 450, width: 560, maxHeight: 300 });
});

test("besideMenu: no room on the right puts the panel at the menu's left edge", () => {
  const menu = { top: 200, right: 1100, bottom: 335, left: 820 };
  const r = besideMenu({ menu, viewportWidth: 1280, viewportHeight: 900, height: 300 });
  assert.equal(r.side, "left");
  assert.equal(r.left, 820 - 8 - 560);
  assert.equal(r.top, 200);
});

test("besideMenu: a narrow viewport narrows the panel to the viewport less the margins", () => {
  const r = besideMenu({ menu: { top: 10, right: 300, bottom: 100, left: 100 }, viewportWidth: 400, viewportHeight: 600, height: 200 });
  assert.equal(r.width, 400 - 32);
  assert.equal(r.left, 8, "neither side has room: against the left margin");
});

test("besideMenu: a menu low in the viewport lifts the panel's top only as far as the capped height needs, never above the margin", () => {
  const low = besideMenu({ menu: { top: 800, right: 500, bottom: 900, left: 220 }, viewportWidth: 1280, viewportHeight: 900, height: 700, cap: 0.7 });
  assert.equal(low.maxHeight, 630, "70vh of 900");
  assert.equal(low.top, 900 - 8 - 630);
  const tall = besideMenu({ menu: { top: 800, right: 500, bottom: 900, left: 220 }, viewportWidth: 1280, viewportHeight: 300, height: 700, cap: 1 });
  assert.equal(tall.top, 8);
  assert.equal(tall.maxHeight, 300 - 16);
});

test("flyoutSide: the flyout takes the popdown's right when the viewport has room, else its left, else below; the popdown never moves", () => {
  const popdown = (left) => ({ top: 60, left, right: left + 600, bottom: 400 });
  assert.equal(flyoutSide({ menu: popdown(20), viewportWidth: 1280, width: 440 }), "right");
  assert.equal(flyoutSide({ menu: popdown(488), viewportWidth: 1100, width: 440 }), "left");
  assert.equal(flyoutSide({ menu: popdown(388), viewportWidth: 1000, width: 440 }), "below");
  assert.equal(flyoutSide({ menu: popdown(216), viewportWidth: 1280, width: 440 }), "right", "exactly enough room on the right is room");
});

test("wheel moves a scroller and stops at either end without releasing the event", () => {
  const box = { scrollTop: 0, scrollHeight: 500, clientHeight: 100 };
  assert.deepEqual(wheelStep(box, 60), { scrollTop: 60, consumed: true, moved: true });
  assert.deepEqual(wheelStep({ ...box, scrollTop: 380 }, 60), { scrollTop: 400, consumed: true, moved: true });
  assert.deepEqual(wheelStep({ ...box, scrollTop: 400 }, 60), { scrollTop: 400, consumed: true, moved: false });
  assert.deepEqual(wheelStep({ ...box, scrollTop: 0 }, -60), { scrollTop: 0, consumed: true, moved: false });
});

test("a section that fits leaves the wheel to the host", () => {
  assert.equal(wheelStep({ scrollTop: 0, scrollHeight: 100, clientHeight: 100 }, 60).consumed, false);
});

test("line and page deltas become pixels", () => {
  const el = { clientHeight: 300 };
  assert.equal(wheelDelta({ deltaY: 3, deltaMode: 1 }, el), 48);
  assert.equal(wheelDelta({ deltaY: 1, deltaMode: 2 }, el), 300);
  assert.equal(wheelDelta({ deltaY: 42, deltaMode: 0 }, el), 42);
});

function fakeBox(props) {
  const box = Object.assign({ scrollTop: 0, scrollHeight: 500, clientHeight: 100, parentElement: null, wired: null }, props);
  box.addEventListener = (type, fn, opts) => { box.wired = { type, fn, opts }; };
  return box;
}
function fakeWheel(target, deltaY, cancelled = false) {
  const e = { deltaY, deltaMode: 0, target, defaultPrevented: cancelled, stopped: false };
  e.preventDefault = () => { e.defaultPrevented = true; };
  e.stopImmediatePropagation = () => { e.stopped = true; };
  return e;
}

test("the listener is registered capturing and cancelable", () => {
  const box = fakeBox();
  ownWheel(box);
  assert.deepEqual(box.wired.opts, { capture: true, passive: false });
});

test("an event the host has not cancelled scrolls natively and goes no further", () => {
  const box = fakeBox();
  const on = ownWheel(box);
  const e = fakeWheel(box, 60);
  on(e);
  assert.equal(e.stopped, true);
  assert.equal(e.defaultPrevented, false);
  assert.equal(box.scrollTop, 0);
});

test("an event the host cancelled on the way down is applied by hand", () => {
  const box = fakeBox({ scrollTop: 40 });
  const on = ownWheel(box);
  const e = fakeWheel(box, 60, true);
  on(e);
  assert.equal(e.stopped, true);
  assert.equal(box.scrollTop, 100);
});

test("at the end of the section the event does not chain into the host page", () => {
  const box = fakeBox({ scrollTop: 400 });
  const on = ownWheel(box);
  const e = fakeWheel(box, 60);
  on(e);
  assert.equal(e.defaultPrevented, true);
  assert.equal(e.stopped, true);
});

test("a section that fits lets the event through to the host", () => {
  const box = fakeBox({ scrollHeight: 100 });
  const on = ownWheel(box);
  const e = fakeWheel(box, 60);
  on(e);
  assert.equal(e.stopped, false);
  assert.equal(e.defaultPrevented, false);
});

test("an inner code block that still scrolls takes the event before the section", () => {
  const box = fakeBox({ scrollTop: 0 });
  const code = fakeBox({ scrollTop: 0, scrollHeight: 300, clientHeight: 100, parentElement: box });
  const on = ownWheel(box, { isScroller: (n) => n === code });
  on(fakeWheel(code, 50, true));
  assert.equal(code.scrollTop, 50);
  assert.equal(box.scrollTop, 0);
  code.scrollTop = 200;
  on(fakeWheel(code, 50, true));
  assert.equal(code.scrollTop, 200);
  assert.equal(box.scrollTop, 50);
});
