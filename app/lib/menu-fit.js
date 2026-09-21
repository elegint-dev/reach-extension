// A Reach section under a host's own menu (Splunk's value popup, the
// blade's ag-Grid menu): the host's menu is never moved, resized or
// restyled. The section mounts inside the menu only when its natural
// height (capped) fits between the menu's own items and the bottom of the
// viewport (or of the layer that clips the menu); otherwise it opens as
// Reach's own panel beside the menu (popup-ui.js anchoredPanel), placed by
// besideMenu() below. Page scroll is never the answer: Splunk closes its
// popup on it.
//
// The wheel over the section stays on the section. The host may cancel
// wheel events on the way down (the blade does, so its grid can own them),
// which leaves the section's scrollbar draggable but the wheel dead; when
// that has happened by the time the event reaches the section, the scroll
// is applied by hand.

const LINE_PX = 16;
const PANEL_WIDTH = 560;

// Pure: whether a section of `wanted` natural height fits under the host's
// own items, and the height it gets there.
//   top             the menu's top edge
//   itemsHeight     the host's own items above the section
//   viewportHeight  the frame's inner height
//   limit           bottom edge of the layer that clips the menu, if any
//   cap             fraction of the viewport the section may take
//   wanted          the section's natural height
// → { fits, maxHeight }: fits when min(wanted, cap) is no taller than the
// room; maxHeight is that capped height (the room itself when it does
// not fit, for a caller that mounts inline regardless).
export function fitBelow({ top, itemsHeight, viewportHeight, limit = viewportHeight, margin = 8, cap = 1, wanted = 0 }) {
  const bottom = Math.min(viewportHeight, limit) - margin;
  const room = Math.max(0, bottom - top - itemsHeight);
  const target = Math.round(Math.min(wanted, viewportHeight * cap));
  const fits = target <= room;
  return { fits, maxHeight: Math.round(fits ? target : room) };
}

// Pure: where Reach's own panel goes beside a host menu it must not move.
//   menu            the menu's viewport rect { top, right, bottom, left }
//   viewportWidth, viewportHeight
//   height          the section's natural height
//   cap             fraction of the viewport the panel may take
// The panel is as wide as an inline section (min(560px, viewport - 32)),
// sits at the menu's right edge, or at its left edge when the right has no
// room for that width (against the left margin when neither side has),
// with its top at the menu's top. Its height is min(height, cap) and
// never past the viewport's bottom: when the menu's top leaves less room
// than that, the panel's top rises just far enough, never above the
// margin. Whatever does not fit scrolls inside the panel.
export function besideMenu({ menu, viewportWidth, viewportHeight, height = 0, cap = 0.7, gap = 8, margin = 8 }) {
  const width = Math.min(PANEL_WIDTH, viewportWidth - 4 * margin);
  const rightRoom = viewportWidth - margin - (menu.right + gap);
  const side = rightRoom >= width ? "right" : "left";
  const left = side === "right" ? menu.right + gap : Math.max(margin, menu.left - gap - width);
  const want = Math.round(Math.min(height, viewportHeight * cap));
  const bottom = viewportHeight - margin;
  const top = Math.max(margin, Math.min(menu.top, bottom - want));
  const maxHeight = Math.max(0, Math.min(want, bottom - top));
  return { side, left: Math.round(left), top: Math.round(top), width: Math.round(width), maxHeight: Math.round(maxHeight) };
}

// Pure: which side of a host popdown Reach's flyout takes, the popdown
// staying where the host put it: its right when the viewport has room for
// the flyout there, else its left, else below it.
export function flyoutSide({ menu, viewportWidth, width, gap = 12, margin = 12 }) {
  if (viewportWidth - margin - (menu.right + gap) >= width) return "right";
  if (menu.left - gap - margin >= width) return "left";
  return "below";
}

// Pure: where a wheel of `delta` pixels leaves a scroller, and whether the
// scroller takes the event at all (it does whenever it can scroll, at
// either end included: the host page must not scroll instead).
export function wheelStep({ scrollTop, scrollHeight, clientHeight }, delta) {
  const max = Math.max(0, scrollHeight - clientHeight);
  if (max <= 1) return { scrollTop, consumed: false, moved: false };
  const next = Math.max(0, Math.min(max, scrollTop + delta));
  return { scrollTop: next, consumed: true, moved: next !== scrollTop };
}

export function wheelDelta(e, el) {
  if (e.deltaMode === 1) return e.deltaY * LINE_PX;
  if (e.deltaMode === 2) return e.deltaY * (el.clientHeight || LINE_PX);
  return e.deltaY;
}

// The innermost scroller under the pointer that still moves for this
// wheel (a code block with its own scrollbar), else the section itself.
function scrollerFor(start, root, delta, isScroller) {
  for (let n = start; n && n !== root; n = n.parentElement) {
    if (isScroller(n) && wheelStep(n, delta).moved) return n;
  }
  return root;
}

// Wires the section's scroll container. Returns the handler for tests.
//   isScroller(el)  whether an inner element scrolls on its own (DOM: the
//                   computed overflow-y); defaults to none
export function ownWheel(el, { isScroller = () => false } = {}) {
  const onWheel = (e) => {
    const delta = wheelDelta(e, el);
    const target = scrollerFor(e.target, el, delta, isScroller);
    const step = wheelStep(target, delta);
    if (!step.consumed) return; // nothing to scroll here: the host keeps the event
    e.stopImmediatePropagation();
    if (e.defaultPrevented) {
      // Cancelled above the section: the native scroll will not happen.
      target.scrollTop = step.scrollTop;
      return;
    }
    if (!step.moved) e.preventDefault(); // at an end: no chaining into the host page
  };
  el.addEventListener("wheel", onWheel, { capture: true, passive: false });
  return onWheel;
}

// DOM isScroller for ownWheel.
export function scrollsOnItsOwn(n) {
  if (!(n instanceof Element)) return false;
  const oy = getComputedStyle(n).overflowY;
  return (oy === "auto" || oy === "scroll") && n.scrollHeight > n.clientHeight + 1;
}

// Pure: the settings bar's "always open Reach beside the menu" toggle
// (Sentinel only; Splunk's popup has no equivalent slot to skip): the
// panel regardless of room. With it off, fitBelow decides.
export function usePanel({ alwaysPanel = false } = {}) {
  return Boolean(alwaysPanel);
}

export default { fitBelow, besideMenu, flyoutSide, wheelStep, wheelDelta, ownWheel, scrollsOnItsOwn, usePanel };
