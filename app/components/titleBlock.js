// titleBlock: the first thing in main on every page. What this is (the
// h1), which one (the chip row and the scope line), what to mind (the
// callout slot), the value the page is on (the value line on a field page), and
// what to do next (the action row, always last).
//
//   titleBlock({
//     kind: "field" | "value" | "sourcetype" | "event" | "page" | ...,   data-kind on the block
//     h1: string | Node,                     the name; a long id middle-ellipsizes, the full text in title
//     chips: [Node | string],                the chip row (absent when empty)
//     scope: [Node | string],                the scope line's items, joined with " · " (absent when empty)
//     callout: Node | null,                  at most one, the slot
//     held: Node | null,                     the value line (field page); the click's value, nothing held
//     actions: [Node],                       the action row, last (absent when empty)
//   }) → Element .r-title
//
//   midEllipsis(text, max)                   the middle-ellipsized form of a long name
//
// The block scrolls with the page; the frame's row 1 carries the compact
// title (app.js) so the name stays on screen.

import { h } from "./h.js";

export const H1_MAX = 60;

export function midEllipsis(text, max = H1_MAX) {
  const s = String(text == null ? "" : text);
  if (s.length <= max) return s;
  const keep = Math.max(2, max - 1);
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}

function joined(items, sep) {
  const out = [];
  items.forEach((item, i) => {
    if (i) out.push(h("span", { class: "r-scope__sep", "aria-hidden": "true" }, sep));
    out.push(item);
  });
  return out;
}

export function titleBlock({ kind = "page", h1 = "", chips = [], scope = [], callout = null, held = null, actions = [] } = {}) {
  const chipRow = chips.filter(Boolean);
  const scopeItems = scope.filter(Boolean);
  const actionRow = actions.filter(Boolean);
  const name = typeof h1 === "string" ? h1 : null;
  const title = name === null ? h1 : midEllipsis(name);
  return h(
    "div",
    { class: "r-title", dataset: { kind } },
    h("h1", { class: "r-title__h1", title: name !== null && title !== name ? name : null }, title),
    chipRow.length ? h("div", { class: "r-title__chips" }, chipRow) : null,
    scopeItems.length ? h("p", { class: "r-scope" }, joined(scopeItems, " · ")) : null,
    callout ? h("div", { class: "r-title__callout" }, callout) : null,
    held ? h("p", { class: "r-title__held" }, held) : null,
    actionRow.length ? h("div", { class: "r-actions" }, actionRow) : null,
  );
}

export default titleBlock;
