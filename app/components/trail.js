// trail: the frame's second row. The investigation's entity hops only
// (sourcetype, field, value, event, and a runbook opened from an alert
// row) oldest first, up to the last three: 936 › 255667414 › 5497396. The
// stack (navstack.js) keeps every navigation; this renders a filtered
// read of it, so a tool page (share, notebook, discover, coverage, packs,
// search, start, a runbook opened from the nav) between two entity hops
// never adds a chip, and two entity hops either side of one collapse to
// their own two chips, not three. Consecutive entries for the same page
// (by hash) count once. A hop is a row the analyst clicked in, not a
// click: clicks in the same row update that hop's chip in place
// (navstack.js). A hop that carried a value reads container · record
// type · value when the chip's budget takes it, else the longest tail of
// that which does, else the value alone; its title is field=value on
// sourcetype · record type. Any other hop reads its name. An entry is
// { hash, kind, name, field, value, st, on, entity } as app.js labels it.
// The chip for the page actually open is the tail, unlinked and marked
// current; when the open page is a tool page (no entity hops between it
// and the last one) every chip is a link back to a past hop. The row is
// absent when there are no entity hops yet. One line, never wraps; a chip
// middle-ellipsizes with the full name in title. A chip click is a new
// hop (the router advances), never a move along the stack.
//
//   const t = trail();  t.update(navState)
//
//   chipLabel(entry, max) → { text, title }   what a stack entry reads as
//                                             inside a budget of max characters

import { h, replace } from "./h.js";
import { midEllipsis } from "./titleBlock.js";

// Characters a chip carries before the middle-ellipsis: 80px at 320 and
// 104px at 380, at 7.2px per character plus padding (components.css).
export const CHIP_MAX = { narrow: 9, wide: 12 };
export const HOPS = 3;

function chipMax() {
  const w = typeof window !== "undefined" && window.innerWidth ? window.innerWidth : 0;
  return w && w < 360 ? CHIP_MAX.narrow : CHIP_MAX.wide;
}

export function chipLabel(entry, max = chipMax()) {
  const name = entry.name || entry.hash || "";
  if (entry.value) {
    const value = String(entry.value);
    const where = entry.st ? ` on ${entry.st}` : "";
    const type = entry.on ? ` · ${entry.on}` : "";
    return { text: hopText(entry, max), title: entry.field ? `${entry.field}=${value}${where}${type}` : `${value}${where}${type}` };
  }
  return { text: String(name), title: String(name) };
}

function hopText(entry, max) {
  const parts = [entry.st, entry.on, String(entry.value)].filter(Boolean);
  for (let i = 0; i < parts.length - 1; i++) {
    const text = parts.slice(i).join(" · ");
    if (text.length <= max) return text;
  }
  return String(entry.value);
}

// The stack's entity hops up to the current position, oldest first,
// consecutive same-hash entries collapsed to the later one, then capped
// to the last n. Each carries atPos: true when it is the entry the panel
// is actually showing, so a tool page open right now (no entity hop of
// its own) leaves every chip a link back, none marked current.
function entityHops(state, n) {
  const list = [];
  for (let i = 0; i <= state.pos; i++) {
    const entry = state.stack[i];
    if (!entry || !entry.entity) continue;
    const atPos = i === state.pos;
    if (list.length && list[list.length - 1].entry.hash === entry.hash) list[list.length - 1] = { entry, atPos };
    else list.push({ entry, atPos });
  }
  return list.slice(-n);
}

export function trail() {
  const el = h("nav", { class: "r-trail", "aria-label": "Trail" });
  el.update = (state) => {
    const hops = entityHops(state, HOPS);
    el.hidden = hops.length === 0;
    const chips = [];
    hops.forEach(({ entry, atPos }, i) => {
      const max = chipMax();
      const { text, title } = chipLabel(entry, max);
      const short = midEllipsis(text, max);
      if (i) chips.push(h("span", { class: "r-trail__sep", "aria-hidden": "true" }, "›"));
      chips.push(
        h(
          atPos ? "span" : "a",
          { class: ["r-trail__chip", atPos && "r-trail__chip--here"], href: atPos ? null : entry.hash, title: title !== short ? title : null, "aria-current": atPos ? "page" : null, dataset: { kind: entry.kind || "page" } },
          short,
        ),
      );
    });
    replace(el, chips);
  };
  return el;
}

export default trail;
