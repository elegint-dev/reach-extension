// One band of a popup section, and the walk that assembles them. Every
// surface (the two Splunk popups, the Sentinel grid, the app's value page)
// draws its bands through walkBands, so the titles and the folds never drift.
//
//   BAND_HEADING                      band id → heading registry id, for the bands that carry a title
//   bandTitle(id, n, platform)        the registry string for a band, under the platform's words
//   band(id, { el, n, fold, platform }) → Element | null
//       the block under its registry title, or a fold whose summary carries it
//   plan(bands, has) → [id]
//       the ids a walk draws for a band list and a presence test, value
//       folded into meaning; the value page's section loop reads the same
//   walkBands(bands, draw, { platform }) → [Element]
//       `bands` is modules.bands(platform) (modules.js BANDS, the off
//       modules gone), draw(id) answers null, an element drawn as is (the
//       head's parts), or { el, n, fold } for a section, which is wrapped
//       under its registry title; value and meaning are one band
//   foldBlock(label, el) → Element | null
//       a secondary band, closed by default, under a label of the caller's
//   SENTINEL_PIVOTS_LINE, SENTINEL_PIVOTS_LINE_PAGE, SENTINEL_NO_PIVOTS_NOTE
//       the Sentinel lines where the workflow module never mounts
//
// DOM module (uses h.js). Never fetches.

import { h } from "../../components/h.js";
import { PLATFORM, termsFor } from "../platform.js";
import { heading } from "../headings.js";

// The sections that carry a title, by band id (modules.js SECTIONS): the
// registry entry each one draws. value has none: it is the first line of
// Meaning.
export const BAND_HEADING = Object.freeze({
  meaning: "meaning",
  everywhere: "other-sourcetypes",
  verdict: "verdict",
  enrich: "enrichment",
  pivots: "pivots",
  workflows: "workflows",
  pattern: "pattern",
});

// The Sentinel lines: the workflow module never mounts there, so the
// pivots are how a value travels. The first closes Pivots (N) on the popup
// (the value page names its drawer); the second is the platform note under
// the scope line when the column has no pivot at all.
export const SENTINEL_PIVOTS_LINE = "No guided workflow on Sentinel: these pivots carry the value. Copy KQL or Open as query tab.";
export const SENTINEL_PIVOTS_LINE_PAGE = "No guided workflow on Sentinel: these pivots carry the value. Copy the KQL from the drawer.";
export const SENTINEL_NO_PIVOTS_NOTE = "No guided workflow on Sentinel. Filter the grid on this value instead.";

export function bandTitle(id, n, platform = PLATFORM) {
  const entry = BAND_HEADING[id];
  if (!entry) throw new Error(`band ${id} has no heading`);
  return heading(entry, n, termsFor(platform));
}

// One band of the popup: its registry title over the block, or a fold whose
// summary carries the title.
export function band(id, { el, n, fold = false, platform = PLATFORM }) {
  if (!el) return null;
  const title = bandTitle(id, n, platform);
  if (fold) {
    return h("details", { class: "reach-details reach-fold reach-band", dataset: { band: id } }, h("summary", { class: "reach-summary" }, h("span", { class: "reach-row__title" }, title)), el);
  }
  return h("div", { class: "reach-band", dataset: { band: id } }, h("div", { class: "reach-row__title" }, title), el);
}

// The ids a walk draws, in order, for a band list and a presence test:
// each id in `bands` (modules.bands(platform), modules.js BANDS) that
// has something to say, the value band folded into meaning. The popups'
// walk and the value page's section loop both read this one list, so the
// two surfaces agree on the bands for the same click by construction.
export function plan(bands, has) {
  const out = [];
  for (const id of bands) {
    if (id === "value") continue;
    if (id === "meaning") {
      if (has("value") || has("meaning")) out.push("meaning");
      continue;
    }
    if (has(id)) out.push(id);
  }
  return out;
}

// The assembly every surface walks, with no list of exceptions: each band
// id in order, drawn or absent. The head's parts (the badge, the scope
// line, the action rows) come back as elements and go in as they are; a
// section comes back as { el, n, fold } and gets its title. The field's
// meaning band draws first and the value's own line, when it has one,
// goes under it; both go under one Meaning heading.
export function walkBands(bands, draw, { platform = PLATFORM } = {}) {
  const drawn = {};
  for (const id of bands) drawn[id] = draw(id);
  const elOf = (r) => (r && r.el !== undefined ? r.el : r);
  const out = [];
  for (const id of plan(bands, (b) => Boolean(elOf(drawn[b])))) {
    if (id === "meaning") {
      const kids = [elOf(drawn.meaning), elOf(drawn.value)].filter(Boolean);
      out.push(band("meaning", { el: h("div", { class: "reach-meaning-band" }, ...kids), platform }));
      continue;
    }
    const r = drawn[id];
    if (r.el === undefined) {
      out.push(r);
      continue;
    }
    const wrapped = band(id, { ...r, platform });
    if (wrapped) out.push(wrapped);
  }
  return out;
}
// A secondary band, closed by default: the popup's first screen is the
// verdict, the value's meaning and Hold; everything foldBlock wraps opens
// on a tap instead of pushing that first screen down.
export function foldBlock(label, el) {
  if (!el) return null;
  return h("details", { class: "reach-details reach-fold" }, h("summary", { class: "reach-summary" }, h("span", { class: "reach-row__title" }, label)), el);
}
