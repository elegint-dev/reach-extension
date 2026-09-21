// ledger: the pivot map. One band per cost tier, rendered as a card grid
// (not a table); field.js's four reachability bands additionally get a small
// spatial map (a center node for what you're holding, a spoke per band)
// that jumps focus to that band's first selectable card.
//
//   ledger({
//     subject: "ResponsiblePid",     // optional; the map's center label
//     selectedId: "e_context_to_target",
//     bands: [{
//       id: "one-join",
//       kind: "here" | "automatic" | "one-join" | "suggested" | "unreachable",
//       title: "One join",            // optional; defaults per kind
//       caption: "…",                 // hidden heading read by screen readers
//       note: "…" | Node,             // one line under the heading
//       columns: ["target", "via", "scope", "cardinality", "basis"],
//       rows: [{
//         id: "e_context_to_target",
//         // cells[0] is the card's title. A trailing cell that IS a chip
//         // Node (chip() returns one) is lifted into the card's badge
//         // corner; everything between is a labelled field, using columns
//         // for the label.
//         cells: ["the process that caused this event", { mono: "ContextProcessId → TargetProcessId" }, "same aid", "n:1", chip(…)],
//         hazard: false,              // hazard rows get the red rule
//         disabled: false,            // unreachable/suggested rows are not selectable
//       }],
//       empty: "…" | Node,            // shown in place of the cards when rows is empty
//       collapsible: false,           // true: the band folds behind its heading (<details>);
//                                     // closed by default on the panel surface, open elsewhere,
//                                     // always open when the selected row lives in it, and open
//                                     // when it holds the page's only actionable rows (below)
//       folded: false,                // true: closed on the panel surface even when it holds the
//                                     // page's only move; the count in the heading says what is inside
//                                     // (`closed` is the same flag under the value page's name)
//     }],
//   })
//
// The fold and the only actionable row. A fold starts closed in the side
// panel so a prose-heavy or empty band is one line, not a screen. That
// hides a row the hunter can act on when the band is where the action is:
// a host-only field's one pivot (every process on the host in the window)
// lives in NOT REACHABLE, the band that folds. The rule: count the
// selectable rows in every band that costs a query; if none of them sits
// in a band that stays open, every fold holding one opens. A closed fold
// never hides the only move on the page; a fold that hides nothing
// actionable (all rows disabled, or no rows) stays closed. HERE and
// AUTOMATIC are left out of the count: HERE's rows pick an event, which is
// scope, and AUTOMATIC's are lookups already on the record, so neither is
// a move to make.
//
// Cost is carried by band order, a glyph and card position, never a hue of
// its own; trust stays on the chip the caller puts in a cell. Cards are
// focusable (tabindex=0, data-row-id) and dispatch a bubbling `select`
// CustomEvent (detail: { rowId, bandId, row }) on click or Enter. Arrow-key
// movement between cards is the spine's job (app.js focusableRows), which
// walks `[data-row-id][tabindex="0"]` outside any closed fold, tag-agnostic,
// so it does not care that cards are <div>s and not <tr>s.
//
// Element API: el.select(rowId) marks the card aria-selected; el.rows()
// lists the selectable cards in order.

import { h, uid } from "./h.js";
import { isPanel } from "../lib/surface.js";

const BANDS = {
  here: { glyph: "≡", title: "Here", sub: "already on the record, free" },
  automatic: { glyph: "⚙", title: "Automatic", sub: "the TA does this at search time; already on the record" },
  "one-join": { glyph: "⤳", title: "One join", sub: "key, scope, cardinality, basis" },
  suggested: { glyph: "≈", title: "Suggested", sub: "enrichment, not validated" },
  unreachable: { glyph: "⊘", title: "Not reachable", sub: "and the closest you can get" },
};

// The map's spokes: cost order, left to right in the ledger, top to bottom
// on the map. Monochrome except the hazard-adjacent unreachable spoke:
// hue stays reserved for trust chips, hazard treatments, and the accent.
const MAP_ORDER = ["automatic", "one-join", "suggested", "unreachable"];
const MAP_HAZARD = new Set(["unreachable"]);

function isChip(node) {
  return node instanceof Node && node.nodeType === 1 && node.classList && node.classList.contains("r-chip");
}

function fieldContent(content) {
  if (content === null || content === undefined) return document.createTextNode("");
  if (content instanceof Node) return content;
  if (typeof content === "object" && !Array.isArray(content)) {
    const { mono, text, muted, wrap } = content;
    return h("span", { class: [muted && "r-muted", wrap && "r-ledger__wraptext"] }, mono !== undefined ? h("code", null, mono) : text ?? "");
  }
  return h("span", null, String(content));
}

function card(row, band) {
  const cells = row.cells || [];
  const lastIdx = cells.length - 1;
  const hasBadge = lastIdx >= 0 && isChip(cells[lastIdx]);
  const bodyEnd = hasBadge ? lastIdx : cells.length;
  const columns = band.columns || [];

  const fields = [];
  for (let i = 1; i < bodyEnd; i++) {
    fields.push(
      h(
        "div",
        { class: "r-ledger__field" },
        columns[i] ? h("span", { class: "r-ledger__k" }, columns[i]) : null,
        fieldContent(cells[i]),
      ),
    );
  }

  const el = h(
    "div",
    {
      class: ["r-ledger__row", row.hazard && "r-ledger__row--hazard", row.disabled && "r-ledger__row--disabled"],
      tabindex: row.disabled ? null : "0",
      dataset: { rowId: row.id, bandId: band.id },
      "aria-disabled": row.disabled ? "true" : null,
    },
    h(
      "div",
      { class: "r-ledger__cardhead" },
      h("div", { class: "r-ledger__lead" }, fieldContent(cells[0])),
      hasBadge ? h("div", { class: "r-ledger__basis" }, cells[lastIdx]) : null,
    ),
    fields.length ? h("div", { class: "r-ledger__body" }, fields) : null,
  );
  return el;
}

function jumpTo(root, bandId) {
  const section = root.querySelector(`[data-band-id="${bandId}"]`);
  if (!section) return;
  const fold = section.querySelector(":scope > details.r-ledger__fold");
  if (fold) fold.open = true;
  if (typeof section.scrollIntoView === "function") section.scrollIntoView({ block: "nearest" });
  const row = section.querySelector('[data-row-id]:not([aria-disabled="true"])');
  if (row) {
    row.focus();
    row.click();
  } else if (typeof section.focus === "function") {
    section.setAttribute("tabindex", "-1");
    section.focus({ preventScroll: true });
  }
}

// The map only earns its space when there is real reachability structure to
// show, i.e. field.js's automatic/one-join/suggested/unreachable bands.
// value.js's candidate bands are all kind "one-join" and never trigger it.
function reachMap(bands, subject, root) {
  const present = MAP_ORDER.map((k) => bands.find((b) => b.kind === k)).filter(Boolean);
  if (!bands.some((b) => b.kind === "automatic") || present.length < 2) return null;

  const top = 36;
  const gap = 84;
  const cx = "8%";
  const spokeX = "64%";
  const cy = top + ((present.length - 1) * gap) / 2;
  const height = top + (present.length - 1) * gap + 36;

  const lines = present.map((band, i) => {
    const y = top + i * gap;
    const hazard = MAP_HAZARD.has(band.kind);
    return h("line", {
      x1: "8%",
      y1: String(cy),
      x2: "64%",
      y2: String(y),
      class: ["r-map__line", hazard && "r-map__line--hazard"],
    });
  });

  const nodes = present.map((band, i) => {
    const y = top + i * gap;
    const spec = BANDS[band.kind];
    const count = (band.rows || []).length;
    const hazard = MAP_HAZARD.has(band.kind);
    return h(
      "button",
      {
        type: "button",
        class: ["r-map__node", hazard && "r-map__node--hazard"],
        style: { left: spokeX, top: `${y}px` },
        onClick: () => jumpTo(root, band.id),
      },
      h("span", { class: "r-map__glyph", "aria-hidden": "true" }, spec.glyph),
      h("span", { class: "r-map__label" }, band.title || spec.title),
      h("span", { class: "r-map__count" }, String(count)),
    );
  });

  return h(
    "div",
    { class: "r-map", role: "group", "aria-label": "Jump to a band", style: { height: `${height}px` } },
    h(
      "svg",
      { class: "r-map__svg", viewBox: `0 0 100 ${height}`, preserveAspectRatio: "none", "aria-hidden": "true" },
      lines,
    ),
    h("div", { class: "r-map__center", style: { left: cx, top: `${cy}px` } }, h("span", null, subject || "here")),
    nodes,
  );
}

export function ledger({ bands = [], selectedId = null, caption, subject } = {}) {
  const el = h("div", { class: "r-ledger", role: "group", "aria-label": caption || "Reach ledger" });
  let selected = selectedId;

  function selectRow(rowId) {
    selected = rowId;
    for (const row of el.querySelectorAll("[data-row-id]")) {
      const on = row.dataset.rowId === rowId;
      row.classList.toggle("is-selected", on);
      if (!row.hasAttribute("aria-disabled")) row.setAttribute("aria-selected", on ? "true" : "false");
    }
  }

  // The only-actionable-row rule (header): which folds must open.
  const FREE = new Set(["here", "automatic"]);
  const actionable = (band) => (band.rows || []).filter((r) => !r.disabled).length;
  const openElsewhere = bands.some((b) => !FREE.has(b.kind) && !b.collapsible && actionable(b) > 0);
  const mustOpen = (band) => band.collapsible && !FREE.has(band.kind) && !openElsewhere && actionable(band) > 0;

  for (const band of bands) {
    const spec = BANDS[band.kind] || BANDS.here;
    const headId = uid("band");
    const rows = band.rows || [];

    const cardsWrap = h("div", { class: "r-ledger__cards" });
    if (rows.length === 0) {
      cardsWrap.appendChild(h("p", { class: "r-ledger__empty" }, typeof band.empty === "string" ? band.empty : band.empty ?? "Nothing here."));
    }
    for (const row of rows) {
      const rowEl = card(row, band);
      if (row.id === selected) {
        rowEl.classList.add("is-selected");
        if (!row.disabled) rowEl.setAttribute("aria-selected", "true");
      } else if (!row.disabled) {
        rowEl.setAttribute("aria-selected", "false");
      }
      if (!row.disabled) {
        const fire = (e) => {
          selectRow(row.id);
          el.dispatchEvent(new CustomEvent("select", { bubbles: true, detail: { rowId: row.id, bandId: band.id, row } }));
          if (e.type === "keydown") e.preventDefault();
        };
        rowEl.addEventListener("click", (e) => {
          // A card's own links, buttons and disclosures keep their clicks;
          // the band's fold (a <details> above the card) is not the card's.
          const own = e.target.closest("a, button, input, details");
          if (own && rowEl.contains(own)) return;
          fire(e);
        });
        rowEl.addEventListener("keydown", (e) => {
          if (e.key === "Enter") fire(e);
        });
      }
      cardsWrap.appendChild(rowEl);
    }

    const head = h(
      "h3",
      { id: headId, class: "r-ledger__head" },
      h("span", { class: "r-ledger__glyph", "aria-hidden": "true" }, spec.glyph),
      h("span", { class: "r-ledger__title" }, band.title || spec.title),
      h("span", { class: "r-ledger__count" }, `${rows.length}`),
    );
    const body = [band.note ? h("p", { class: "r-ledger__note" }, band.note) : null, h("div", { class: "r-ledger__scroll" }, cardsWrap)];

    // A fold never hides the selected row, nor the page's only move.
    const holdsSelected = selected !== null && rows.some((r) => r.id === selected);
    const content = band.collapsible
      ? h("details", { class: "r-ledger__fold", open: holdsSelected || !isPanel() || (!band.folded && !band.closed && mustOpen(band)) }, h("summary", { class: "r-ledger__summary" }, head), body)
      : [head, body];

    const section = h(
      "section",
      { class: ["r-ledger__band", `r-ledger__band--${band.kind}`], "aria-labelledby": headId, dataset: { bandId: band.id ?? band.kind } },
      content,
    );
    el.appendChild(section);
  }

  const map = reachMap(bands, subject, el);
  if (map) el.insertBefore(map, el.firstChild);

  el.select = selectRow;
  el.rows = () => Array.from(el.querySelectorAll('[data-row-id]:not([aria-disabled="true"])'));
  return el;
}

export default ledger;
