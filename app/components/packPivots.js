// packPivots: the pivot graph a pack declares from one field on one
// sourcetype, as a selectable list that fills the drawer with the rendered
// SPL, its parameters and its hazards. The generic counterpart of the FDR
// ledger in app/views/field.js.
//
//   packPivots({ ctx, sourcetype, name, edges, heading, titled, setSel, carried }) → section element
//     carried: the page's value under its field's names (facts.carried), bound
//     under the user's own drawer inputs; nothing when the page has none
//     ctx: the view context (drawer, setDrawerParamHandler, setUrl, params)
//     heading: false draws the list alone (a div) for a page that heads it
//     titled: false keeps the section but leaves the Pivots (N) heading to
//       the caller
//     setSel(edgeId): how the page writes the selection into its URL; the
//       field route's ?sel= when absent

import { h } from "./h.js";
import { chip } from "./chip.js";
import { fillFrom } from "./drawer.js";
import * as packs from "../lib/packs.js";
import * as pivot from "../lib/pivot.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import { TERMS } from "../lib/platform.js";
import { headingNode } from "../lib/headings.js";

function basisChip(edge) {
  const v = edge.basis === "confirmed" || edge.basis === "validated" ? edge.basis : edge.basis === "proposed" ? "suggested" : "asserted";
  return chip({ kind: "trust", value: v, text: edge.basis, title: edge.basis_ref || "" });
}

// The window a pivot opens on when nothing binds it: the pack's own
// suggested earliest (its placeholder, -24h), so the search is one click
// and the input to change it stays drawn, prefilled. Only the window
// defaults: an id or a scope is never guessed.
export function windowDefaults(meta) {
  const m = meta && meta.earliest;
  return m && m.placeholder ? { earliest: m.placeholder } : {};
}

export function packPivots({ ctx, sourcetype, name, edges, heading = true, titled = true, setSel = null, carried = {} }) {
  const userParams = {};
  let current = null;

  function paramInputs(names, meta, defaults = {}) {
    return names.map((n) => {
      const m = meta[n] || {};
      return { name: n, label: m.label || n, value: userParams[n] ?? defaults[n] ?? "", placeholder: m.placeholder || "", hint: m.hint || "", required: true };
    });
  }

  function fill(edge, rebuild) {
    current = edge;
    const pack = packs.pack(edge.packId);
    const meta = packs.params(edge.packId);
    const defaults = windowDefaults(meta);
    // The index is scope, resolved for the sourcetype the search runs on
    // (the edge's destination, as pivot.js renders it), never a held fact.
    const on = (edge.dst && edge.dst.sourcetype) || edge.src.sourcetype;
    const params = scope.bind({ ...defaults, ...facts.bound(), ...carried, ...userParams }, on);
    const subtitle = `${edge.src.field} → ${edge.dst.field} on ${edge.dst.sourcetype}`;
    fillFrom(
      ctx.drawer,
      {
        title: edge.label,
        subtitle: edge.note ? `${subtitle}: ${edge.note}` : subtitle,
        // The defaulted window keeps its input, prefilled, beside what is still unbound.
        params: (out) => paramInputs(Array.from(new Set([...Object.keys(defaults), ...out.missing])), meta, defaults),
        errorParams: () => paramInputs(["value", "earliest"], meta, defaults),
        notes: () => scope.notes(on),
        catchAll: true,
      },
      () => pivot.generate(edge, params, { pack }),
      rebuild,
    );
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    if (current) fill(current, false);
  });

  const rows = edges.map((e) =>
    h(
      "tr",
      {
        class: "r-rowlink",
        tabindex: "0",
        dataset: { rowId: e.id },
        onClick: () => select(e),
        onKeydown: (ev) => {
          if (ev.key === "Enter") select(e);
        },
      },
      h("td", null, h("span", null, e.label), e.note ? h("p", { class: "r-ledger__sub r-muted" }, e.note) : null),
      h("td", null, h("code", null, e.kind)),
      h("td", null, h("code", null, e.dst.field), e.dst.sourcetype !== sourcetype ? h("span", { class: "r-muted" }, ` on ${e.dst.sourcetype}`) : null),
      h("td", null, h("code", null, e.cardinality || "")),
      h("td", null, basisChip(e)),
    ),
  );

  const table = h(
    "table",
    { class: "r-table r-packpivots" },
    h("thead", null, h("tr", null, h("th", null, "pivot"), h("th", null, "kind"), h("th", null, "to"), h("th", null, "cardinality"), h("th", null, "basis"))),
    h("tbody", null, rows),
  );

  function select(e) {
    for (const r of table.querySelectorAll("tr[data-row-id]")) r.classList.toggle("r-selected", r.dataset.rowId === e.id);
    if (setSel) setSel(e.id);
    else ctx.setUrl("field", { ...ctx.params, name, st: sourcetype, sel: e.id });
    fill(e, true);
  }

  const packNames = Array.from(new Set(edges.map((e) => (packs.pack(e.packId) || {}).name || e.packId)));
  const el = h(
    heading ? "section" : "div",
    { class: heading ? "r-section" : "r-packpivots__list" },
    heading && titled ? headingNode("pivots", edges.length) : null,
    heading
      ? h("p", { class: "r-secondary" }, `Pivots the ${packNames.join(", ")} pack declares from `, h("code", null, name), `. Select one and the ${TERMS.lang} appears in the drawer with its parameters and hazards.`)
      : h("p", { class: "r-secondary" }, `From the ${packNames.join(", ")} pack. Select a row: the ${TERMS.lang} lands in the drawer with its parameters and hazards.`),
    h("div", { class: "r-table-wrap" }, table),
  );
  el.selectRow = (id) => {
    const e = edges.find((x) => x.id === id);
    if (e) select(e);
  };
  // An index chosen or set under Settings lands in the open pivot.
  scope.follow(el, () => {
    if (current) fill(current, true);
  });
  return el;
}

export default packPivots;
