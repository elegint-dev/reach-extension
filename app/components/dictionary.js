// dictionary: the data-dictionary part of a field page (app/lib/values.js),
// laid out like an AWS CLI operation page: the format line, the values
// with one line each, examples, gotchas (the concept's hazards), and the
// document it was read from. It sits under the annotation (the user's own
// note and the pack's description), never in its place.
//
// The pack's values sidecar is fetched on demand: the block draws what the
// catalogue already has (a decode table, or nothing) and redraws itself in
// place when the sidecar lands, so render() stays synchronous.
//
//   dictionaryBlock({ view, sourcetype, name, catalogue })   → section | null
//   conceptHazard(view)                                      → the hazard a title block's callout slot takes, or null
//   referenceLine({ sourcetype, packId, catalogue })         → p | null   the feed's reference document and licence
//   valuesSummary(dict)                                      → the words on the fold's summary line (pure)
//   provenanceChip(p)                                        → chip | null

import { h } from "./h.js";
import { chip } from "./chip.js";
import { callout } from "./callout.js";
import * as values from "../lib/values.js";
import { TERMS } from "../lib/platform.js";
import { heading, headingNode } from "../lib/headings.js";

// Same breakpoint as ledger.js: a fold starts closed at side-panel widths.
const NARROW = "(max-width: 599px)";
function isNarrow() {
  return typeof matchMedia === "function" && matchMedia(NARROW).matches;
}

const PROVENANCE_CHIP = {
  documented: { value: "confirmed", text: "documented", title: "Read from the vendor's documentation; the citation is below." },
  observed: { value: "asserted", text: "observed", title: "Seen in data; not in the vendor's documentation." },
  inferred: { value: "inferred", text: "inferred", title: "Worked out, not read or seen." },
};

export function provenanceChip(p) {
  const spec = PROVENANCE_CHIP[p];
  return spec ? chip({ kind: "trust", value: spec.value, text: spec.text, title: spec.title }) : null;
}

// "6 values · documented" / "5 values via cloudtrail-event-type" /
// "1 value · 19 flags from the pack's decode table"
export function valuesSummary(dict) {
  if (!dict) return "";
  const nv = dict.count - (dict.flags ? Object.keys(dict.flags).length : 0);
  const n = dict.flags ? `${nv} value${nv === 1 ? "" : "s"} · ${Object.keys(dict.flags).length} flags` : `${dict.count} value${dict.count === 1 ? "" : "s"}`;
  if (dict.source === "decode") return dict.lookup ? `${n} via ${dict.lookup}` : `${n} from the pack's decode table`;
  return dict.provenance ? `${n} · ${values.provenanceWords(dict.provenance)}` : n;
}

function citeLink(cite) {
  return h("a", { href: cite.url, rel: "noreferrer", target: "_blank", class: "r-idlink" }, cite.title);
}

function valueRow(literal, v, dict) {
  const own = v.provenance && v.provenance !== dict.provenance ? provenanceChip(v.provenance) : null;
  const cite = v.cite && (!dict.cite || v.cite.url !== dict.cite.url) ? h("span", { class: "r-muted r-dict__cite" }, " · ", citeLink(v.cite)) : null;
  return h(
    "li",
    null,
    h("code", null, literal),
    " ",
    h("span", null, v.meaning),
    own ? [" ", own] : null,
    v.note ? h("span", { class: "r-muted" }, ` (${v.note})`) : null,
    cite,
  );
}

// One bit of a bitmask concept: the mask, then the flag it sets.
function flagRow(mask, name) {
  return h("li", { class: "r-dict__flag" }, h("code", null, mask), " ", h("span", null, name), h("span", { class: "r-muted" }, " (bit)"));
}

const HAZARD_KIND = { danger: "hazard", caution: "caution", note: "note" };

// The concept's hazards, as callouts under the values. The field page
// lifts the first danger or caution into its title block's callout slot
// (conceptHazard); the rest stay here.
export function conceptHazard(view) {
  const list = (view && view.concept && view.concept.hazards) || [];
  return list.find((hz) => hz.level === "danger" || hz.level === "caution") || null;
}

// A hazard is the same one by id or text: the view is rebuilt when the
// values sidecar lands, so identity does not hold across a redraw.
const sameHazard = (a, b) => Boolean(a && b) && (a === b || (a.id && a.id === b.id) || a.text === b.text);

function gotchas(view, skip) {
  const list = ((view.concept && view.concept.hazards) || []).filter((hz) => !sameHazard(hz, skip));
  if (!list.length) return null;
  return h(
    "div",
    { class: "r-dict__gotchas" },
    list.map((hz) => callout({ kind: HAZARD_KIND[hz.level] || "note", body: hz.text })),
  );
}

function draw(view, sourcetype, skipHazard) {
  const dict = view && view.dictionary;
  const got = gotchas(view, skipHazard);
  if (!dict && !got) return null;
  const parts = [];
  if (dict && dict.format) parts.push(h("p", { class: "r-dict__format" }, h("span", { class: "r-muted" }, "Format "), dict.format));
  if (dict && dict.count) {
    parts.push(
      h(
        "details",
        { class: "r-decode r-dict__values", open: !isNarrow() },
        h("summary", { title: valuesSummary(dict) }, heading("decode-table", dict.count)),
        h("ul", { class: "r-decode__list r-dict__list" }, [
          ...Object.entries(dict.values).slice(0, 500).map(([k, v]) => valueRow(k, v, dict)),
          ...Object.entries(dict.flags || {}).map(([mask, name]) => flagRow(mask, name)),
        ]),
      ),
    );
  }
  if (dict && dict.examples.length) {
    parts.push(
      h(
        "p",
        { class: "r-dict__examples r-secondary" },
        h("span", { class: "r-muted" }, "Examples "),
        ...dict.examples.flatMap((ex, i) => [i ? "; " : "", h("code", null, ex.value), ex.note ? ` ${ex.note}` : ""]),
      ),
    );
  }
  if (got) parts.push(got);
  if (dict && dict.quote && dict.cite) parts.push(h("p", { class: "r-dict__quote r-secondary" }, h("q", null, dict.quote), " ", h("span", { class: "r-muted" }, "(the reference's words)")));
  if (dict && (dict.cite || dict.provenance)) {
    parts.push(
      h(
        "p",
        { class: "r-dict__ref r-secondary" },
        provenanceChip(dict.provenance),
        dict.cite ? [" ", h("span", { class: "r-muted" }, "Reference "), citeLink(dict.cite), h("span", { class: "r-muted" }, `, read ${dict.cite.read_on}`)] : null,
      ),
    );
  }
  const b = view.binding && view.binding.provenance;
  if (b) {
    const cite = b.cite ? [" ", citeLink(b.cite)] : null;
    parts.push(h("p", { class: "r-dict__binding r-secondary" }, h("span", { class: "r-muted" }, `On this ${TERMS.sourcetype} `), h("code", null, b.kind), b.statement ? `: ${b.statement}` : "", cite));
  }
  return parts;
}

//   skipHazard: a concept hazard drawn elsewhere on the page (the title block's callout slot)
export function dictionaryBlock({ view, sourcetype, name, catalogue, skipHazard = null }) {
  if (!view || !(view.concept || view.dictionary)) return null;
  const section = h("section", { class: "r-section r-dict" }, headingNode("values"));
  const body = h("div", { class: "r-dict__body" });
  section.appendChild(body);
  const fill = (v) => {
    const parts = draw(v, sourcetype, skipHazard);
    body.replaceChildren();
    if (!parts) return false;
    for (const p of parts) body.appendChild(p);
    return true;
  };
  const ready = catalogue.valuesReady(sourcetype);
  const drawn = fill(view);
  if (ready) return drawn ? section : null;
  if (!drawn) body.appendChild(h("p", { class: "r-muted r-dict__loading" }, "Looking the values up…"));
  // The sidecar is on its way: redraw in place when it lands, unless the
  // page has moved on (a detached section is left alone).
  catalogue.loadValues(sourcetype).then(() => {
    if (!section.isConnected) return;
    const next = catalogue.fieldOn(sourcetype, name) || view;
    if (!fill(next)) section.remove();
  });
  return section;
}

// The feed's reference document and the licence its words are under, for
// the sourcetype page header. Filled when the sidecar lands.
export function referenceLine({ sourcetype, packId, catalogue }) {
  if (!packId) return null;
  const el = h("p", { class: "r-secondary r-dict__ref" });
  const fill = () => {
    const ref = values.reference(packId);
    const lic = values.licence(packId);
    el.replaceChildren();
    if (!ref && !lic) return false;
    if (ref) el.append(h("span", { class: "r-muted" }, "Reference "), citeLink(ref), h("span", { class: "r-muted" }, `, read ${ref.read_on}`));
    if (lic) el.append(h("span", { class: "r-muted" }, `${ref ? " · " : ""}${lic.holder ? `${lic.holder} documentation, ` : ""}${lic.name}${lic.note ? `; ${lic.note}` : ""}`));
    return true;
  };
  if (catalogue.valuesReady(sourcetype)) return fill() ? el : null;
  catalogue.loadValues(sourcetype).then(() => {
    if (!el.isConnected) return;
    if (!fill()) el.remove();
  });
  return el;
}

export default { dictionaryBlock, referenceLine, valuesSummary, provenanceChip, conceptHazard };
