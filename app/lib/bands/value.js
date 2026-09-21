// The clicked value's own line: what the value itself means, from the
// pack's values table or a decode table the popup already holds, or (a
// closed set only) that it is not one of the documented ones. Its rules
// live in popup-shell.js POPUP_CSS (.reach-value).
//
//   valueEntry({ catalogue, container, field, value, view }) → ValueRow | null   (pure)
//       the pack's values table (catalogue.valueOn), else the decode table
//       the popup already holds (view.decode: the FDR bundle's, a pack's, or
//       one discovery read from your own lookup), else, when the field's
//       dictionary is a closed set, that the value misses it; null when the
//       value carries no information (an open field with only a format)
//   valueBlock({ field, value, container, platform, catalogue, view }) → Element | null
//       that row, drawn; the pack's values sidecar is fetched when the popup
//       opens for the container and the row is redrawn in place when it lands
//   whenValuesLand({ catalogue, container, el, fill })
//       the lazy pattern above, shared with the app's value page
//
// DOM module (uses h.js). Never fetches.

import { h } from "../../components/h.js";
import { PLATFORM } from "../platform.js";

// --- the clicked value -------------------------------------------------------
//
// ValueRow: { kind: "entry", value, meaning, source, provenance, cite, quote, note, lookup, packId, concept }
//           source "pack": the pack's values table; "discovered": a table discovery read from your own
//           lookup; "decode": a bundled decode table (the FDR bundle's, or a pack's) the popup already held
//         | { kind: "closed", value, count }   the dictionary is a closed set and the value misses it
//
// The pack's table is asked through catalogue.valueOn, which sees a pack's
// concept-carried decode too. The FDR bundle's decode tables are keyed by
// field name outside the concept model, so the caller's own decode record
// (view.decode, catalogue.decodeOn) is checked next: the row the popups
// drew before this block existed never goes missing.
const UNSAFE_LITERAL = new Set(["__proto__", "constructor", "prototype"]);

// A dictionary's values table is the whole set, not a sample of it, when
// its own entry says so (`closed: true`, the loader/builder marker in
// values.js) or its concept is an enumeration (taxonomy type `enum`): a
// bitmask decodes flags, not a fixed list, so its type never counts.
export function dictionaryClosed(dict, concept) {
  return Boolean(dict) && Boolean(dict.closed || (concept && concept.type === "enum"));
}

export function valueEntry({ catalogue, container, field, value, view = null }) {
  if (value === undefined || value === null || !field) return null;
  const literal = String(value);
  const hit = catalogue && container ? catalogue.valueOn(container, field, literal) : null;
  if (hit) {
    return { kind: "entry", value: literal, meaning: hit.meaning, source: hit.source, provenance: hit.provenance || null, cite: hit.cite || null, quote: hit.quote || null, note: hit.note || null, lookup: null, packId: hit.packId || null, concept: hit.concept || null };
  }
  const dec = view && view.decode;
  if (dec && dec.values && typeof dec.values === "object" && !UNSAFE_LITERAL.has(literal) && Object.prototype.hasOwnProperty.call(dec.values, literal)) {
    const m = dec.values[literal];
    const discovered = dec.source === "discovered";
    return { kind: "entry", value: literal, meaning: typeof m === "string" ? m : String(m), source: discovered ? "discovered" : "decode", provenance: discovered ? "observed" : null, cite: null, quote: null, note: null, lookup: dec.lookup || null, packId: null, concept: null };
  }
  const dict = view && view.dictionary;
  if (dictionaryClosed(dict, view && view.concept)) return { kind: "closed", value: literal, count: dict.count || 0 };
  return null;
}

// Fill now with what the catalogue holds; when the container's values
// sidecar has not been fetched yet, fetch it and fill again in place.
// `fill(ready)` returns whether it drew anything; an empty second draw
// removes the element. The second fill runs whether or not the element is
// in the document yet: the popups build their whole section before
// appending it, and the sidecar can land first.
export function whenValuesLand({ catalogue, container, el, fill }) {
  const ready = !container || !catalogue || typeof catalogue.valuesReady !== "function" || catalogue.valuesReady(container);
  const drawn = fill(ready);
  if (ready) return drawn;
  catalogue.loadValues(container).then(() => {
    if (!fill(true)) el.remove();
  });
  return drawn;
}

const VALUE_CHIP = {
  documented: { basis: "confirmed", text: "documented", title: "Read from the vendor's documentation; the citation is below." },
  observed: { basis: "asserted", text: "observed", title: "Seen in data; not in the vendor's documentation." },
  inferred: { basis: "proposed", text: "inferred", title: "Worked out, not read or seen." },
};

function valueChip(row, platform) {
  if (row.source === "discovered") {
    const own = platform === "sentinel" ? "your watchlist" : "your lookup";
    return h("span", { class: "reach-chip", dataset: { basis: "confirmed" }, title: "Read by discovery from a lookup of yours." }, row.lookup ? `${own} · ${row.lookup}` : own);
  }
  if (row.source === "decode") return h("span", { class: "reach-chip", dataset: { basis: "pack" }, title: "The bundled decode table for this field." }, row.lookup ? `decode · ${row.lookup}` : "decode");
  const spec = VALUE_CHIP[row.provenance];
  if (spec) return h("span", { class: "reach-chip", dataset: { basis: spec.basis }, title: spec.title }, spec.text);
  return h("span", { class: "reach-chip", dataset: { basis: "pack" } }, "pack");
}

// The clicked value's own line, one line, under the field's meaning:
// "AwsConsoleSignIn: an interactive console sign-in" with where the words
// came from. Drawn at once from what is cached; the pack's sidecar,
// fetched only now, refills it in place. Returns null when the value
// carries no information: nothing names it and the field's dictionary is
// not a closed set (an open format alone says nothing a value can miss).
export function valueBlock({ field, value, container, platform = PLATFORM, catalogue, view = null }) {
  if (value === undefined || value === null || !field) return null;
  const root = h("div", { class: "reach-row reach-value" });
  const draw = (v) => {
    const row = valueEntry({ catalogue, container, field, value, view: v });
    root.replaceChildren();
    if (!row) return false;
    if (row.kind === "closed") {
      root.appendChild(h("div", { class: "reach-value__body reach-row__body--muted" }, h("code", null, row.value), `: not one of the ${row.count} documented values`));
      return true;
    }
    root.appendChild(h("div", { class: "reach-value__body" }, h("code", null, row.value), ": ", row.meaning, " ", valueChip(row, platform)));
    if (row.note) root.appendChild(h("div", { class: "reach-value__note" }, row.note));
    if (row.quote && row.cite) root.appendChild(h("div", { class: "reach-value__note reach-value__quote" }, h("q", null, row.quote), " (the reference's words)"));
    if (row.cite) root.appendChild(h("div", { class: "reach-value__cite" }, h("a", { href: row.cite.url, target: "_blank", rel: "noreferrer" }, row.cite.title), `, read ${row.cite.read_on}`));
    return true;
  };
  // Once the sidecar is in, the catalogue's fresh view carries the
  // dictionary; the decode the caller handed over stays when the fresh
  // view has none (the no-sourcetype path's FDR table).
  const fresh = () => {
    const next = container && catalogue ? catalogue.fieldOn(container, field) : null;
    return next ? { ...next, decode: next.decode || (view && view.decode) || null } : view;
  };
  const drawn = whenValuesLand({ catalogue, container, el: root, fill: (ready) => draw(ready ? fresh() : view) });
  // Nothing yet and nothing coming: no row. Nothing yet with a sidecar on
  // its way: an empty row that fills or removes itself.
  if (!drawn && (!container || !catalogue || catalogue.valuesReady(container))) return null;
  return root;
}
