// provenance: how a field comes to exist on a sourcetype, as Splunk
// declares it: an alias of another field, an EVAL over others, a lookup's
// output (or its key), a regex extraction. Read by discovery from props and
// transforms; shown with the statement so nothing has to be taken on faith.
//
//   provenanceBlock({ provenance, sourcetype })   → section | null
//   provenanceLine(provenance)                    → one-line summary | null

import { h } from "./h.js";
import { fieldLink } from "./links.js";
import { chip } from "./chip.js";
import { headingNode } from "../lib/headings.js";

const KIND = {
  alias: { label: "alias", trust: "confirmed", say: (p) => ["alias of ", code(p.from)] },
  calculated: { label: "calculated", trust: "confirmed", say: (p) => ["computed from ", ...list(p.refs)] },
  lookup: { label: "lookup", trust: "confirmed", say: (p) => ["output of lookup ", code(p.transform), " keyed on ", ...list(p.inputs)] },
  lookup_key: { label: "lookup key", trust: "asserted", say: (p) => ["key into lookup ", code(p.transform), " → ", ...list(p.outputs)] },
  extracted: { label: "extracted", trust: "confirmed", say: (p) => [p.transform ? ["by transform ", code(p.transform)] : "by an inline regex"].flat() },
};

function code(s) {
  return h("code", null, String(s));
}
function list(names) {
  return (names || []).flatMap((n, i) => [i ? ", " : "", fieldLink(n)]);
}
export function provenanceLine(provenance) {
  if (!provenance || !provenance.length) return null;
  const p = provenance[0];
  const k = KIND[p.kind];
  if (!k) return null;
  return h("span", null, ...k.say(p), provenance.length > 1 ? h("span", { class: "r-muted" }, ` (+${provenance.length - 1} more)`) : null);
}

export function provenanceBlock({ provenance, sourcetype }) {
  if (!provenance || !provenance.length) return null;
  return h(
    "section",
    { class: "r-section" },
    headingNode("extraction"),
    h("p", { class: "r-secondary" }, "As declared on ", h("code", null, sourcetype), " in props.conf and transforms.conf, read from your Splunk. Several entries mean several stanzas produce this field; the last one to run wins."),
    h(
      "div",
      { class: "r-prov" },
      provenance.map((p) => {
        const k = KIND[p.kind] || { label: p.kind, trust: "inferred", say: () => [] };
        return h(
          "div",
          { class: "r-prov__row" },
          h("div", { class: "r-prov__head" }, chip({ kind: "trust", value: k.trust, text: k.label }), " ", ...k.say(p), p.app ? h("span", { class: "r-muted" }, ` · ${p.app}`) : null),
          p.statement ? h("pre", { class: "r-prov__stmt" }, h("code", null, p.statement)) : null,
          p.regex ? h("pre", { class: "r-prov__stmt" }, h("code", null, p.regex + (p.format ? `\nFORMAT = ${p.format}` : ""))) : null,
          p.attribute ? h("p", { class: "r-muted" }, p.attribute) : null,
        );
      }),
    ),
  );
}

export default { provenanceBlock, provenanceLine };
