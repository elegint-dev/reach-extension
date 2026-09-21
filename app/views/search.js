// Search results: #/search?q=…

import { h } from "../components/h.js";
import { table } from "../components/table.js";
import { empty } from "../components/empty.js";
import { chip } from "../components/chip.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { classify, matchNames } from "../lib/search.js";

const MATCH_WHY = {
  exact: "exact",
  prefix: "prefix",
  substring: "substring",
  fuzzy: "near miss",
  family: "same name family",
};

// One line on what a name is. An FDR-bundle field: its layer, role and
// event count. Anything else the catalogue knows: which sourcetypes carry
// it and the best fill discovery measured, the fact that tells a user why
// their search on it came back empty.
export function aboutField(name, { fields, catalogue }) {
  const rec = fields.field(name);
  if (rec) return `${rec.layer === "cim" ? "L3 CIM" : rec.layer === "ta_derived" ? "L2 TA" : "L1 raw"} · ${rec.role} · ${rec.event_count} events`;
  const rows = catalogue ? catalogue.fieldEverywhere(name) : [];
  if (!rows.length) return "not catalogued";
  const best = rows[0];
  const fill = best.fill === null ? "" : ` · ${Math.round(best.fill * 100)}% fill on ${best.sourcetype}`;
  return rows.length === 1 ? `on ${best.sourcetype}${best.fill === null ? "" : ` · ${Math.round(best.fill * 100)}% fill`}` : `on ${rows.length} sourcetypes${fill}`;
}

export function aboutEvent(name, { fields }) {
  const rec = fields.event(name);
  return rec ? `${rec.field_count} fields · ${rec.cim && rec.cim.normalized ? "CIM normalized" : "no CIM path"}` : "";
}

export function render(ctx) {
  const { fields, catalogue } = ctx;
  const q = String(ctx.params.q || "");
  const idx = catalogue ? catalogue.searchIndex() : fields.searchIndex();
  const el = h("div", { class: "r-view r-view--search" });

  if (!q.trim()) {
    el.appendChild(titleBlock({ kind: "search", h1: "Search", scope: ["nothing searched yet"] }));
    el.appendChild(
      empty({
        title: "Type anything you are holding",
        line: "A field name, an event, a CIM name, a hash, an IP, a PID.",
        moves: [{ key: "/", text: "focus the search box" }, { key: "1", text: "or start from one of the four holdings", href: "#/" }],
      }),
    );
    return el;
  }

  const c = classify(q, idx);
  const hits = c.kind === "name" ? c.candidates : matchNames(q, idx);

  el.appendChild(
    titleBlock({
      kind: "search",
      h1: q,
      chips: [c.kind !== "name" ? chip({ kind: "trust", value: "inferred", text: c.kind.replace(/_/g, " ") }) : null],
      scope: [
        `${hits.length} name${hits.length === 1 ? "" : "s"} match`,
        c.kind !== "name" ? h("a", { href: `#/v/${encodeURIComponent(q)}` }, "also a value →") : null,
      ],
    }),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      hits.length ? headingNode("matches", hits.length) : null,
      hits.length
        ? table({
            caption: `Matches for ${q}`,
            columns: [
              { key: "name", label: "name" },
              { key: "kind", label: "kind" },
              { key: "about", label: "what it is" },
              { key: "why", label: "match" },
            ],
            rows: hits.map((m) => ({
              name: h("a", { href: `#/${m.kind === "field" ? "f" : "e"}/${encodeURIComponent(m.name)}`, class: "r-idlink r-rowlink", tabindex: "0" }, h("code", null, m.name)),
              kind: m.kind,
              about: m.kind === "field" ? aboutField(m.name, ctx) : aboutEvent(m.name, ctx),
              why: MATCH_WHY[m.match] || m.match,
            })),
          })
        : h("p", { class: "r-secondary" }, `Nothing in the catalogue is called ${q} or anything close to it. `, h("a", { href: `#/unknown/${encodeURIComponent(q)}` }, "See what is near it"), "."),
    ),
  );

  return el;
}

export default { render, aboutField, aboutEvent };
