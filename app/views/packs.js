// Packs: #/packs
// What curated knowledge is loaded, per feed: which sourcetypes each pack
// covers, how many fields it describes, how many pivots it declares.

import { h } from "../components/h.js";
import { stLink } from "../components/links.js";
import { titleBlock } from "../components/titleBlock.js";
import { TERMS } from "../lib/platform.js";
import { chip } from "../components/chip.js";
import * as packs from "../lib/packs.js";

export function render() {
  const el = h("div", { class: "r-view r-view--packs" });
  const list = packs.list();
  el.appendChild(titleBlock({ kind: "page", h1: "Packs", scope: [`${list.length} pack${list.length === 1 ? "" : "s"}`] }));
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h(
        "p",
        { class: "r-secondary" },
        `A pack is curated knowledge for one feed, as data: what its ${TERMS.fields} mean on each ${TERMS.sourcetype}, their roles, decode tables and CIM mapping, the pivots between them with the ${TERMS.lang} to run, and guided workflows that walk those pivots. Your notes override a pack; discovery adds facts beside it. Packs ship with the extension.`,
      ),
    ),
  );
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      h(
        "div",
        { class: "r-stlist" },
        list.map((p) =>
          h(
            "div",
            { class: "r-stlist__row r-packrow" },
            h(
              "div",
              { class: "r-stlist__name" },
              h("b", null, p.name),
              p.pack_version ? h("span", { class: "r-muted" }, ` ${p.pack_version}`) : null,
              h("p", { class: "r-secondary" }, p.description),
              p.source ? h("p", { class: "r-muted" }, "Source: ", p.source) : null,
              h("p", { class: "r-inline" }, p.sourcetypes.flatMap((s, i) => [i ? " " : null, stLink(s)])),
            ),
            h("div", { class: "r-stlist__meta" }, `${p.fields.toLocaleString()} field${p.fields === 1 ? "" : "s"} · ${p.edges} pivot${p.edges === 1 ? "" : "s"} · ${p.workflows} workflow${p.workflows === 1 ? "" : "s"}`),
            chip({ kind: "trust", value: "confirmed", text: "pack" }),
          ),
        ),
      ),
    ),
  );
  return el;
}

export default { render };
