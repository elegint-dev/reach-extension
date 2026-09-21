// Catalogue overview: #/catalogue
// Every sourcetype the catalogue knows, from any layer, with where it came
// from and how much is described. The place to start when the question is
// "what data do we have" rather than "what is this field".

import { h } from "../components/h.js";
import { stLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { TERMS } from "../lib/platform.js";
import * as modules from "../lib/modules.js";
import { healthChips, deltaSummary } from "../components/health.js";

const SOURCE_CHIP = {
  pack: { value: "confirmed", text: "pack" },
  user: { value: "confirmed", text: "yours" },
  discovered: { value: "inferred", text: "discovered" },
};

export function sourceChips(sources) {
  return h("span", { class: "r-stlist__src" }, (sources || []).map((s) => chip({ kind: "trust", ...(SOURCE_CHIP[s] || { value: "inferred", text: s }) })));
}

export function render(ctx) {
  const { catalogue } = ctx;
  const el = h("div", { class: "r-view r-view--catalogue" });
  const sts = catalogue.sourcetypes();
  const noted = catalogue.noteCount().notes; // by (sourcetype, field) and by concept

  // The action row links a tool route only while its module is mounted.
  const tool = (route, label) => (modules.routeStatus(route) === "on" ? h("a", { class: "r-btn", href: `#/${route}` }, label) : null);
  el.appendChild(
    titleBlock({
      kind: "page",
      h1: "Catalogue",
      scope: [
        `${sts.length} ${sts.length === 1 ? TERMS.sourcetype : TERMS.sourcetypes}`,
        `${noted} ${TERMS.fields} described`,
        `${sts.filter((s) => s.sources.includes("pack")).length} from packs`,
        `${sts.filter((s) => s.sources.includes("discovered")).length} discovered on your ${TERMS.env}`,
      ],
      actions: [tool("discover", "Discover"), tool("share", "Share")],
    }),
  );
  el.appendChild(
    h(
      "p",
      { class: "r-secondary" },
      `Everything here is keyed by ${TERMS.sourcetype}, then ${TERMS.field}. A pack describes a feed someone has done the work on; your notes override it and travel with an export; discovery fills in what your own ${TERMS.env} actually carries.`,
    ),
  );

  const rows = sts.map((s) => {
    const fields = catalogue.fieldsOn(s.name);
    const described = fields.filter((f) => {
      const v = catalogue.fieldOn(s.name, f);
      return v && v.meaning && v.meaning.description;
    }).length;
    const meta = [];
    meta.push(`${fields.length} ${fields.length === 1 ? TERMS.field : TERMS.fields}`);
    if (fields.length) meta.push(`${described} described`);
    if (s.discriminator) meta.push(`record type in ${s.discriminator}`);
    if (s.indexes && s.indexes.length) meta.push(`${TERMS.index} ${s.indexes.join(", ")}`);
    if (s.volumeMb) meta.push(`${s.volumeMb} MB in 30d`);
    if (s.eventCount) meta.push(`${s.eventCount.toLocaleString()} events seen`);
    const moved = deltaSummary(s.profileDelta);
    if (moved) meta.push(`since last profile: ${moved}`);
    return h(
      "div",
      { class: "r-stlist__row" },
      h(
        "div",
        { class: "r-stlist__name" },
        stLink(s.name),
        s.description
          ? h("p", { class: "r-secondary" }, s.description)
          : h("p", { class: "r-secondary r-muted" }, "Not described yet. ", h("a", { href: `#/st/${encodeURIComponent(s.name)}` }, "say what this feed is"), "."),
      ),
      h("div", { class: "r-stlist__meta" }, meta.join(" · ")),
      h("span", { class: "r-stlist__src" }, sourceChips(s.sources), ...healthChips(s)),
    );
  });

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("sourcetypes", sts.length),
      rows.length ? h("div", { class: "r-stlist" }, rows) : h("p", { class: "r-muted" }, "Nothing catalogued yet."),
    ),
  );

  return el;
}

export default { render, sourceChips };
