// Not-in-catalogue page: #/unknown/<name>. Ranking comes from search.matchNames.
//
// Also the unknown template every absent page draws (app.js: a route not
// on this platform, a module switched off, no such page, a render
// failure): the name, a chip saying what kind of absence this is, one
// line of why in the scope line, at most one callout, then Back, the
// alternative and Catalogue in the action row.
//
//   absentPage({ name, chip, why, callout, actions, sections })   → Element
//   backAction(goBack)                                            → the Back button

import { h } from "../components/h.js";
import { callout } from "../components/callout.js";
import { table } from "../components/table.js";
import { empty } from "../components/empty.js";
import { titleBlock, midEllipsis } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { TERMS, isSentinel } from "../lib/platform.js";
import * as modules from "../lib/modules.js";
import { matchNames, familyOf } from "../lib/search.js";
import { aboutField, aboutEvent } from "./search.js";

const MATCH_WHY = {
  exact: "the same name",
  prefix: "starts with what you typed",
  substring: "contains what you typed",
  fuzzy: "one or two characters away",
  family: "same name family: same kind of thing, different prefix",
};

export function backAction(goBack) {
  const back = typeof goBack === "function" ? goBack : () => window.history.back();
  return h("button", { type: "button", class: "r-btn", onClick: back }, "Back");
}

export function absentPage({ name, chip, why, callout: note = null, actions = [], sections = [] }) {
  return h(
    "div",
    { class: "r-view r-view--unknown r-unknown" },
    titleBlock({ kind: "page", h1: name, chips: [chip ? h("span", { class: "r-chip r-chip--state" }, chip) : null], scope: [why], callout: note, actions }),
    sections,
  );
}

function hrefFor(m) {
  return `#/${m.kind === "field" ? "f" : "e"}/${encodeURIComponent(m.name)}`;
}

// The event page is Splunk knowledge: a name whose route is not mounted
// here stays text.
function linkable(m, routes) {
  return m.kind !== "event" || routes.has("event");
}

function nameLink(m, routes, cls) {
  const code = h("code", null, m.name);
  if (!linkable(m, routes)) return code;
  return h("a", { href: hrefFor(m), class: cls, tabindex: "0" }, code);
}

export function render(ctx) {
  const { fields, catalogue } = ctx;
  const name = String(ctx.params.name || "");
  const idx = catalogue ? catalogue.searchIndex() : fields.searchIndex();
  const hits = matchNames(name, idx);
  const fam = familyOf(name);
  const top = hits[0] || null;
  const routeList = ctx.modules ? ctx.modules.routes() : modules.routes();
  const routes = new Set(routeList);

  const back = backAction(ctx.goBack || ctx.back);
  const alternative = top && linkable(top, routes)
    ? h("a", { class: "r-btn", href: hrefFor(top), title: `${top.name}: ${MATCH_WHY[top.match] || top.match}` }, `Open ${midEllipsis(top.name, 18)}`)
    : h("a", { class: "r-btn", href: `#/search?q=${encodeURIComponent(name)}` }, "Search");

  const didYouMean = top
    ? callout({
        kind: "why",
        label: "Did you mean",
        body: h(
          "div",
          null,
          h("p", null, nameLink(top, routes, "r-idlink"), `: ${MATCH_WHY[top.match] || top.match}.`),
          fam && top.match === "family"
            ? h("p", null, `Names ending in ${fam.suffix} belong to the ${fam.family} family. The near match with the same stem is `, h("code", null, fam.stem), ".")
            : null,
        ),
      })
    : null;

  const nearest = h(
    "section",
    { class: "r-section" },
    headingNode("nearest-names", hits.length),
    hits.length
      ? table({
          caption: `Names near ${name}`,
          columns: [
            { key: "name", label: "name" },
            { key: "kind", label: "kind" },
            { key: "why", label: "why it is here" },
            { key: "about", label: "what it is" },
          ],
          rows: hits.map((m) => ({
            name: nameLink(m, routes, "r-idlink r-rowlink"),
            kind: m.kind,
            why: MATCH_WHY[m.match] || m.match,
            about: m.kind === "field" ? aboutField(m.name, ctx) : aboutEvent(m.name, ctx),
          })),
        })
      : empty({
          title: "Nothing is close to that",
          line: "No catalogue name is within a couple of characters of this, and it matches no known name family.",
          moves: [
            { key: "/", text: "try a shorter fragment: substring matches count" },
            // The ioc workflow is the FDR bundle's: Splunk only.
            routes.has("workflow") && !isSentinel() ? { key: "4", text: "paste a value instead and let the classifier name it", href: "#/w/ioc" } : null,
          ].filter(Boolean),
        }),
  );

  return absentPage({
    name,
    chip: "not in the catalogue",
    why: `no ${TERMS.field} or event is called this among ${idx.fields.length} names on ${idx.sourcetypes.length} ${TERMS.sourcetypes}`,
    callout: didYouMean,
    actions: [back, alternative, h("a", { class: "r-btn", href: "#/catalogue" }, "Catalogue")],
    sections: [nearest],
  });
}

export default { render, absentPage, backAction };
