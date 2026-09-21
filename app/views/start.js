// Start page: #/
//
// The title block (Reach, the platform and the two counts, Search and the
// setup card's dismiss as the actions), the teach line, then the sections
// in the tool master's order: Setup while nothing is enabled, Workflows
// (Splunk: the FDR cards and every other pack's, one section), Tools (one
// line per non-core module that owns a tool route: a link while it is on,
// "<Module> · off · Settings" while it is off, so the way to turn it on is
// on screen; the nav draws no link for an off module).

import { h } from "../components/h.js";
import { empty } from "../components/empty.js";
import { keycap } from "../components/keycap.js";
import { onboardingCard } from "../components/onboarding.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import * as workflows from "../lib/workflows.js";
import * as packs from "../lib/packs.js";
import * as onboarding from "../lib/onboarding.js";
import { TERMS, isSentinel } from "../lib/platform.js";
import { copy } from "../lib/copy.js";
import * as modules from "../lib/modules.js";
import { PACK_ID as FALCON_PACK } from "../lib/fdr-queries.js";

// The tool routes the Tools section lists, in the nav's order; each is
// owned by a non-core module (modules.js), which is what puts it here.
export const TOOL_ROUTES = Object.freeze([
  { route: "discover", label: "Discover" },
  { route: "coverage", label: "Coverage" },
  { route: "share", label: "Share" },
]);

// One Tools line: the link while the route is mounted, the off state with
// its Settings link while the module is off, nothing while the route is
// absent on this platform.
export function toolLine(ctx, { route, label }) {
  const status = modules.routeStatus(route);
  const m = modules.routeOwner(route);
  if (status === "on") return h("li", { class: "r-tool" }, h("a", { href: `#/${route}` }, label));
  if (status !== "off" || !m) return null;
  return h(
    "li",
    { class: "r-tool r-tool--off" },
    `${m.label} · off · `,
    h("a", { href: "#/", class: "r-settings__open", onClick: (e) => { e.preventDefault(); if (ctx.openSettings) ctx.openSettings(m.id); } }, "Settings"),
  );
}

function card(ctx, c, line) {
  return h(
    "a",
    { class: "r-card", href: c.href },
    h("span", { class: "r-card__key" }, keycap({ key: c.key })),
    h("span", { class: "r-card__title" }, c.title),
    h("span", { class: "r-card__line" }, c.copy ? copy(c.copy) : c.line),
    line ? h("span", { class: "r-card__count" }, line) : null,
  );
}

// Setup: the first-install card, and on Sentinel the steps in the portal.
// Absent once an origin is enabled or the card was dismissed.
function setup() {
  const cardEl = onboardingCard();
  const section = h(
    "section",
    { class: "r-section r-setup", hidden: cardEl.hidden },
    headingNode("setup"),
    cardEl,
    isSentinel()
      ? h(
          "ol",
          { class: "r-secondary" },
          h("li", null, "Open the Logs blade on a workspace (Azure Monitor → Logs, or Sentinel → Logs), then click the Reach toolbar icon and press ", h("b", null, "Enable in the Azure portal"), ". Reload the blade once."),
          h("li", null, "Run any query. Right-click a value in the results: the blade's own menu gets a REACH section: meaning, decode, pivots with the KQL and an Open in portal link."),
          h("li", null, "Right-click a column header for the column's meaning on that table; expand a row to reach the leaves of a dynamic column."),
          h("li", null, "Reach never runs a query and never touches the network. ", h("a", { href: "#/discover" }, "Discover"), " gives you queries to run yourself and reads the results you bring back."),
        )
      : null,
  );
  const off = onboarding.subscribe(() => {
    section.hidden = !onboarding.shouldShow();
    if (!section.isConnected) off();
  });
  return section;
}

// Workflows: every pack's guided workflows as cards, the Falcon pack's
// four with their number keys, reached by click or from the popup.
function workflowSection(ctx, counts) {
  const lines = counts
    ? {
        host: `${counts.edges_confirmed} confirmed joins, aidmaster among them`,
        pid: `${counts.routes.one_hop} fields are one join from the process`,
        detection: `${counts.events_cim_gap} of ${counts.events} events have no CIM path`,
        ioc: `${counts.fields} fields, ${counts.enriched} with a written meaning`,
      }
    : {};
  // One group per pack, its workflows as cards. The Falcon pack's group
  // leads with the keyed cards (keys 1 to 4, app.js CARDS) where the
  // fields sidecar is loaded, and closes with the build's counts.
  const groups = [];
  const keyed = new Set((ctx.cards || []).map((c) => c.id));
  for (const pk of packs.list()) {
    const ws = workflows.list().filter((w) => w.packId === pk.id);
    if (!ws.length) continue;
    const withCards = counts && pk.id === FALCON_PACK;
    const cards = withCards ? (ctx.cards || []).map((c) => card(ctx, c, lines[c.id])) : [];
    const rest = withCards ? ws.filter((w) => !keyed.has(w.id)) : ws;
    groups.push(
      h(
        "div",
        { class: "r-workflows__pack" },
        h("p", { class: "r-workflows__packname" }, `${pk.name} pack`),
        h(
          "div",
          { class: "r-cards" },
          cards,
          rest.map((w) =>
            h(
              "a",
              { class: "r-card", href: workflows.href(w.id) },
              h("span", { class: "r-card__title" }, w.title),
              h("span", { class: "r-card__line" }, w.kicker),
              h("span", { class: "r-card__count" }, w.entries.length ? `from ${w.entries.map((e) => e.field).filter((f, i, a) => a.indexOf(f) === i).slice(0, 3).join(", ")}${w.entries.length > 3 ? "…" : ""}` : "a hunt: no value to start from"),
            ),
          ),
        ),
        withCards
          ? h(
              "p",
              { class: "r-muted" },
              `Built from ${counts.fields} fields and ${counts.events} events · ${counts.raw_fdr} raw, ${counts.ta_derived} TA-derived, ${counts.cim} CIM · ${counts.edges_confirmed} confirmed and ${counts.edges_asserted} asserted edges · ${counts.decode_tables} decode tables · ${counts.suggested_joins} enrichment suggestions, kept separate from the joins.`,
            )
          : h("p", { class: "r-muted" }, `${pk.fields} fields · ${pk.edges} pivots · ${pk.workflows} workflows · ${pk.description}`),
      ),
    );
  }
  return h("section", { class: "r-section r-workflows" }, headingNode("workflows"), groups);
}

function toolsSection(ctx) {
  const lines = TOOL_ROUTES.map((t) => toolLine(ctx, t)).filter(Boolean);
  if (!lines.length) return null;
  return h("section", { class: "r-section r-tools" }, headingNode("tools"), h("ul", { class: "r-tools__list" }, lines));
}

export function render(ctx) {
  const { fields } = ctx;
  const fdr = !isSentinel() && fields.loaded();
  const el = h("div", { class: "r-view r-view--start" });
  const sts = ctx.catalogue.sourcetypes();
  const packList = packs.list();
  const model = onboarding.cardModel();

  el.appendChild(
    titleBlock({
      kind: "page",
      h1: "Reach",
      scope: [
        TERMS.platform,
        h("a", { href: "#/catalogue" }, `${sts.length} ${sts.length === 1 ? TERMS.sourcetype : TERMS.sourcetypes}`),
        h("a", { href: "#/packs" }, `${packList.length} pack${packList.length === 1 ? "" : "s"}`),
      ],
      actions: [
        h("button", { type: "button", class: "r-btn r-btn--primary", title: "Search (/)", onClick: () => ctx.focusSearch && ctx.focusSearch() }, "Search"),
        model.show ? h("button", { type: "button", class: "r-btn", title: "Hide the setup card; Settings brings it back", onClick: () => onboarding.dismiss() }, "Hide setup") : null,
      ],
    }),
  );

  el.appendChild(
    h(
      "div",
      { class: "r-lede" },
      h(
        "p",
        { class: "r-lede__line" },
        fdr
          ? "Field meaning, and what to run."
          : `What each ${TERMS.field} means, and what to run.`,
      ),
      empty({
        title: "What are you looking at?",
        line: copy(fdr ? "start.line.fdr" : "start.line"),
        moves: [
          { key: "/", text: fdr ? "a sourcetype, a field, a hash, an IP, a PID" : `a ${TERMS.sourcetype} or ${TERMS.field} name, a hash, an IP` },
        ],
      }),
    ),
  );

  el.appendChild(setup());
  if (modules.on("workflows") && (fdr || workflows.list().length)) el.appendChild(workflowSection(ctx, fdr ? fields.counts() : null));
  el.appendChild(toolsSection(ctx));
  return el;
}

export default { render, toolLine, TOOL_ROUTES };
