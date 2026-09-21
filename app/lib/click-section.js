// The REACH section for a click, assembled once for every host: the
// Splunk value popup, the Splunk field popdown and JSON key, the Sentinel
// grid's menu. One walk over the band order (modules.js BANDS, the off
// modules gone) draws each band from the same block the
// value page draws (popup-ui.js), and the hooks carry what genuinely
// differs between the hosts: how a pivot runs (a live search here, a deep
// link into the Logs blade), whether the editor takes an insert, the
// pattern test, and where a click with no container is placed.
//
//   sectionFor({ platform, click, ctx, lib, hooks }) → Promise<{ el, panel } | null>
//       click   { kind: "value" | "field", name, value }
//       ctx     click-context.js clickContext()
//       lib     { catalogue, modules, runbooks, keys, runtime, enrich, packs, workflows, bridge, fields?, resolve? }
//       hooks   {
//         names(raw, container) → { name, fallback }     the catalogue's name for the clicked one
//         place(m) → placement                             a click whose container is unknown (see placeClick)
//         pivots(m) → { el, n, fold } | null               the Pivots band
//         insert(m) → Promise<fn | null>                   the editor write, when the host's editor answers
//         pattern(m) → { fieldClass, liveTest }            what only the host adds to the pattern block
//         scopeFor(m) → Promise<string | null>             the scope a pivot binds when the row names none
//         appUrl(hash)                                     the app's URL for a hash
//       }
//       el is the .reach-section; panel is true when the window's side
//       panel took the click and el is the one line the page shows.
//       null when there is nothing to say: the caller stays out of the
//       host's own popup.
//   placeClick(m) → { name, container, view, scopeText, everywhere, head, bare }
//       the default placement: the container the context names, else the
//       one candidate the catalogue places the field on, else the name
//       alone; bare when nothing anywhere knows the name.
//   packEdgeRows(m, control, { before, after, summary }) → [Element]
//       one disclosure per pack edge from the field on the container,
//       parameters bound off the row (before(params, meta) ahead of the
//       row, after(params, meta) for what it left unbound), the edge's
//       control(edge, params, meta) drawn on the first open, summary(edge,
//       container) after the basis chip.
//   pivotNames(m, hint) → Element | null
//       the edges by name, for a field click.
//   viewFor(catalogue, container, name, fallback)
//
// DOM module (uses h.js). Never fetches on its own; a band's own network
// call (an enrichment source, a live run) stays behind its button.

import { h } from "../components/h.js";
import * as ui from "./popup-ui.js";
import { termsFor } from "./platform.js";

export function viewFor(catalogue, container, name, fallback = null) {
  if (!container) return null;
  return catalogue.fieldOn(container, name) || (fallback && fallback !== name ? catalogue.fieldOn(container, fallback) : null);
}

// A view for a name the FDR bundle knows without a sourcetype in reach
// (Splunk), so the meaning band still reads.
function bundleView(rec, name) {
  if (!rec) return { sourcetype: null, name, meaning: { description: null, source: null }, taxonomy: { role: null, tags: [] }, pack: null, user: null };
  return { sourcetype: null, name, meaning: rec.meaning && rec.meaning.description ? { description: rec.meaning.description, notes: rec.meaning.hunting_notes, source: "pack", basis: rec.meaning.source, confidence: rec.meaning.confidence } : { description: null, source: null }, taxonomy: { role: rec.role, tags: [] }, pack: rec, user: null };
}

export function placeClick(m) {
  const { ctx, catalogue, names, TERMS, lib } = m;
  const disc = ctx.discriminator ? ` · ${ctx.discriminator.value}` : "";
  let name = names.name;
  if (ctx.container) {
    const c = ctx.container;
    const view = viewFor(catalogue, c, name, names.fallback);
    let scopeText;
    if (ctx.basis.container === "column") scopeText = `on ${c}${disc}, the one ${TERMS.sourcetype} with a column ${name}`;
    else if (view && (view.pack || view.packField)) scopeText = view.scope === "sourcetype" ? `on ${c}${disc}` : `${c}${disc}, field known, never observed on any ${TERMS.sourcetype}`;
    else if (view) scopeText = `on ${c}${disc}, your catalogue`;
    else scopeText = `on ${c}${disc}, not catalogued`;
    return { name, container: c, view, scopeText, everywhere: catalogue.fieldEverywhere(name).filter((r) => r.sourcetype !== c), head: [], bare: false };
  }
  // Several containers in reach (a page mixing sourcetypes, a query
  // naming several tables): the first the catalogue places the field on.
  if (ctx.candidates.length > 1) {
    const hits = ctx.candidates.filter((c) => viewFor(catalogue, c, name, names.fallback));
    const c = hits[0] || null;
    const scopeText = hits.length
      ? `results mix ${ctx.candidates.length} ${TERMS.sourcetypes}: catalogued on ${hits.join(", ")}; not on ${ctx.candidates.filter((s) => !hits.includes(s)).join(", ") || "the others"}`
      : `results mix ${ctx.candidates.length} ${TERMS.sourcetypes}: not catalogued on any of them`;
    if (c && m.hooks.names) name = { ...names, ...m.hooks.names(names.raw, c) }.name; // the name the container knows it under
    const view = c ? viewFor(catalogue, c, name, names.fallback) : null;
    const everywhere = c ? catalogue.fieldEverywhere(name).filter((r) => r.sourcetype !== c) : catalogue.fieldEverywhere(name);
    return { name, container: c, view, scopeText, everywhere, head: [], bare: false };
  }
  // No container anywhere: the name alone, every container carrying it
  // listed so the analyst can tell which one this is. The FDR bundle's
  // record, when the name is one of its fields, still gives a meaning.
  const rec = lib.fields ? lib.fields.field(name) : null;
  let everywhere = catalogue.fieldEverywhere(name);
  if (!everywhere.length && name !== names.raw) {
    name = names.raw;
    everywhere = catalogue.fieldEverywhere(name);
  }
  // A key clicked in an event always gets a section (the host draws no
  // popup of its own there); a value or the sidebar's field with nothing
  // known anywhere is bare: Hold and the enrichment row, or nothing.
  const bare = !rec && !everywhere.length && !(m.click.kind === "field" && ctx.row);
  const scopeText = bare
    ? "field not catalogued"
    : everywhere.length > 1
      ? `${TERMS.sourcetype} unknown here: carried on ${everywhere.length} ${TERMS.sourcetypes}`
      : everywhere.length === 1
        ? `${TERMS.sourcetype} unknown here: carried on ${everywhere[0].sourcetype}`
        : `${TERMS.sourcetype} unknown here: matched by name only`;
  return { name, container: null, view: bare ? null : bundleView(rec, name), scopeText, everywhere, head: [], bare };
}

const BASIS_TEXT = { confirmed: "confirmed", confirmed_ta: "confirmed", validated: "validated", proposed: "proposed" };
export const basisText = (basis) => BASIS_TEXT[basis] || "asserted";

export function packEdgeRows(m, control, { before = null, after = null, summary = null } = {}) {
  const { lib, ctx, edges, value, container } = m;
  const rows = [];
  for (const edge of edges) {
    const pmeta = lib.packs.params(edge.packId, edge.src.sourcetype); // a v2 pack's from_concept becomes this container's column
    const params = { value };
    if (before) before(params, pmeta); // a scope the row does not name, bound ahead of the row's own fields
    for (const [pname, pm] of Object.entries(pmeta)) {
      if (pm.from_field && params[pname] === undefined) {
        const v = ctx.read(pm.from_field);
        if (v) params[pname] = v;
      }
    }
    if (after) after(params, pmeta); // a default for what the row left unbound
    const body = h("div");
    rows.push(
      h(
        "details",
        { class: "reach-details reach-edge", onToggle: (e) => { if (e.target.open && !body.childElementCount) body.appendChild(control(edge, params, pmeta)); } },
        h("summary", { class: "reach-summary" }, edge.label, " ", h("span", { class: "reach-chip", dataset: { basis: basisText(edge.basis) } }, basisText(edge.basis)), summary ? summary(edge, container) : null),
        edge.note ? h("div", { class: "reach-row__body reach-row__body--muted" }, edge.note) : null,
        body,
      ),
    );
  }
  return rows;
}

export function pivotNames(m, hint) {
  if (!m.edges.length) return null;
  return h("div", { class: "reach-edges" }, h("div", { class: "reach-row__body reach-row__feeds" }, m.edges.map((e) => e.label).join(" · "), hint));
}

// The enrichment row: bundled sources read only packaged data; a fetch
// source asks the background worker only from a click on its button.
async function enrichOffer(m) {
  const { lib, platform, click, value, hold } = m;
  const sources = lib.modules.sources(platform);
  if (!sources.length) return null;
  const { ask, optionsUrl } = lib.runtime;
  const enabledIds = await lib.enrich.enabledIds(ask);
  const offers = lib.enrich.offersFor(value, { fieldName: click.name, enabledIds, sources });
  const settingsUrl = (source) => {
    const owner = lib.modules.sourceOwner(source.id);
    return optionsUrl(platform, lib.modules.anchor(owner ? owner.id : ""));
  };
  return ui.enrichBlock({ value, offers, ask, settingsUrl, hold });
}

export async function sectionFor({ platform, click, ctx, lib, hooks = {} }) {
  const { catalogue, modules } = lib;
  const TERMS = termsFor(platform);
  const on = (id) => modules.on(id, platform);
  const isValue = click.kind === "value";
  const value = isValue ? String(click.value ?? "") : "";
  const raw = click.name;
  const ruleKey = on("runbooks") && Object.keys(ctx.alertRow).length ? lib.runbooks.ruleKeyFor(ctx.alertRow, platform) : null;

  // A side panel open in this window takes the click; the page shows one line.
  const provenance = { event: ctx.event, search: ctx.search || { text: "" }, scope: ctx.scope || "" };
  if (await ui.offerToPanel({ platform, kind: click.kind, name: raw, value, sourcetype: ctx.container, index: platform === "splunk" ? ctx.scope : null, discriminator: ctx.discriminator, event: ctx.eventFields, provenance })) {
    return { el: ui.panelLine(), panel: true };
  }

  const appUrl = hooks.appUrl || ((hash) => lib.runtime.appUrl(platform, hash));
  // The field catalogue of the click's container, fetched on first need
  // (a popup loads the catalogue lazily: a tab on a feed with no such
  // sidecar never parses one); with no container known, the sidecars of
  // every container this platform knows, so a name can still be placed.
  await catalogue.loadFields(ctx.container || undefined);
  const names = { raw, fallback: null, ...(hooks.names ? hooks.names(raw, ctx.container) : { name: raw }) };
  const m = { platform, click, ctx, lib, hooks, TERMS, on, isValue, value, names, catalogue, appUrl, ruleKey };
  const place = (hooks.place || placeClick)(m);
  const { name, container, view, scopeText, everywhere, bare } = place;
  Object.assign(m, { name, container, view, everywhere, bare });
  // Several tables share the column on one concept (Sentinel): the
  // meaning reads off the first, the pivots wait for the table.
  m.meaningContainer = place.meaningContainer || container;

  const inject = on("benign") && modules.setting("benign", lib.keys.benignInject) === true;
  const notebookUrl = appUrl("#/notebook");
  // The clicked value's pin: only the Hold button writes it.
  m.hold = isValue ? { field: name, value, container, platform, scope: ctx.scope, event: ctx.event, search: ctx.search === null ? null : ctx.searchNow, notebookUrl } : null;
  m.insert = isValue && (on("benign") || on("pattern")) ? (hooks.insert ? await hooks.insert(m) : null) : null;
  m.enrichEl = isValue ? await enrichOffer(m) : null;
  m.edges = container && !bare ? catalogue.edgesFrom(container, name) : [];
  m.scope = isValue && !bare && hooks.scopeFor ? await hooks.scopeFor(m) : ctx.scope;
  const scopeEl = ui.scopeLine(scopeText);
  const headEl = place.head && place.head.length ? h("div", { class: "reach-head" }, scopeEl, ...place.head) : scopeEl;
  const samples = view && view.profile ? view.profile.top : null;
  // The decode table for the value line: the view's, else the FDR bundle's for its own field.
  const decode = (view && view.decode) || (lib.fields && view && view.pack ? lib.fields.decode(view.pack.name) : null);
  const pivots = bare ? null : hooks.pivots ? hooks.pivots(m) : null;
  const patternExtra = hooks.pattern ? hooks.pattern(m) : {};

  const parts = ui.walkBands(modules.bands(platform), (id) => {
    switch (id) {
      case "scope":
        return headEl;
      case "runbook":
        return ruleKey ? ui.runbookBlock({ ruleKey, row: ctx.alertRow, platform, appUrl }) : null;
      case "hold":
        return m.hold ? ui.holdBlock(m.hold) : null;
      case "benign":
        return m.hold ? ui.benignBlock({ ...m.hold, samples, onInsert: inject ? m.insert : null }) : null;
      case "value":
        return isValue && !bare ? ui.valueBlock({ field: name, value, container: m.meaningContainer, platform, catalogue, view: decode ? { ...(view || {}), decode } : view }) : null;
      case "meaning":
        return bare ? null : ui.meaningBlock({ view, sourcetype: container, name, catalogue, appUrl, scopeEl, value: isValue ? value : undefined, index: platform === "splunk" ? ctx.scope : undefined });
      case "everywhere":
        return bare ? null : { el: ui.everywhereBlock({ rows: everywhere, name, appUrl, titled: false, platform }), n: everywhere.length, fold: true };
      case "verdict":
        return isValue && !bare ? { el: ui.verdictBlock({ field: name, value, container: m.meaningContainer, platform, event: ctx.eventFields, catalogue, view, hold: m.hold, titled: false, appUrl }) } : null;
      case "enrich":
        return { el: m.enrichEl };
      case "pivots":
        return pivots;
      case "workflows":
        return bare ? null : { el: ui.workflowsBlock({ rows: lib.workflows.forField(container, name), value: isValue ? value : null, appUrl, href: lib.workflows.href, sourcetype: container, titled: false, platform }), fold: true };
      case "pattern":
        return isValue && !bare ? { el: ui.patternBlock({ value, field: name, container: m.meaningContainer, platform, samples, onInsert: m.insert || undefined, ...patternExtra }), fold: true } : null;
      default:
        return null;
    }
  }, { platform });

  if (parts.length <= 1) return null; // the scope line alone says nothing
  return { el: h("div", { class: "reach-section" }, h("span", { class: "reach-badge" }, "REACH"), ...parts), panel: false };
}

export default { sectionFor, placeClick, packEdgeRows, pivotNames, viewFor, basisText };
