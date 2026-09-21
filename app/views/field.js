// Field page: #/f/<name>?st=<sourcetype>&on=<event>&sel=<rowId>&value=<clicked>
// The title block (what this field is, which sourcetype and record type,
// the value the click carried), then the sections in the entity master
// order (headings.js ENTITY_ORDER): Meaning, Other sourcetypes, Values,
// Verdict and Enrichment for the page's value, Pivots (the pack's edges, then
// the FDR ledger's five bands), Workflows, Pattern, Profile, Extraction,
// CIM mapping, Query advisor. One template for a bundle field and for a
// field only the user or discovery knows; what a path cannot fill is absent.
// Reachability is read off the selected event, not the field. All SPL comes
// from fdr-queries.generate().

import { decodeWidget } from "../components/convert.js";
import { h } from "../components/h.js";
import { fillFrom } from "../components/drawer.js";
import { stLink, fieldLink, eventLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { ledger } from "../components/ledger.js";
import { meaning } from "../components/meaning.js";
import { sourceTable } from "../components/sourceTable.js";
import { callout } from "../components/callout.js";
import { titleBlock, midEllipsis } from "../components/titleBlock.js";
import * as fdr from "../lib/fdr-queries.js";
import { TIME_HINT } from "../lib/spl.js";
import { EDGE_ORDER, isAutomaticOn, edgeRowsFor, pivotForEdgeRow, baseParamsForRow } from "../lib/reachability.js";
export { isAutomaticOn, edgeRowsFor, pivotForEdgeRow, baseParamsForRow };
import { familyOf } from "../lib/search.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import * as lastEvent from "../lib/last-event.js";
import * as unknownView from "./unknown.js";
import { annotation } from "../components/annotation.js";
import { profileBlock, measuredLine } from "../components/profile.js";
import { provenanceBlock } from "../components/provenance.js";
import { packPivots } from "../components/packPivots.js";
import { dictionaryBlock, conceptHazard } from "../components/dictionary.js";
import * as taxonomy from "../lib/taxonomy.js";
import { bitmaskParts } from "../lib/values.js";
import { advisorSection } from "../components/advisor.js";
import * as modules from "../lib/modules.js";
import { isSentinel, TERMS } from "../lib/platform.js";
import { ENTITY_ORDER, heading, headingNode } from "../lib/headings.js";
import { LEARNED_ID } from "../lib/learned.js";
import * as packs from "../lib/packs.js";
import * as layer from "../lib/layer.js";
import * as workflows from "../lib/workflows.js";
import { valueEntry, workflowsBlock } from "../lib/popup-ui.js";
import { verdictSection, enrichSection, patternSection, holdAction, benignAction, keepRow } from "./value.js";
import * as runbooks from "../lib/runbooks.js";

export const NO_FILL_RATES =
  "Grouped by role, then alphabetical. No fill-rate data is available for ordering.";
export const fillRatesNote = (evRec, runId) =>
  `Grouped by role, then by fill rate measured in run ${runId}: ${evRec.tenant.count} ${evRec.name} events on ${evRec.tenant.hosts} hosts.`;

const ROUTE_TEXT = {
  direct_anchor: { chip: "here", label: "on an anchor event" },
  one_hop: { chip: "one-hop", label: "one join to the process" },
  host_only: { chip: "dead-end", label: "host and time only" },
  mixed: { chip: "one-hop", label: "depends on the event" },
  unobserved: { chip: "dead-end", label: "never observed" },
  derived: { chip: "dead-end", label: "computed field" },
};

const BASIS_LABEL = {
  decode_table: "the TA's decode table",
  meaning_sibling: "a sibling *_meaning field",
  dotted_prefix: "the dotted name prefix",
  name_convention: "the name convention",
  enrichment: "AI enrichment",
  none: "nothing: it stayed unclassified",
};

const PARAM_META = {
  aid: { placeholder: "32-hex agent id", hint: "The host. Both PID spaces are per-host, and ComputerName is not stable; aid is." },
  earliest: { placeholder: "-24h", hint: TIME_HINT },
  latest: { placeholder: "now", hint: TIME_HINT },
  value: { placeholder: "the value you hold" },
  pid: { placeholder: "OS PID" },
  tpid: { placeholder: "TargetProcessId" },
  hostname: { placeholder: "COMPUTERNAME" },
  field: {},
  event: {},
  index: { placeholder: "leave empty to use the cs_index macro" },
  sourcetype: {},
};

// The join hazard on a curated field with safe_to_join false: the label and
// body are the title block's callout, `more` follows them in Meaning.
export const UNSAFE_JOIN = Object.freeze({
  label: "Not safe to join on",
  body: "Scope by aid and a time window.",
  more: "Expect multiple matches: the generated search requires both.",
});

// A hazard's text split for the title block: the first sentence is the
// callout's body, the rest a line in Meaning.
export function splitHazard(text) {
  const t = String(text || "").trim();
  const m = /^(.+?[.!?])\s+(\S[\s\S]*)$/.exec(t);
  return m ? { lead: m[1], rest: m[2] } : { lead: t, rest: "" };
}

const PID_HANDLES = new Set(["TargetProcessId", "ContextProcessId", "ParentProcessId", "RawProcessId"]);

// A missing macro's one-line define hint for the drawer's macro tab. Only
// cs_index has a definition Reach can derive (the scope index this pivot
// resolved, or a placeholder when nothing resolved it); the TA's other
// macros ship with the Add-on, so Reach names them without guessing their body.
export function macroDefineHint(name, resolvedIndex) {
  if (name === "cs_index") {
    const def = resolvedIndex ? `index=${resolvedIndex}` : "index=<your index>";
    return `Settings > Advanced search > Search macros: name cs_index, definition ${def}.`;
  }
  return `Settings > Advanced search > Search macros: name ${name} (from the CrowdStrike Falcon Add-on; Reach has no definition to suggest).`;
}

// The pack macros a rendered form needs, checked against whatever a
// discovered Splunk environment's provenance step found (discovery.js:
// conf-macros, scoped to the pack's macro list). One environment is
// assumed, matching the single-Splunk-instance model the rest of the
// drawer (Run in Splunk's base URL) already uses; several discovered
// environments pick the first rather than guess which one the user means.
export function macroInfo(names, macroEnv, resolvedIndex) {
  const env = macroEnv ? macroEnv.origin : null;
  const known = macroEnv ? macroEnv.macros : null;
  const needed = (names || []).map((name) => {
    const rec = known && known[name];
    const defined = rec ? rec.defined : null;
    return { name, defined, hint: defined === false ? macroDefineHint(name, resolvedIndex) : undefined };
  });
  return { env, needed };
}

// edgeRowsFor / pivotForEdgeRow / baseParamsForRow / isAutomaticOn / EDGE_ORDER
// moved to ../lib/reachability.js (shared with the Splunk extension) and
// re-exported below for existing callers (tests/views.test.js, default export).

// ---------------------------------------------------------------------------

function layerChip(rec) {
  return chip({ kind: "layer", value: rec.layer });
}

// The chip's short form keeps the title block's chip row to one line at
// 320; the route's label is the chip's title.
function routeChip(rec) {
  const r = ROUTE_TEXT[rec.route && rec.route.summary] || ROUTE_TEXT.mixed;
  return chip({ kind: "route", value: r.chip, title: r.label });
}

export function basisChip(edge) {
  if (edge.cardinality === "unsafe" || edge.hazard) return chip({ kind: "hazard", text: "unsafe key" });
  if (edge.basis === "confirmed_ta") return chip({ kind: "trust", value: "confirmed", title: edge.basis_ref });
  if (edge.basis === "validated" && edge.validation) {
    return chip({ kind: "trust", value: "validated", text: `validated ${Math.round(edge.validation.rate * 100)}%`, title: edge.basis_ref });
  }
  return chip({ kind: "trust", value: "asserted", title: edge.basis_ref });
}

function scopeText(edge) {
  const s = Array.isArray(edge.scope) ? edge.scope : [];
  if (!s.length) return "global";
  if (s.includes("time")) return "same aid and time window";
  return "same " + s.join(" and ");
}

function handlesCell(evRec) {
  const hs = (evRec && evRec.handles) || [];
  if (!hs.length) return h("span", { class: "r-muted" }, "none");
  return h("span", { class: "r-inline" }, hs.flatMap((n, i) => [i ? " " : null, h("code", null, n)]));
}

function cimCell(evRec) {
  if (evRec && evRec.cim && evRec.cim.normalized) {
    return h("span", null, (evRec.cim.data_models || []).join(", ") || "normalized");
  }
  return h("span", { class: "r-muted" }, "no CIM path");
}

// The sourcetype (container) a field page leads with, and every container
// that carries the name: ?st= if given, kept even when the catalogue places
// the field nowhere on it (a popup links here so the user can describe it
// there); else a container ?on= actually names, since a click with no
// separate sourcetype in its link can carry the container under that key
// instead (an FDR event name, the usual meaning of ?on=, never resolves
// here and falls through); else the catalogue's own default order. The pack
// bound to the container this picks leads everywhere on the page: heading,
// description, values table, provenance chip, dictionary block. Every other
// pack's meaning for the same column name is "also on".
export function resolveContainer(name, params, catalogue) {
  const knownOn = catalogue ? catalogue.sourcetypes().map((s) => s.name).filter((st) => catalogue.fieldOn(st, name)) : [];
  const onHint = catalogue ? catalogue.leadingContainer(name, [params.on]) : null;
  const st = params.st ? params.st : onHint || knownOn[0] || null;
  return { st, knownOn };
}

// ---------------------------------------------------------------------------

export function render(ctx) {
  const { fields, catalogue } = ctx;
  const name = ctx.params.name;

  // The value the click carried stays in the URL (?value=), whether the
  // panel's route (app/lib/selection.js) or a tab opened from an in-page
  // popup's "Open in Reach →" link (app/lib/popup-ui.js fieldHash): the
  // page reads it there on every render and holds nothing. The index such
  // a link carries is not held either: it is scope, learned for the
  // sourcetype the event was on (scope.js) and dropped from the URL.
  if (ctx.params.index) {
    if (ctx.params.st) scope.learn(ctx.params.st, ctx.params.index);
    const { index, ...rest } = ctx.params;
    ctx.setUrl("field", rest);
  }

  const rec = fields.field(name);

  const { st, knownOn } = resolveContainer(name, ctx.params, catalogue);
  const view = st && catalogue ? catalogue.fieldOn(st, name) : null;

  // The FDR ledger is FDR's: a name the bundle also knows (user, src, app,
  // status, dvc… are CIM names in both worlds) scoped to a sourcetype the
  // bundle does not carry is that sourcetype's page, not FDR's.
  const fdrSourcetype = !st || fields.sourcetypes().includes(st);
  if (!rec || !fdrSourcetype) {
    if (!view && !ctx.params.st) return unknownView.render({ ...ctx, params: { ...ctx.params, name } });
    const bare = { sourcetype: st, name, meaning: { description: null, source: null }, taxonomy: { role: null, tags: [] }, pack: null, user: null, profile: null, provenance: null, decode: null, scope: "none" };
    return page(ctx, { name, st, view: view || bare, knownOn, rec: null, events: [], on: null, evRec: null });
  }

  // `on` is the bundle event the ledger, co-fields and routes key on; the
  // record type the click named stays in the URL and on the scope line
  // whether or not the corpus registered the field on it. A page opened
  // with no record type takes the first registered event and writes it.
  const events = rec.events || [];
  const bundleName = ctx.params.on ? fields.eventName(ctx.params.on) : null;
  const on = ctx.params.on ? (bundleName && events.includes(bundleName) ? bundleName : null) : events[0] || null;
  if (on && !ctx.params.on) ctx.setUrl("field", { ...ctx.params, name, on });
  const evRec = on ? fields.event(on) : null;
  return page(ctx, { name, st, view, knownOn, rec, events, on, evRec });
}

// What the page's literal means on this field: the pack's dictionary entry,
// the decode table (the pack's, discovery's or the FDR TA's), or nothing.
function decodeOf({ ctx, st, name, view, rec, value }) {
  const row = valueEntry({ catalogue: ctx.catalogue, container: st, field: name, value, view });
  if (row && row.kind === "entry") return row.meaning;
  const dec = rec ? ctx.fields.decode(rec.name) : null;
  if (dec && dec.values && Object.prototype.hasOwnProperty.call(dec.values, value)) return String(dec.values[value]);
  return null;
}

// A bitmask value on the title block: its own name and the count of flags
// it sets on the line, the flag names folded closed under it. The joined
// list is the popup's and the value page's line; the title block has one
// line to give at 320.
function bitmaskFold({ view, value }) {
  const dict = view && view.concept && view.concept.type === "bitmask" ? view.dictionary : null;
  const parts = dict ? bitmaskParts({ values: dict.values, flags: dict.flags }, value) : null;
  if (!parts) return null;
  const n = parts.flags.length;
  // A named whole value covers its bits by definition; only an unnamed one shows a remainder.
  const tail = [n ? `${n} flag${n === 1 ? "" : "s"}` : null, parts.rest && parts.name === null ? `+0x${parts.rest}` : null].filter(Boolean).join(" · ");
  // The name gives way first at 320; the count stays whole.
  const line = [parts.name ? h("span", { class: "r-title__decode-name", title: parts.name }, parts.name) : null, parts.name && tail ? h("span", { class: "r-muted" }, " · ") : null, tail ? h("span", { class: "r-title__decode-count" }, tail) : null];
  if (!n) return { line, fold: null };
  const fold = h("ul", { class: "r-title__flaglist" }, parts.flags.map((f) => h("li", null, h("code", null, f))));
  return { line, fold };
}

// How many values this field decodes: the dictionary's, else the decode
// table's. Null while the pack's values sidecar is still on its way.
function decodeCount({ ctx, st, name, view, rec }) {
  const dict = view && view.dictionary;
  if (dict && dict.count) return dict.count;
  const dec = rec ? ctx.fields.decode(rec.name) : null;
  if (dec && dec.values) return Object.keys(dec.values).length;
  if (view && view.decode && view.decode.values) return Object.keys(view.decode.values).length;
  if (st && ctx.catalogue && !ctx.catalogue.valuesReady(st)) return null;
  return 0;
}

// Scroll a section to sit under the pinned frame (the sticky bar), not
// behind it.
function reveal(el) {
  if (!el || typeof el.getBoundingClientRect !== "function") return;
  if (el.tagName === "DETAILS") el.open = true;
  const bar = document.querySelector(".r-bar");
  const offset = bar ? bar.offsetHeight + 8 : 0;
  const top = el.getBoundingClientRect().top + (window.scrollY || 0) - offset;
  if (typeof window.scrollTo === "function") window.scrollTo(0, Math.max(0, top));
}

// A link that scrolls to a section on this page; a hash link would be a route.
function jumpLink(text, target, attrs = {}) {
  return h(
    "a",
    {
      href: "#",
      class: "r-idlink",
      ...attrs,
      onClick: (e) => {
        e.preventDefault();
        reveal(typeof target === "function" ? target() : target);
      },
    },
    text,
  );
}

// The decode chip: `decode …` while the values load, then `decode (N)`
// linking to Values, or `no decode`.
function decodeChip(count, valuesSection, { flags = false } = {}) {
  const el = h("span", { class: "r-chip r-chip--decode", dataset: { state: count === null ? "pending" : count ? "some" : "none" } });
  if (count === null) el.textContent = "decode …";
  else if (count) el.appendChild(jumpLink(flags ? `${Number(count).toLocaleString("en-US")} flags` : `decode (${Number(count).toLocaleString("en-US")})`, valuesSection, { class: "" }));
  else el.textContent = "no decode";
  return el;
}

// A bitmask concept's chip counts its flags (`19 flags`, short enough to
// share the row with the pack chip at 320); the whole values it names
// besides are in the same table on the page.
function chipFlags(view) {
  const dict = view && view.concept && view.concept.type === "bitmask" ? view.dictionary : null;
  return dict && dict.flags ? { flags: true, count: Object.keys(dict.flags).length } : null;
}

// The value the page is on: the route's ?value=, else the value the last
// click carried when it was on this field and container (last-event.js).
// Never a held store: what the analyst holds is the notebook's, and a
// value held earlier does not become the page's.
export function carriedValue(ctx, { name, st }) {
  if (!st) return "";
  if (ctx.params.value) return String(ctx.params.value);
  const c = lastEvent.clicked(st);
  return c && c.field === name ? String(c.value) : "";
}

// The chips, scope line, callout slot, value line and action row on a field
// page, then the sections in the entity master order. `rec` is the FDR
// bundle's record (null off the bundle); `view` is what the catalogue holds
// for the name on `st`.
function page(ctx, { name, st, view, knownOn, rec, events, on, evRec }) {
  const { catalogue } = ctx;
  const compact = ctx.compact === true;
  const root = h("div", { class: "r-view r-view--field" });
  const sections = new Map(); // registry id → section element
  const value = carriedValue(ctx, { name, st });
  const stPackId = st && catalogue && catalogue.sourcetype(st) ? catalogue.sourcetype(st).packId : null;
  const prov = rec ? roleProvenance(rec, view) : null;

  // ---- Meaning ----------------------------------------------------------
  const own = view && (view.user || view.concept);
  // The join hazard: its label and first line are the title block's
  // callout; the rest is a line here.
  const unsafe = rec && rec.meaning && rec.meaning.source === "curated" && rec.meaning.safe_to_join === false;
  const hazard = view ? conceptHazard(view) : null;
  const hazardText = !unsafe && hazard ? splitHazard(hazard.text) : null;
  // The bound concept's taxonomy type, for the pid family only (an OS pid
  // and a sensor's own pid are easy to confuse), once neither hazard above
  // already covers the ground: head the type's label and description,
  // body its first hazard. Meaning's own callout, drawn only on the field
  // page; annotation() draws it first when set.
  let typeHead = null;
  if (!unsafe && !hazard && view && view.concept && view.concept.type) {
    const typeRec = taxonomy.type(view.concept.type);
    const typeHazard = typeRec && typeRec.role === "pid" ? typeRec.hazards[0] : null;
    if (typeHazard) {
      const kind = typeHazard.level === "danger" ? "hazard" : typeHazard.level === "caution" ? "caution" : "note";
      typeHead = { kind, label: `${typeRec.label} · ${typeRec.description}`, body: typeHazard.text };
    }
  }
  const note = st ? annotation({ view: view || { name, sourcetype: st, meaning: {}, taxonomy: {} }, sourcetype: st, name, catalogue, compact: !own && Boolean(rec), typeHead, onSaved: () => ctx.navigate("field", { ...ctx.params, name, st }) }) : null;
  const bundleMeaning = rec && !own
    ? rec.meaning
      ? meaning({ description: rec.meaning.description, hunting_notes: rec.meaning.hunting_notes, data_format: rec.meaning.data_format, source: rec.meaning.source, confidence: rec.meaning.confidence, evidence: rec.meaning.evidence, basis_ref: rec.meaning.basis_ref, data_model: rec.meaning.data_model })
      : meaning({ absent: true })
    : null;
  if (bundleMeaning && rec.meaning && rec.meaning.source === "enrichment") {
    const det = bundleMeaning.querySelector("details");
    if (det) det.setAttribute("open", "");
  }
  const roleLine = prov
    ? h(
        "p",
        { class: "r-hold__role" },
        h("span", { class: "r-muted" }, "role "),
        h("code", null, prov.role),
        h("span", { class: "r-muted" }, ", read from "),
        prov.from,
        rec.type ? h("span", { class: "r-muted" }, ` · type ${rec.type}`) : null,
        rec.legacy ? h("span", { class: "r-muted" }, " · legacy twin") : null,
        rec.in_catalogue || !prov.inferred ? null : h("span", { class: "r-muted" }, " · not in the field catalogue"),
      )
    : null; // off the bundle the annotation block's taxonomy line names the role
  const unsafeLine = unsafe
    ? h("p", { class: "r-secondary r-meaning__unsafe" }, `${UNSAFE_JOIN.label}: ${UNSAFE_JOIN.more}`)
    : hazardText && hazardText.rest
      ? h("p", { class: "r-secondary r-meaning__unsafe" }, `${hazard.level === "danger" ? "Hazard" : "Caution"}: ${hazardText.rest}`)
      : null;
  const disagreement = rec && rec.role_disagreement
    ? h("p", { class: "r-secondary r-meaning__disagree" }, `Two sources disagree: ${BASIS_LABEL[rec.role_basis] || rec.role_basis} says ${rec.role}; enrichment says ${rec.role_disagreement.enrichment || Object.values(rec.role_disagreement)[0]}. The convention wins because it is checkable against FDR's own naming, but both are kept.`)
    : null;
  const sameRole = !compact && rec && (rec.same_role_fields || []).length
    ? h(
        "details",
        { class: "r-samerole" },
        h("summary", null, heading("same-role-fields", rec.same_role_fields.length)),
        h("p", { class: "r-muted" }, "Fields sharing this role by name convention. Reference only, never a join."),
        h("p", { class: "r-inline" }, rec.same_role_fields.flatMap((n, i) => [i ? " · " : null, fieldLink(n)])),
      )
    : null;
  sections.set(
    "meaning",
    h(
      "section",
      { class: "r-section r-meaning-section" },
      headingNode("meaning"),
      own || !rec ? note : bundleMeaning,
      !own && rec ? note : null,
      !rec && !own ? h("p", { class: "r-secondary" }, `No pack covers this ${TERMS.field}, so there is no pivot graph for it: what follows is what you and discovery have recorded.`) : null,
      roleLine,
      unsafeLine,
      disagreement,
      sameRole,
    ),
  );
  const noteEl = note;

  // ---- Other sourcetypes (N) --------------------------------------------
  const others = catalogue ? catalogue.fieldEverywhere(name).filter((r) => r.sourcetype !== st) : [];
  let othersFold = null;
  if (others.length) {
    othersFold = h(
      "details",
      { class: "r-fold r-others" },
      h("summary", { class: "r-fold__summary" }, headingNode("other-sourcetypes", others.length)),
      h(
        "ul",
        { class: "r-others__list" },
        others.map((r) =>
          h(
            "li",
            null,
            h("a", { href: `#/f/${encodeURIComponent(name)}?st=${encodeURIComponent(r.sourcetype)}`, class: "r-idlink" }, h("code", null, r.sourcetype)),
            r.fill === null ? (r.sources.includes("discovered") ? h("span", { class: "r-muted" }, " · seen, not profiled") : null) : h("span", { class: "r-muted" }, ` · ${Math.round(r.fill * 100)}% fill`),
          ),
        ),
      ),
    );
    sections.set("other-sourcetypes", h("section", { class: "r-section" }, othersFold));
  }

  // ---- Values -------------------------------------------------------------
  const dec = compact || !rec ? null : ctx.fields.decode(rec.name);
  let valuesSection = !compact && view ? dictionaryBlock({ view, sourcetype: st, name, catalogue, skipHazard: hazard }) : null;
  if (!valuesSection && dec) valuesSection = decodeSection(dec);
  else if (!valuesSection && !compact && view && view.decode && (!rec || (view.decode.source === "discovered" && !dec))) valuesSection = decodeSection(view.decode);
  if (valuesSection && dec) {
    const head = valuesSection.querySelector("h2");
    const widget = decodeWidget({ field: rec.name, decode: dec });
    if (head && head.parentNode === valuesSection) head.insertAdjacentElement("afterend", widget);
    else valuesSection.appendChild(widget);
  }
  if (valuesSection) sections.set("values", valuesSection);

  // ---- Verdict, Enrichment, Pattern: the page's value's, walked from the
  // popup's section list so the panel landing draws what the popup draws.
  let verdictRow = null;
  if (value && !compact) {
    for (const band of modules.bands()) {
      if (band === "verdict") {
        verdictRow = verdictSection({ catalogue, container: st, field: name, value });
        if (verdictRow) sections.set("verdict", h("section", { class: "r-section r-verdict" }, headingNode("verdict"), verdictRow));
      } else if (band === "enrich") {
        const e = enrichSection({ value, fieldName: name, container: st, openSettings: ctx.openSettings });
        if (e) sections.set("enrichment", h("section", { class: "r-section r-enrich" }, headingNode("enrichment"), e));
      } else if (band === "pattern") {
        const pat = patternSection({ catalogue, container: st, field: name, value });
        if (pat) sections.set("pattern", h("section", { class: "r-section" }, headingNode("pattern"), pat));
      }
    }
  }

  // ---- Pivots (N) ---------------------------------------------------------
  // N counts the rows that put a query in the drawer: the pack's pivots and
  // the ledger's moves (search-time fallbacks, one-join rows, the host
  // pivot under Not reachable). Rows that only read (On the record,
  // Suggested joins) are not moves and are not counted.
  const packEdges = !compact && st && catalogue ? catalogue.edgesFrom(st, name) : [];
  const carried = facts.carried(name, value);
  // One drawer, two owners: the pack's own pivots and the FDR ledger's
  // moves both fill it, so each keeps its own handler out of band and the
  // typed param goes to whichever a row selection last put in charge.
  let drawerActive = null; // "pack" | "ledger"
  let packHandler = null;
  let ledgerHandler = null;
  const pivots = packEdges.length
    ? packPivots({
        ctx: { ...ctx, setDrawerParamHandler: (fn) => { packHandler = fn; } },
        sourcetype: st,
        name,
        edges: packEdges,
        heading: false,
        carried,
        setSel: (id) => {
          drawerActive = "pack";
          ctx.setUrl("field", { ...ctx.params, st, sel: id });
        },
      })
    : null;
  const led = rec && !compact ? fdrLedger({ ...ctx, setDrawerParamHandler: (fn) => { ledgerHandler = fn; } }, { rec, events, on, evRec, root, carried }) : null;
  if (led) led.el.addEventListener("select", () => { drawerActive = "ledger"; });
  if (pivots || led) {
    ctx.setDrawerParamHandler((n, v) => {
      if (drawerActive === "pack") packHandler && packHandler(n, v);
      else if (drawerActive === "ledger") ledgerHandler && ledgerHandler(n, v);
    });
  }
  const moves = packEdges.length + (led ? led.moves : 0);
  const pivotsPresent = Boolean(pivots || led);
  if (pivotsPresent) {
    sections.set(
      "pivots",
      h(
        "section",
        { class: "r-section r-pivots" },
        headingNode("pivots", moves),
        pivots,
        led ? led.el : null,
        isSentinel() ? h("p", { class: "r-secondary r-pivots__platform" }, `No guided workflow on Sentinel: these pivots carry the value. Copy ${TERMS.lang} or Open in portal from the drawer.`) : null,
      ),
    );
  }

  // ---- Workflows (Splunk) -------------------------------------------------
  if (!compact && st && modules.on("workflows")) {
    const rows = workflows.forField(st, name);
    const block = workflowsBlock({ rows, value: value || undefined, appUrl: (hash) => hash, href: workflows.href, sourcetype: st });
    if (block) {
      const title = block.querySelector(".reach-row__title");
      if (title) title.remove();
      for (const a of block.querySelectorAll("a")) {
        a.removeAttribute("target");
        a.removeAttribute("rel");
        a.classList.add("r-idlink");
      }
      sections.set("workflows", h("section", { class: "r-section r-workflows" }, headingNode("workflows"), block));
    }
  }

  // ---- Profile, Extraction, CIM mapping, Query advisor ------------------
  const profile = !compact && view && view.profile ? profileBlock({ profile: view.profile }) : null;
  if (profile) sections.set("profile", profile);
  const extraction = !compact && view && view.provenance ? provenanceBlock({ provenance: view.provenance, sourcetype: st }) : null;
  if (extraction) sections.set("extraction", extraction);
  const cim = !compact && !isSentinel() ? cimSection({ rec, cim: view && view.cim, st, learned: Boolean(view && view.binding && view.binding.packId === LEARNED_ID) }) : null;
  if (cim) sections.set("cim-mapping", cim);
  if (!compact && st && modules.on("advisor")) sections.set("query-advisor", advisorSection({ ctx, view: view || { name, pack: rec }, sourcetype: st, name }));

  // ---- the title block ----------------------------------------------------
  const chips = [];
  if (rec) {
    chips.push(layerChip(rec), routeChip(rec));
    if (!rec.observed) chips.push(chip({ kind: "trust", value: "inferred", text: "never observed" }));
    else if (rec.tenant && !rec.tenant.seen) chips.push(chip({ kind: "trust", value: "inferred", text: "not seen in tenant run", title: `not populated on any event received in run ${(ctx.fields.manifest().observed || { run: {} }).run.id}` }));
  } else if (view.scope === "none") chips.push(chip({ kind: "trust", value: "inferred", text: "not catalogued" }));
  else if (view.packField) chips.push(chip({ kind: "trust", value: "confirmed", text: boundChipText(view, stPackId) }));
  else chips.push(chip({ kind: "trust", value: "confirmed", text: view.user ? "your catalogue" : "discovered" }));
  const verdictChip = verdictRow ? h("span", { class: "r-chip r-chip--verdict", dataset: { tier: "pending" }, title: "the known-good verdict for this value" }, "checking…") : null;
  if (verdictChip) chips.push(verdictChip);
  if (view && view.profile && view.profile.fill !== null && view.profile.fill !== undefined) {
    chips.push(h("span", { class: "r-chip r-chip--profile" }, jumpLink(`${Math.round(view.profile.fill * 100)}% · ${Number(view.profile.distinct || 0).toLocaleString("en-US")} distinct`, () => sections.get("profile"), { class: "", title: measuredLine(view.profile) })));
  }
  const flagged = chipFlags(view);
  const count = flagged ? flagged.count : decodeCount({ ctx, st, name, view, rec });
  const dChip = decodeChip(count, () => sections.get("values"), { flags: Boolean(flagged) });
  chips.push(dChip);
  if (count === null && st && catalogue) {
    catalogue.loadValues(st).then(() => {
      if (!root.isConnected) return;
      const next = catalogue.fieldOn(st, name) || view;
      const f = chipFlags(next);
      dChip.replaceWith(decodeChip(f ? f.count : decodeCount({ ctx, st, name, view: next, rec }), () => sections.get("values"), { flags: Boolean(f) }));
    });
  }

  const scopeItems = [];
  if (st) scopeItems.push(h("span", null, "on ", stLink(st)));
  const recordType = ctx.params.on && ctx.params.on !== st ? ctx.params.on : on;
  if (recordType) scopeItems.push(rec && ctx.fields.eventName(recordType) ? eventLink(recordType) : h("code", null, recordType));
  if (others.length) scopeItems.push(jumpLink(`also on ${others.length} more`, () => othersFold));

  // The callout slot: one hazard by priority. The danger verdict banner
  // lands here when the verdict resolves; the bundle's join hazard, else
  // the concept's first danger or caution, is drawn now.
  let slot = null;
  if (unsafe) slot = callout({ kind: "hazard", label: UNSAFE_JOIN.label, body: UNSAFE_JOIN.body });
  else if (hazard) slot = callout({ kind: hazard.level === "danger" ? "hazard" : "caution", body: hazardText.lead });
  // The platform note at N = 0: the label line and one body line.
  const platformNote = isSentinel() && !pivotsPresent ? callout({ kind: "note", label: "No guided workflow on Sentinel", body: "Filter the grid on this value instead." }) : null;
  const calloutSlot = slot || platformNote ? h("div", { class: "r-title__slot" }, slot, platformNote) : null;

  // The value line: the value the click carried, named as a value (held
  // is the Hold action's word), its decode, the value page.
  let valueLine = null;
  if (value) {
    const bits = bitmaskFold({ view, value });
    const decoded = bits ? bits.line : decodeOf({ ctx, st, name, view, rec, value });
    const line = h(
      "span",
      { class: bits && bits.fold ? "r-title__value" : null },
      h("span", { class: "r-muted" }, "value "),
      h("code", { title: value }, midEllipsis(value, 24)),
      decoded ? [h("span", { class: "r-muted" }, " · "), h("span", { class: "r-title__decode" }, decoded)] : null,
      " ",
      h("a", { href: `#/v/${encodeURIComponent(value)}?st=${encodeURIComponent(st)}&name=${encodeURIComponent(name)}`, class: "r-idlink", title: "the value page" }, "→"),
    );
    // The flag list opens on the line; the arrow keeps its own link.
    valueLine = bits && bits.fold ? h("details", { class: "r-title__flags" }, h("summary", { title: "the flags this value sets" }, line), bits.fold) : line;
  }

  // The action row: Hold and Mark benign act on the page's value; Note opens
  // the editor in Meaning; Bind when no concept binds the column. Their
  // bodies (the reason form, the status line, the exclusion offer) sit in
  // the value page's keepRow(), so the row hides again once Release or
  // Unmark empties it, the same one code path the value and runbook pages use.
  const actions = [];
  const keep = value && st && !compact
    ? keepRow([holdAction({ container: st, field: name, value }), modules.on("benign") ? benignAction({ catalogue, container: st, field: name, value }) : null])
    : { row: null, buttons: [] };
  actions.push(...keep.buttons);
  if (noteEl && st) {
    actions.push(
      h(
        "button",
        {
          type: "button",
          class: "r-btn r-action-note",
          onClick: () => {
            noteEl.edit();
            reveal(sections.get("meaning"));
          },
        },
        "Note",
      ),
    );
  }
  if (st && view && !view.concept && !rec) {
    actions.push(h("a", { class: "r-btn r-action-bind", href: `#/coverage?st=${encodeURIComponent(st)}&sel=${encodeURIComponent(name)}` }, "Bind"));
  }

  const title = titleBlock({ kind: "field", h1: name, chips, scope: scopeItems, callout: calloutSlot, held: valueLine, actions });
  if (keep.buttons.length) title.appendChild(keep.row);
  root.appendChild(title);
  const rbLine = compact ? null : runbookLine();
  if (rbLine) root.appendChild(rbLine);

  // The verdict's tier lands on the chip; its danger tier is the banner.
  if (verdictRow && verdictChip) followVerdict(verdictRow, verdictChip, title);

  for (const id of ENTITY_ORDER) {
    const s = sections.get(id);
    if (s) root.appendChild(s);
  }

  // ---- row selection and the keys ----------------------------------------
  root.selectRow = (rowId) => {
    if (led && led.selectRow(rowId)) return;
    if (pivots) pivots.selectRow(rowId);
  };
  root.cycleEvent = () => {
    if (led) led.cycleEvent();
  };
  root.afterMount = () => {
    if (ctx.params.sel) root.selectRow(ctx.params.sel);
  };
  root.unmount = () => {
    if (led) led.unmount();
  };
  return root;
}

// The verdict block (popup-ui.js) writes its tier on data-tier when the
// corpus answers; mirror it onto the title block's chip, and put the
// danger tier in the callout slot as a banner.
function followVerdict(row, chipEl, title) {
  const block = row.querySelector(".reach-verdict") || row;
  const apply = () => {
    const tier = block.dataset.tier || "pending";
    chipEl.dataset.tier = tier;
    chipEl.textContent = tier === "pending" ? "checking…" : tier;
    if (tier === "impersonation" && !title.querySelector(".r-callout--hazard")) {
      const text = block.querySelector(".reach-verdict__text");
      const banner = callout({ kind: "hazard", label: "Disagrees with the corpus", body: text ? text.textContent : "This value does not match the known-good corpus for this build." });
      let slot = title.querySelector(".r-title__slot");
      if (!slot) {
        slot = h("div", { class: "r-title__slot" });
        const scopeEl = title.querySelector(".r-scope");
        if (scopeEl) scopeEl.insertAdjacentElement("afterend", slot);
        else title.appendChild(slot);
      }
      slot.prepend(banner);
    }
  };
  if (typeof MutationObserver === "function") {
    const mo = new MutationObserver(() => {
      apply();
      if (block.dataset.tier && block.dataset.tier !== "pending") mo.disconnect();
    });
    mo.observe(block, { attributes: true, attributeFilter: ["data-tier"] });
  }
  apply();
}


// The FDR ledger: the five bands (on the record, search-time lookups, one
// join away, suggested joins, not reachable) read off the selected event,
// each folded with its count, and the drawer wiring for their rows. `root`
// is the view element the subscriptions watch for unmount.
function fdrLedger(ctx, { rec, events, on, evRec, root, carried = {} }) {
  const { fields } = ctx;
  const oneJoinRows = edgeRowsFor(fields.edges(), evRec, rec.name);
  const specs = new Map(); // rowId → { pivot, params, title, subtitle, hazards, errorParams }

  const hereRows = events.map((evName) => {
    const r = fields.event(evName);
    specs.set(`ev-${evName}`, {
      pivot: { kind: "event_sample" },
      params: { event: evName },
      title: `See ${evName} on real data`,
      subtitle: `${rec.name} rides on this event · ${(r && r.sourcetype) || ""}`,
      errorParams: ["event", "earliest"],
    });
    return {
      id: `ev-${evName}`,
      cells: [eventLink(evName), handlesCell(r), cimCell(r)],
    };
  });

  const evSt = evRec ? evRec.sourcetype : null;
  const isAutomatic = (e) => isAutomaticOn(e, evRec);
  const autoRows = oneJoinRows.filter((row) => isAutomatic(row.edge)).map((row) => {
    const e = row.edge;
    const viaText = `${e.src} → ${e.dst}`;
    specs.set(e.id, {
      pivot: { kind: "edge", edge: e },
      params: baseParamsForRow(row, rec.name, on),
      title: `${e.target_label}: manual fallback`,
      subtitle: `${viaText}; the TA already applies this on ${on}`,
      valueOwner: e.src,
      errorParams: ["value"],
    });
    const yields = (e.yields || []).filter((y) => fields.field(y));
    return {
      id: e.id,
      cells: [
        h("div", null, h("span", null, e.target_label), h("p", { class: "r-ledger__sub r-muted" }, `keyed on ${e.src}, which rides on this event; nothing to run`)),
        { mono: viaText },
        h(
          "div",
          { class: "r-ledger__yields" },
          yields.slice(0, 5).map((y, i) => h("span", null, i ? " " : "", fieldLink(y))),
          yields.length > 5 ? h("span", { class: "r-muted" }, ` +${yields.length - 5} more`) : null,
        ),
        basisChip(e),
      ],
    };
  });

  const joinRows = oneJoinRows.filter((row) => !isAutomatic(row.edge)).map((row) => {
    const e = row.edge;
    const pivot = pivotForEdgeRow(row, rec.name);
    const viaText = e.dst ? `${e.src} → ${e.dst}` : `${e.src} (lookup, not a join)`;
    specs.set(e.id, {
      pivot,
      params: baseParamsForRow(row, rec.name, on),
      title: e.target_label,
      subtitle: row.viaSelf ? `${viaText} from ${rec.name} on ${on}` : `${rec.name} → ${viaText} on ${on}`,
      valueOwner: pivot.kind === "trace" ? rec.name : e.src,
      errorParams: ["value", "aid", "earliest", "latest"],
    });
    return {
      id: e.id,
      hazard: Boolean(e.hazard) || e.cardinality === "unsafe",
      cells: [
        h(
          "div",
          null,
          h("span", null, e.target_label),
          row.viaSelf
            ? null
            : h("p", { class: "r-ledger__sub r-muted" }, `not on ${rec.name} itself: the hop is ${e.src}, which rides on this same event`),
          e.enrichment_concurs
            ? h("p", { class: "r-ledger__sub r-muted" }, `enrichment agrees (${e.enrichment_concurs.confidence}): ${e.enrichment_concurs.why}`)
            : null,
        ),
        { mono: viaText },
        scopeText(e),
        { mono: e.cardinality },
        basisChip(e),
      ],
    };
  });

  const suggestedRows = (rec.suggested_joins || []).map((s) => ({
    id: `s-${s.to}`,
    disabled: true,
    cells: [
      fieldLink(s.to),
      { text: s.why, wrap: true },
      chip({ kind: "trust", value: "suggested", confidence: s.confidence }),
    ],
  }));

  const unreachable = unreachableBand(ctx, rec, on, evRec, oneJoinRows, specs);

  const led = ledger({
    subject: rec.name,
    selectedId: ctx.params.sel || null,
    caption: `Reach ledger for ${rec.name}${on ? ` on ${on}` : ""}`,
    bands: [
      {
        id: "here",
        kind: "here",
        title: heading("on-the-record"),
        collapsible: true,
        folded: true,
        note: events.length
          ? h(
              "span",
              null,
              `${rec.name} rides on ${events.length} event${events.length === 1 ? "" : "s"}. Pick one. It scopes everything below. `,
              h("kbd", null, "e"),
              " cycles.",
            )
          : "This field is in the catalogue but was never observed on an event in the public corpus.",
        columns: ["event", "process handles", "CIM"],
        rows: hereRows,
        empty: "No events carry this field in the public corpus, so there is nothing free to show.",
      },
      {
        id: "automatic",
        kind: "automatic",
        title: heading("search-time-lookups"),
        collapsible: true,
        folded: true,
        note: on
          ? `Lookups the Splunk TA runs for you at search time on ${evSt}. Their output fields are already on every ${on} record: no query, no join. Select a row only if you need the manual fallback.`
          : "No event selected.",
        columns: ["target", "via", "already on the record", "basis"],
        rows: autoRows,
        empty: on ? `No TA lookup fires on ${on}'s sourcetype for a key it carries.` : "Nothing to show.",
      },
      {
        id: "one-join",
        kind: "one-join",
        title: heading("one-join-away"),
        collapsible: true,
        folded: true,
        note: on
          ? `Everything that costs a query from ${on}. A row is here only when its key actually rides on this event.`
          : "No event selected, so nothing can be shown as reachable.",
        columns: ["target", "via", "scope", "cardinality", "basis"],
        rows: joinRows,
        empty: on
          ? `Nothing on ${on} is a join key: no field on this event is the source of a typed edge.`
          : "Nothing to join from.",
      },
      {
        id: "suggested",
        kind: "suggested",
        title: heading("suggested-joins"),
        collapsible: true,
        folded: true,
        note: "AI enrichment's candidates. Not joins, not validated, never merged into the band above. Follow the name to read that field first.",
        columns: ["candidate", "why enrichment suggested it", "basis"],
        rows: suggestedRows,
        empty: "Enrichment suggested no companion field for this one.",
      },
      unreachable,
    ],
  });

  if (evRec) {
    // Inside the band's fold, so a closed On the record stays one line.
    const hereSection = led.querySelector('[data-band-id="here"]');
    const host = hereSection ? hereSection.querySelector("details") || hereSection : null;
    if (host) host.appendChild(coFieldsBlock(ctx, rec, on));
  }

  // ---- drawer wiring ----------------------------------------------------
  const userParams = {};
  let currentId = null;

  // The TA macros the pack's queries call, as the discovered layer's
  // provenance step last found them (discovery.js, configs/conf-macros).
  // One Splunk environment is assumed, the same single-instance model
  // "Run in Splunk" already leans on; several discovered environments pick
  // the first over guessing which one the user means.
  let macroEnv = null; // { origin, macros } | null
  let unmount = () => {};
  if (!isSentinel()) {
    const loadMacroEnv = async () => {
      let all;
      try {
        all = await layer.readAll();
      } catch {
        all = {};
      }
      const withMacros = Object.keys(all).filter((k) => /^https?:\/\//.test(k) && all[k] && all[k].macros);
      macroEnv = withMacros.length ? { origin: withMacros[0], macros: all[withMacros[0]].macros } : null;
      if (currentId) fill(currentId, false);
    };
    loadMacroEnv();
    unmount = layer.subscribe(loadMacroEnv);
  }

  function paramInputs(names, spec) {
    return names.map((n) => {
      const meta = PARAM_META[n] || {};
      let hint = meta.hint;
      if (n === "value" && spec && spec.valueOwner) hint = `the ${spec.valueOwner} value to search for`;
      return {
        name: n,
        label: n,
        value: userParams[n] ?? "",
        placeholder: meta.placeholder || "",
        hint,
        required: true,
      };
    });
  }

  function fill(rowId, rebuild) {
    const spec = specs.get(rowId);
    if (!spec) return;
    currentId = rowId;
    // The index is scope, resolved for the sourcetype the generator picks
    // for this pivot (the destination of an edge, aidmaster for a host
    // lookup): one pass to learn it, one more with the index bound.
    const base = { ...facts.bound(), ...carried, ...spec.params, ...userParams };
    fillFrom(
      ctx.drawer,
      {
        title: spec.title,
        subtitle: spec.subtitle,
        params: (out) => paramInputs(out.missing, spec),
        errorParams: () => paramInputs(spec.errorParams || ["value", "aid", "earliest", "latest"], spec),
        notes: (out) => scope.notes(out.sourcetype),
        macros: (out) =>
          isSentinel()
            ? undefined
            : {
                inline: macroInfo(fdr.macrosFor(spec.pivot, out.params, { form: "inline" }), macroEnv, out.params.index),
                macro: macroInfo(fdr.macrosFor(spec.pivot, out.params, { form: "macro" }), macroEnv, out.params.index),
              },
        errorText: (err) =>
          err.code === "unscoped_pid"
            ? `A RawProcessId search needs a host and a time window: the OS recycles PIDs, so an unscoped one matches unrelated processes. Bind aid, earliest and latest below. (${err.message})`
            : err.message,
      },
      () => {
        let params = base;
        let inline = fdr.generate(spec.pivot, base);
        params = scope.bind(base, inline.sourcetype);
        if (params !== base) inline = fdr.generate(spec.pivot, params);
        let macro = "";
        try {
          macro = fdr.generate(spec.pivot, params, { form: "macro" }).spl;
        } catch {
          macro = "";
        }
        return { ...inline, macro, params };
      },
      rebuild,
    );
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    if (currentId) fill(currentId, false);
  });
  // An index chosen or set under Settings lands in the open pivot.
  scope.follow(root, () => {
    if (currentId) fill(currentId, false);
  });

  led.addEventListener("select", (e) => {
    const { rowId, bandId } = e.detail;
    if (bandId === "here") {
      const evName = rowId.slice(3);
      ctx.navigate("field", { name: rec.name, on: evName, sel: rowId });
      return;
    }
    ctx.setUrl("field", { ...ctx.params, name: rec.name, on, sel: rowId });
    fill(rowId, true);
  });

  const selectRow = (rowId) => {
    if (!rowId || !specs.has(rowId)) return false;
    led.select(rowId);
    fill(rowId, true);
    return true;
  };

  const cycleEvent = () => {
    if (events.length < 2) return;
    const i = events.indexOf(on);
    const next = events[(i + 1) % events.length];
    ctx.navigate("field", { name: rec.name, on: next, sel: `ev-${next}` });
  };

  // The rows that put a query in the drawer: the moves this ledger offers.
  const moves = autoRows.length + joinRows.length + unreachable.rows.filter((r) => !r.disabled).length;

  return { el: led, selectRow, cycleEvent, moves, unmount };
}

// The chip on a bound column: the pack that binds it, or "yours" for a
// binding you confirmed (the learned pack, learned.js), which no TA and
// no pack author has seen.
export function boundChipText(view, stPackId) {
  if (view && view.binding && view.binding.packId === LEARNED_ID) return "yours";
  return `pack · ${stPackId || (view && view.packId)}`;
}

// CIM mapping, Splunk's: the raw fields the TA computes this from and
// the CIM names it lands on (the FDR bundle's walk-back tables), and what
// a generic pack says about the concept's place in CIM. On a column you
// bound yourself there is no TA: the sentence says where the concept lands
// on the pack's own tables.
function cimSection({ rec, cim, st, learned = false }) {
  const body = [];
  if (rec && (rec.sources || []).length) {
    body.push(
      h("p", { class: "r-secondary" }, "Computed by the TA. Which raw field feeds it depends on the event: this is the walk-back, not a 1:1 rename."),
      sourceTable({ field: rec.name, direction: "sources", rows: rec.sources }),
    );
  }
  if (rec && (rec.cim_targets || []).length) {
    body.push(
      h("p", { class: "r-secondary" }, "The TA maps this raw field onto CIM / TA names, and which name it lands on depends on the event."),
      sourceTable({ field: rec.name, direction: "targets", rows: rec.cim_targets }),
    );
  }
  if (cim) {
    const link = (n) => fieldLink(n, st);
    const plain = (n) => h("code", null, n);
    const list = (names, mk = link) => names.flatMap((n, i) => [i ? ", " : "", mk(n)]);
    if (cim.data_models && cim.data_models.length) {
      body.push(h("p", null, "Serves the ", ...cim.data_models.flatMap((m, i) => [i ? " and " : "", h("b", null, m)]), ` data model${cim.data_models.length === 1 ? "" : "s"}`, cim.from && cim.from.length ? h("span", null, learned ? "; on the pack's own tables the TA derives it from " : "; the TA derives it from ", ...list(cim.from, learned ? plain : link), ".") : "."));
    }
    if (cim.targets && cim.targets.length) {
      body.push(
        learned
          ? h("p", null, `Bound by you, so no TA maps it here. On the pack's own ${TERMS.sourcetypes} this concept lands on `, ...list(cim.targets, plain), "; CIM searches there see it under those names.")
          : h("p", null, "The TA maps it onto ", ...list(cim.targets), "; CIM searches see it under those names."),
      );
    }
  }
  if (!body.length) return null;
  return h("section", { class: "r-section r-cim" }, headingNode("cim-mapping"), ...body);
}

// The runbook for the alert the last clicked row came from, when the row
// carried a rule key (runbooks.js): one action line under the title block.
// Null on any other row, or while the module is off.
function runbookLine() {
  if (!modules.on("runbooks")) return null;
  const row = lastEvent.recall(null);
  const rk = row ? runbooks.ruleKeyFor(row) : null;
  if (!rk) return null;
  const href = runbooks.href(rk, row);
  return h("p", { class: "r-section r-runbook-line" }, h("a", { class: "r-btn r-btn--small", href }, `Runbook for ${rk.name || rk.keys[0].value} →`));
}

// Values from a decode table alone (the FDR TA's lookup, or the one
// discovery read from your Splunk): the fold names the count, the lookup
// sits in its title.
function decodeSection(dec) {
  const keys = Object.keys(dec.values || {});
  return h(
    "section",
    { class: "r-section r-dict" },
    headingNode("values"),
    h(
      "details",
      { class: "r-decode" },
      h("summary", { title: `${keys.length} values via ${dec.lookup || "the decode table"}${dec.meaning_field ? ` → ${dec.meaning_field}` : ""}${dec.source === "discovered" ? " (read from your Splunk's lookup)" : ""}` }, heading("decode-table", keys.length)),
      h("p", { class: "r-secondary" }, "via ", h("code", null, dec.lookup || "the decode table"), dec.meaning_field ? [" → ", h("code", null, dec.meaning_field)] : null, dec.source === "discovered" ? " (read from your Splunk's lookup)" : null),
      h("ul", { class: "r-decode__list" }, keys.slice(0, 500).map((k) => h("li", null, h("code", null, k), " ", h("span", null, dec.values[k])))),
    ),
  );
}

// The role line's provenance. A pack concept bound on this sourcetype, or
// the user's own note, describes the field; the bundle's inferred basis
// (name convention, enrichment) is what is left when neither does.
export function roleProvenance(rec, view) {
  const t = (view && view.taxonomy) || {};
  if (t.roleSource === "user" && t.role) return { role: t.role, from: "your note", inferred: false };
  if (view && view.concept && t.roleSource === "pack" && t.role) {
    const pack = packs.pack(view.concept.packId);
    return { role: t.role, from: `the ${pack && pack.name ? pack.name : view.concept.packId} pack`, inferred: false };
  }
  return { role: rec.role || "unclassified", from: BASIS_LABEL[rec.role_basis] || rec.role_basis || "nothing", inferred: true };
}

function coFieldsBlock(ctx, rec, on) {
  const evRec = ctx.fields.event(on);
  const groups = ctx.fields.coFields(rec.name, on);
  const total = groups.reduce((n, g) => n + g.fields.length, 0);
  const measured = Boolean(evRec && evRec.tenant && evRec.tenant.measured);
  const runId = measured ? ((ctx.fields.manifest().observed || {}).run || {}).id : null;
  const pct = (f) => h("span", { class: "r-muted r-cofields__fill" }, `${Math.round(f * 100)}%`);
  return h(
    "div",
    { class: "r-cofields" },
    h("p", { class: "r-cofields__lead" }, h("b", null, `Free on ${on}`), `: ${total} other field${total === 1 ? "" : "s"} on the same record`),
    h(
      "p",
      { class: "r-cofields__note r-muted" },
      measured ? fillRatesNote(evRec, runId) : NO_FILL_RATES,
    ),
    h(
      "div",
      { class: "r-rolelist" },
      groups.map((g) =>
        h(
          "div",
          { class: "r-rolelist__group" },
          h("h5", { class: "r-rolelist__role" }, g.role, h("span", { class: "r-muted" }, ` ${g.fields.length}`)),
          h(
            "p",
            { class: "r-rolelist__fields" },
            g.fields.flatMap((n, i) => [i ? " " : null, fieldLink(n), g.fills ? pct(g.fills[i]) : null]),
          ),
        ),
      ),
    ),
  );
}

function unreachableBand(ctx, rec, on, evRec, oneJoinRows, specs) {
  const route = rec.route || { summary: "unobserved", explain: "", by_event: {}, derived_from: [] };
  const rows = [];
  const columns = ["what you cannot get from here", "closest you can get", "basis"];

  const addHostOnly = (why, eventName) => {
    const id = `u-host-${eventName || "any"}`;
    specs.set(id, {
      pivot: { kind: "process_table" },
      params: {},
      title: "Every process on the host in the window",
      subtitle: `closest you can get from ${eventName || rec.name}: attribution is to a host and a time, not to a process`,
      errorParams: ["aid", "earliest", "latest"],
      valueOwner: "aid",
    });
    rows.push({
      id,
      cells: [{ text: why, wrap: true }, { text: "Every process on the host for the window (cs_process_table).", wrap: true }, chip({ kind: "trust", value: "confirmed", text: "confirmed" })],
    });
  };

  if (route.summary === "host_only") {
    addHostOnly(`The events carrying ${rec.name} have no process handle: no ContextProcessId, no TargetProcessId, no ParentProcessId. You can attribute this to a host and a time, not to a process.`, on);
  } else if (route.summary === "mixed") {
    if (evRec && (route.by_event[on] || {}).route === "host_only") {
      addHostOnly(`On ${on} this field has no process handle, even though other events carrying it do. The route is event-conditional. That is why there is no single verdict.`, on);
    }
    for (const [evName, info] of Object.entries(route.by_event || {})) {
      if (evName === on && info.route === "host_only") continue; // already the pivot row above
      const r = ROUTE_TEXT[info.route] || { label: info.route };
      rows.push({
        id: `u-ev-${evName}`,
        disabled: true,
        cells: [
          h(
            "span",
            null,
            "on ",
            eventLink(evName),
            evName === on ? h("span", { class: "r-muted" }, " (selected)") : null,
            ": ",
            r.label,
          ),
          info.route === "host_only"
            ? { text: "No process handle on that event: select it above and take the host pivot.", wrap: true }
            : h(
                "span",
                null,
                "handles: ",
                (info.handles || []).length
                  ? h("span", { class: "r-inline" }, (info.handles || []).flatMap((n, i) => [i ? " " : null, h("code", null, n)]))
                  : h("span", { class: "r-muted" }, "none"),
                info.is_anchor ? " · anchor event" : null,
              ),
          chip({ kind: "route", value: (ROUTE_TEXT[info.route] || {}).chip || "dead-end", text: r.label }),
        ],
      });
    }
  } else if (route.summary === "derived") {
    for (const src of route.derived_from || []) {
      const srcRec = ctx.fields.field(src);
      rows.push({
        id: `u-derived-${src}`,
        disabled: true,
        cells: [
          h("span", null, "This field is computed, so it has no route of its own. It derives from ", fieldLink(src), "."),
          h(
            "span",
            null,
            srcRec ? `That field's route: ${(ROUTE_TEXT[srcRec.route.summary] || {}).label || srcRec.route.summary}. ` : "",
            fieldLink(src),
            " has the answer.",
          ),
          chip({ kind: "trust", value: "confirmed", text: "the TA computes it" }),
        ],
      });
    }
  } else if (route.summary === "unobserved") {
    rows.push({
      id: "u-unobserved",
      disabled: true,
      cells: [
        { text: "No route can be computed: this field is in the catalogue but was never observed on any event in the public corpus. This is 'we do not know', not 'there is no path'.", wrap: true },
        { text: "Check discovery/01 against your own tenant. Your data may carry it where the public fixtures do not.", wrap: true },
        chip({ kind: "trust", value: "inferred", text: "unobserved" }),
      ],
    });
  }

  // *Pid field with no edge: PID space unestablished.
  const fam = familyOf(rec.name);
  if (fam && fam.family === "pid" && !PID_HANDLES.has(rec.name) && !(rec.edges || []).length) {
    const handle = (evRec && (evRec.handles || [])[0]) || null;
    rows.push({
      id: "u-pidspace",
      disabled: true,
      cells: [
        { text: `Which PID space ${rec.name} is in. Nothing in the catalogue, the TA or the reference says whether it is an OS PID (recycled) or a Falcon process id, so no join is offered on it.`, wrap: true },
        handle
          ? h("span", null, "Pivot through ", h("code", null, handle), " on this same event instead: the row in ONE JOIN does exactly that.")
          : { text: "No process handle on this event either; the host pivot above is the closest.", wrap: true },
        chip({ kind: "hazard", text: "no basis" }),
      ],
    });
  }

  return {
    id: "unreachable",
    kind: "unreachable",
    collapsible: true, // prose-heavy and last; folds in the panel unless it holds the page's only pivot (ledger.js)
    note: h(
      "span",
      null,
      h("b", null, (ROUTE_TEXT[route.summary] || {}).label || route.summary),
      ": ",
      route.explain || "",
    ),
    columns,
    rows,
    empty:
      route.summary === "one_hop" || route.summary === "direct_anchor"
        ? "Nothing is out of reach from this record: the route above gets you to the process."
        : "No breakdown to show for this route.",
  };
}

export default { render, edgeRowsFor, pivotForEdgeRow, baseParamsForRow, basisChip, roleProvenance, resolveContainer, NO_FILL_RATES, fillRatesNote };
