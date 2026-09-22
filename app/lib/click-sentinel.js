// What only the Logs blade adds to a click's section (click-section.js
// hooks): the pivot control that copies a pack edge's KQL or opens it as
// a query tab through a deep link (nothing runs from here), the table
// picker when the page names none, the workspace note, and the editor
// bridge as the insert once the blade's Monaco has answered.
//
//   hooks(lib, { workspace, rerender }) → the hooks object sectionFor takes
//       workspace   { name, resourceId } | null, the Logs blade's current workspace (a config fact)
//       rerender(table)   the caller draws the section again with the picked table
//   pivotControl(lib, edge, params, meta, workspace, hold) → Element
//       the KQL with the parameters bound, inputs for the rest, Copy KQL
//       and Open as query tab. `hold` records a copy or an open from a
//       held value as a notebook edge; nothing for a value that is not held.
//   PORTAL_ORIGIN       the only frame allowed to receive a query deep link
//
// DOM module. Never fetches.

import { h } from "../components/h.js";
import { placeClick, packEdgeRows, pivotNames, viewFor } from "./click-section.js";
import { SENTINEL_PIVOTS_LINE, SENTINEL_NO_PIVOTS_NOTE } from "./bands/band.js";

export const PORTAL_ORIGIN = "https://portal.azure.com";

export function pivotControl(lib, edge, params, meta, workspace, hold = null) {
  const { pivot, packs, kql, runtime } = lib;
  const box = h("div", { class: "reach-run-box" });
  const pack = packs.pack(edge.packId);
  let current = { ...params };
  const noteEdge = (text) => { if (hold) lib.ui.recordPivot({ ...hold, query: text, name: edge.label }).catch(() => {}); };
  // The search history takes every hand-off, held or not.
  const noteSearch = (text, source) => { if (lib.ui.noteSearch) lib.ui.noteSearch({ text, platform: "sentinel", source, origin: "pivot", container: hold && hold.container, field: hold && hold.field, value: hold && hold.value, name: edge.label }); };

  function draw() {
    box.replaceChildren();
    let result;
    try {
      result = pivot.generate(edge, current, { pack });
    } catch (err) {
      // Any generator failure renders here; Preview never throws past its
      // own row, and the rest of the popup stays mounted.
      box.appendChild(h("div", { class: "reach-row__body reach-row__body--warn" }, (err && err.message) || String(err)));
      return;
    }
    box.appendChild(h("pre", { class: "reach-spl" }, result.spl));
    for (const hz of result.hazards || []) box.appendChild(h("div", { class: `reach-row__body reach-row__body--${hz.level}` }, hz.text));
    if (result.missing && result.missing.length) {
      for (const el of lib.ui.missingParamInputs({ missing: result.missing, meta, platform: "sentinel", onChange: (name, v) => { current = { ...current, [name]: v }; }, onPreview: draw })) box.appendChild(el);
      return;
    }
    const copy = h("button", { class: "reach-run-btn", type: "button", onClick: (e) => { runtime.copyText(result.spl, e.currentTarget, "copied ✓"); noteEdge(result.spl); noteSearch(result.spl, "copy"); } }, "Copy KQL");
    const open = h("a", { class: "reach-run-btn reach-run-btn--tab", href: "#", target: "_blank", rel: "noopener", title: workspace ? `Run this as a new query tab in this Logs screen (⌘/Ctrl-click: a new browser tab)` : "No workspace known yet: open the Logs blade once so Reach can see which workspace you are on" }, "Open as query tab ↗");
    if (workspace) {
      // A plain click opens the query as one of the Logs screen's own
      // tabs: the top frame (sentinel-workspace.js) navigates the portal
      // to the deep link. A modified or middle click keeps the link's own
      // behaviour, a new browser tab. The link carries the workspace
      // resource id and the KQL, so only the portal may receive it; a
      // mismatched target drops it silently.
      open.addEventListener("click", (e) => {
        e.stopPropagation();
        noteEdge(result.spl);
        noteSearch(result.spl, "open");
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button === 1 || !open.dataset.url) return;
        e.preventDefault();
        try {
          window.top.postMessage({ type: "reach:open", url: open.dataset.url }, PORTAL_ORIGIN);
        } catch {
          window.open(open.dataset.url, "_blank", "noopener");
        }
      });
      kql.deepLink({ resourceId: workspace.resourceId, kql: result.spl, timespan: "P1D" }).then((url) => { open.href = url; open.dataset.url = url; }).catch(() => {});
    } else {
      open.addEventListener("click", (e) => e.preventDefault());
      open.style.opacity = "0.5";
    }
    box.appendChild(h("div", { class: "reach-run-split" }, copy, open));
  }
  draw();
  return box;
}

// The table picker: the tables the column is bound on, else the query's,
// else every table the catalogue knows.
function tablePick(m, rerender) {
  const { ctx, TERMS, names } = m;
  const name = names.name;
  const options = ctx.inferred && ctx.inferred.sourcetypes ? ctx.inferred.sourcetypes : ctx.candidates.length ? ctx.candidates : m.lib.catalogue.sourcetypes().map((s) => s.name);
  const sel = h("select", { class: "reach-input", style: { width: "auto", maxWidth: "260px" } }, h("option", { value: "" }, `${TERMS.sourcetype}…`), options.map((t) => h("option", { value: t }, t)));
  sel.addEventListener("change", () => {
    if (sel.value) rerender(sel.value);
  });
  const why = ctx.inferred && ctx.inferred.sourcetypes ? `${name} is a column on ${ctx.inferred.sourcetypes.length} ${TERMS.sourcetypes}; which one is this row from? (for the pivots)` : ctx.candidates.length > 1 ? "The query reads several tables; which one is this row from?" : "Which table is this row from?";
  return h("div", { class: "reach-row" }, h("div", { class: "reach-row__body reach-row__body--muted" }, why), sel);
}

export function hooks(lib, { workspace = null, rerender = null } = {}) {
  // The workspace is scope: its note sits in the head, under the scope line.
  const wsNote = () => (workspace ? null : h("div", { class: "reach-row__body reach-row__body--muted" }, "Workspace not seen yet: open the Logs blade from the portal once so pivots can link back to it."));
  return {
    // The dotted path of a nested leaf, the top-level column as the fallback.
    names: (raw) => ({ name: raw, fallback: raw.includes(".") ? raw.split(".")[0] : null }),
    // No table on the page (Simple mode, Type not projected): several
    // tables sharing the column on one concept read the meaning off the
    // first and wait for the picker before any pivot; otherwise the
    // picker alone, under a scope line that says the table is unknown.
    place(m) {
      const { ctx, TERMS, catalogue, names } = m;
      if (ctx.container) {
        const out = placeClick(m);
        out.head = [];
        if (m.isValue && !catalogue.edgesFrom(out.container, out.name).length) out.head.push(h("div", { class: "reach-note reach-pivots__platform" }, SENTINEL_NO_PIVOTS_NOTE));
        out.head.push(wsNote());
        return out;
      }
      const shared = ctx.inferred && ctx.inferred.concept ? ctx.inferred.sourcetypes[0] : null;
      const view = shared ? viewFor(catalogue, shared, names.name, names.fallback) : null;
      const scopeText = shared ? `${TERMS.sourcetype} unknown here; ${names.name} means the same on ${ctx.inferred.sourcetypes.join(", ")}` : `${TERMS.sourcetype} unknown here: nothing to attach a note to until Reach knows the table`;
      return { name: names.name, container: null, meaningContainer: shared, view, scopeText, everywhere: catalogue.fieldEverywhere(names.name).filter((r) => r.sourcetype !== shared), head: [rerender ? tablePick(m, rerender) : null, wsNote()], bare: false };
    },
    insert: async () => ((await lib.bridge.kqlReady()) ? (req) => lib.bridge.apply(req) : null),
    // A value click: every pack edge leaving the column, its KQL on open,
    // and the line that says the pivots are how a value travels here. A
    // column click lists them by name.
    pivots(m) {
      if (!m.isValue) {
        const el = pivotNames(m, ". Right-click a value for the KQL.");
        return el ? { el, n: m.edges.length, fold: false } : null;
      }
      if (!m.edges.length) return null;
      const rows = packEdgeRows(m, (edge, params, pmeta) => pivotControl(lib, edge, params, pmeta, workspace, m.hold), {
        // The window starts at the pack's suggested default (-24h): the
        // pivot is one click, and the input to change it is still there.
        after: (params, pmeta) => { if (params.earliest === undefined && pmeta.earliest && pmeta.earliest.placeholder) params.earliest = pmeta.earliest.placeholder; },
        summary: (edge, container) => (edge.dst.sourcetype !== container ? h("span", { class: "reach-row__feeds" }, ` → ${edge.dst.sourcetype}`) : null),
      });
      return { el: h("div", { class: "reach-edges" }, ...rows, h("div", { class: "reach-row__body reach-row__body--muted reach-pivots__platform" }, SENTINEL_PIVOTS_LINE)), n: m.edges.length, fold: true };
    },
  };
}

export default { hooks, pivotControl, PORTAL_ORIGIN };
