// What only Splunk adds to a click's section (click-section.js hooks):
// the run control that dispatches a pivot from the popup and streams the
// results into it, the FDR bundle's own edge ahead of the pack edges, the
// name a raw field resolves to in the bundle, the pattern rung's live
// test, and the editor bridge as the insert.
//
//   hooks(lib) → the hooks object sectionFor takes
//   runControl(lib, generate, params, meta, edge) → Element
//       edge { hold, name, origin }: Copy SPL, Open in Splunk and Run here write the search history
//       generate(params) → { spl, hazards, missing, sourcetype }; the SPL
//       block, inputs for the missing parameters, Run here (a live job
//       through live-lookup.js, only from an isTrusted click) and Open in
//       Splunk. `edge` ({ hold, name }) records a run from a held value as
//       a notebook edge; nothing for a value that is not held.
//   patternSearch(lib, rung, { index, sourcetype, field }) → a generate() result
//   aliasMap(spl) → { alias: field }   the "... as alias" clauses a result column came from
//   searchPageUrl(lib, spl)            Splunk Web's search page for this origin, locale and app
//   INDEXED_DEFAULTS                   Splunk's default fields, indexed
//
// DOM module. Nothing runs before the Run button's own isTrusted click.

import { h } from "../components/h.js";
import * as store from "./store.js";
import { KEYS } from "./storage-keys.js";
import { placeClick, packEdgeRows, pivotNames, basisText } from "./click-section.js";

// Splunk's default fields are indexed: the one efficiency class known
// without discovery's provenance, and the one that lets TERM() onto the ladder.
export const INDEXED_DEFAULTS = new Set(["index", "sourcetype", "source", "host", "splunk_server", "punct"]);

const HIDDEN_RESULT_FIELDS = /^(_raw|_bkt|_cd|_indextime|_serial|_si|_subsecond|_sourcetype|punct|linecount|splunk_server|splunk_server_group|_time_raw|_span|_tc|_mkv_child|_kv|_n)$/;

// The app namespace and the configured index are Settings: read ahead of
// a click, never held.
let appNs = "search";
async function appNamespace() {
  const out = await store.getLiteral(KEYS.spAppNamespace);
  appNs = out[KEYS.spAppNamespace] || "search";
  return appNs;
}
appNamespace().catch(() => {});

// Empty: generated SPL keeps the cs_index macro (spl.js's default). Set:
// every pivot searches this literal index, for search heads that never
// defined the macro.
async function configuredIndex() {
  const out = await store.getLiteral(KEYS.csIndex);
  return out[KEYS.csIndex] || "";
}

// Inline earliest=/latest= in the SPL win over the time picker, so no time
// parameters are added; a pivot without them gets the picker's default.
export function searchPageUrl(lib, spl) {
  const origin = globalThis.location ? globalThis.location.origin : "";
  return `${origin}/${lib.runtime.localePrefix()}/app/${encodeURIComponent(appNs)}/search?q=${encodeURIComponent(spl)}`;
}

// alias → source field, from the SPL's "… as alias" clauses: bare
// "X as y", aggregations "min(X) as y", and the eval(if(cond, X, null()))
// shape the pivots use. Only aggregations that carry a field's own literal
// values through are aliases worth searching on; dc()/count()/sum()/avg()
// produce a number derived from the field, not one of its values.
export function aliasMap(text) {
  const out = {};
  const re = /(?:\b(?:values|latest|earliest|first|last|min|max)\(\s*(?:eval\(\s*if\([^,]*,\s*)?([A-Za-z_][\w.]*)[^)]*\)+|\b(?:rename\s+)?([A-Za-z_][\w.]*))\s+as\s+([A-Za-z_]\w*)/gi;
  let m;
  while ((m = re.exec(text))) {
    const src = m[1] || m[2];
    const alias = m[3];
    if (src && alias && !(alias in out)) out[alias] = src;
  }
  return out;
}

// The generated SPL stays collapsed even once the edge is open: reading
// it and copying it are equally likely next moves, so both sit on the bar.
function splBlock(lib, splText, hazards, onCopy = null) {
  const { runtime } = lib;
  const pre = h("pre", { class: "reach-spl", hidden: true }, splText);
  const notes = h(
    "div",
    { class: "reach-spl-notes", hidden: true },
    (hazards || []).map((hz) => h("div", { class: `reach-row__body reach-row__body--${hz.level}` }, hz.text)),
  );
  const expandBtn = h(
    "button",
    {
      type: "button",
      class: "reach-mini",
      onClick: (e) => {
        e.stopPropagation();
        pre.hidden = !pre.hidden;
        notes.hidden = pre.hidden;
        expandBtn.textContent = pre.hidden ? "Expand SPL" : "Collapse SPL";
      },
    },
    "Expand SPL",
  );
  const copyBtn = h(
    "button",
    {
      type: "button",
      class: "reach-mini",
      onClick: (e) => {
        e.stopPropagation();
        runtime.copyText(splText, e.currentTarget, "copied ✓");
        if (onCopy) onCopy(splText);
      },
    },
    "Copy SPL",
  );
  return h(
    "div",
    { class: "reach-spl-wrap" },
    h("div", { class: "reach-spl-bar" }, h("span", { class: "reach-spl-label" }, "SPL"), expandBtn, copyBtn),
    pre,
    notes,
  );
}

// Results as a real table: every field, values wrapped, click a value to
// copy it, ↗ to search for it, copy the whole set as TSV. Preview rows
// re-render in place while the job runs; the final set replaces them.
function renderRows(lib, box, rows, isFinal, pivotUrl) {
  const { runtime } = lib;
  box.replaceChildren();
  if (!rows.length) {
    box.appendChild(h("div", { class: "reach-results__head" }, h("span", { class: "reach-results__title" }, isFinal ? "No results" : "Running: no rows yet")));
    return;
  }
  const fields = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!HIDDEN_RESULT_FIELDS.test(k) && !fields.includes(k)) fields.push(k);
  const tsv = [fields.join("\t"), ...rows.map((r) => fields.map((f) => String(r[f] ?? "")).join("\t"))].join("\n");
  const copyAll = h("button", { type: "button", class: "reach-mini", onClick: (e) => { e.stopPropagation(); runtime.copyText(tsv, e.currentTarget, "copied ✓"); } }, "copy all (TSV)");
  box.appendChild(
    h(
      "div",
      { class: "reach-results__head" },
      h("span", { class: "reach-results__title" }, isFinal ? `${rows.length} result${rows.length === 1 ? "" : "s"}` : `Running: ${rows.length} so far`),
      h("span", { class: "reach-results__hint" }, "click a value to copy · ↗ searches it"),
      copyAll,
    ),
  );
  const shown = rows.slice(0, 20);
  for (const [i, row] of shown.entries()) {
    const card = h("div", { class: "reach-result" });
    if (shown.length > 1) card.appendChild(h("div", { class: "reach-result__n" }, `#${i + 1}`));
    const dl = h("dl", { class: "reach-result__kv" });
    for (const f of fields) {
      const raw = row[f];
      if (raw === undefined || raw === null || raw === "") continue;
      const value = Array.isArray(raw) ? raw.join(", ") : String(raw);
      const val = h(
        "button",
        { type: "button", class: "reach-result__v", title: "click to copy", onClick: (e) => { e.stopPropagation(); runtime.copyText(value, e.currentTarget.nextSibling, "copied ✓"); } },
        value,
      );
      const href = pivotUrl ? pivotUrl(f, Array.isArray(raw) ? raw[0] : raw) : null;
      const go = href
        ? h("a", { class: "reach-result__go", href, target: "_blank", rel: "noopener", title: `search ${decodeURIComponent(href).replace(/.*sourcetype=\S+\s+/, "").slice(0, 60)} in a new tab` }, "↗")
        : h("span", { class: "reach-result__go" }, "");
      dl.appendChild(h("dt", null, f));
      dl.appendChild(h("dd", null, val, go));
    }
    card.appendChild(dl);
    box.appendChild(card);
  }
  if (rows.length > shown.length) box.appendChild(h("div", { class: "reach-results__more" }, `+${rows.length - shown.length} more - Open in Splunk ↗ for the full set`));
}

// `result`/`params` are reactive to the inputs this renders for any
// still-missing parameter: regenerating locally (free) on every keystroke;
// only the final Run click ever touches the network, and only after
// event.isTrusted.
export function runControl(lib, generate, params, meta = {}, edge = null) {
  const { spl, live } = lib;
  const box = h("div", { class: "reach-run-box" });
  let currentParams = { ...params };
  const noteEdge = (text) => (edge && edge.hold ? lib.ui.recordPivot({ ...edge.hold, query: text, name: edge.name || null }).catch(() => null) : Promise.resolve(null));
  // The search history takes every hand-off, held or not.
  const hold = (edge && edge.hold) || {};
  const noteSearch = (text, source, extra = {}) => (lib.ui.noteSearch ? lib.ui.noteSearch({ text, platform: "splunk", source, origin: (edge && edge.origin) || "pivot", container: hold.container, field: hold.field, value: hold.value, name: (edge && edge.name) || null, ...extra }) : Promise.resolve(null));

  function renderState() {
    box.replaceChildren();
    let result;
    try {
      result = generate(currentParams);
    } catch (err) {
      if (err && (err.name === "SplError" || err.name === "PivotError")) {
        box.appendChild(h("div", { class: "reach-row__body reach-row__body--warn" }, err.message));
        return;
      }
      throw err;
    }

    box.appendChild(splBlock(lib, result.spl, result.hazards, (text) => noteSearch(text, "copy")));

    if (result.missing && result.missing.length) {
      for (const el of lib.ui.missingParamInputs({ missing: result.missing, meta, platform: "splunk", onChange: (name, v) => { currentParams = { ...currentParams, [name]: v }; }, onPreview: renderState })) box.appendChild(el);
      return;
    }

    const status = h("div", { class: "reach-row__body reach-row__body--muted" });
    const runBtn = h(
      "button",
      {
        class: "reach-run-btn reach-run-btn--live",
        type: "button",
        title: "Dispatch it from here and stream the results into this menu",
        onClick: (e) => runLive(e, result, runBtn, status, box),
      },
      "Run here →",
    );
    // The same SPL as a normal Splunk search in a new tab: Splunk runs it
    // on load, exactly as if it had been pasted into the search bar.
    const openTab = h(
      "a",
      {
        class: "reach-run-btn reach-run-btn--tab",
        href: searchPageUrl(lib, result.spl),
        target: "_blank",
        rel: "noopener",
        title: "Open this search in a new Splunk tab",
        onClick: () => {
          noteEdge(result.spl);
          noteSearch(result.spl, "open");
        },
      },
      "Open in Splunk ↗",
    );
    box.appendChild(h("div", { class: "reach-run-split" }, runBtn, openTab));
    box.appendChild(status);
  }

  async function runLive(e, result, runBtn, status, container) {
    if (!e.isTrusted) return; // a synthetic click never dispatches anything
    const capturedSpl = result.spl; // captured at render time, never re-read from the DOM
    runBtn.disabled = true;
    runBtn.replaceChildren(h("span", { class: "reach-spinner" }), "Running…");
    status.textContent = "";
    const app = await appNamespace();
    let sid = null;
    let cancelled = false;
    const popupGone = () => !document.body.contains(container);

    let rowsBox = container.querySelector(".reach-results");
    if (!rowsBox) {
      rowsBox = h("div", { class: "reach-results" });
      container.appendChild(rowsBox);
    }
    // "search this ↗" for any value in a result: the same index and
    // sourcetype the pivot ran on, narrowed to field="value". Result
    // columns are often aliases (os_pid is RawProcessId), so the column
    // is mapped back to the field it came from; a column that is neither
    // an alias nor a real field on the sourcetype gets no link.
    const scope = `index=${currentParams.index ? spl.quote(String(currentParams.index)).replace(/^"([A-Za-z0-9_\-]+)"$/, "$1") : "`cs_index`"} sourcetype=${result.sourcetype}`;
    const aliases = aliasMap(capturedSpl);
    const known = new Set(lib.catalogue.fieldsOn(result.sourcetype));
    const fieldFor = (col) => {
      const a = aliases[col];
      // The alias regex over-captures across a string concatenation
      // ("eventName." before the quote stops it): only an alias that is
      // itself a real field on this sourcetype is trusted.
      if (a && !a.startsWith("_") && known.has(a)) return a; // os_pid → RawProcessId
      return known.has(col) ? col : null; // TargetProcessId (renamed from _pid) is a real field itself
    };
    const pivotUrl = (col, value) => {
      const f = fieldFor(col);
      return f ? searchPageUrl(lib, `search ${scope} ${f}=${spl.quote(String(value))}`) : null;
    };

    const noted = noteEdge(capturedSpl);
    try {
      sid = await live.dispatch(capturedSpl, { app });
      noteSearch(capturedSpl, "run", { ran: true, sid });
      status.textContent = `Running against your Splunk (sid ${sid})…`;
      const outcome = await live.pollUntilDone(sid, {
        app,
        isCancelled: () => (cancelled = cancelled || popupGone()),
        onPreview: (rows) => renderRows(lib, rowsBox, rows, false, pivotUrl),
      });
      if (outcome.cancelled) return;
      // /results, not /events: every pivot ends in stats/table, and a
      // transforming search has no events to return, only results.
      const rows = await live.fetchStats(sid, { app, count: 50 });
      renderRows(lib, rowsBox, rows, true, pivotUrl);
      status.textContent = rows.length ? "" : "Ran clean: zero results.";
      noted.then((e) => e && lib.notebook.update(e.id, { found: `${rows.length} result${rows.length === 1 ? "" : "s"}` })).catch(() => {});
    } catch (err) {
      status.textContent = err && err.message ? err.message : String(err);
    } finally {
      runBtn.textContent = "Run again →";
      runBtn.disabled = false;
      // One-shot: the rows are on screen or the run failed, and either way
      // the job has no further use; left alone it burns search-head
      // concurrency until Splunk reaps it.
      if (sid) live.cancelJob(sid, { app });
    }
  }

  renderState();
  return box;
}

// The live test for a pattern rung: the rung on the event's index and
// sourcetype over the last day, topped by the field, so the rows read
// like the offline preview (value, count) but from the user's own Splunk.
export function patternSearch(lib, rung, { index, sourcetype, field }) {
  const { spl } = lib;
  const bare = (v) => spl.quote(String(v)).replace(/^"([A-Za-z0-9_:\-]+)"$/, "$1");
  const scope = `${index ? `index=${bare(index)} ` : ""}sourcetype=${bare(sourcetype)} earliest=-24h latest=now`;
  const hazards = [{ level: "note", text: `The last 24 hours${index ? "" : ", in your default indexes (no index known for this event)"}; edit earliest= in Splunk for a wider window.` }];
  for (const c of rung.caveats || []) hazards.push({ level: "caution", text: c });
  return { spl: `search ${scope} ${rung.text} | top limit=10 ${field}`, hazards, missing: [], sourcetype };
}

// The FDR bundle's edge from this field on this record type, ahead of
// the pack edges: the row's own aid and index bound, the configured
// index as the fallback, the macro as the last resort.
function fdrEdgeRow(m) {
  const { lib, ctx, view, name, value } = m;
  const { fields, edgeRowsFor, pivotForEdgeRow, baseParamsForRow } = lib;
  const fieldRec = view && view.pack;
  const eventName = ctx.discriminator ? ctx.discriminator.value : null;
  const eventRec = eventName && fieldRec ? fields.event(eventName) : null;
  if (!eventRec) return null;
  const rows = edgeRowsFor(fields.edges(), eventRec, fieldRec.name);
  if (!rows.length) return null;
  const row = rows[0];
  const pivot = pivotForEdgeRow(row, fieldRec.name);
  const params = {
    value,
    aid: ctx.read("aid") || undefined,
    ...(m.scope ? { index: m.scope } : {}),
    ...baseParamsForRow(row, fieldRec.name, eventName),
  };
  const label = row.edge.target_label || row.edge.id || "the FDR pivot";
  return h(
    "details",
    { class: "reach-details reach-edge" },
    h("summary", { class: "reach-summary" }, label, " ", h("span", { class: "reach-chip", dataset: { basis: basisText(row.edge.basis) } }, basisText(row.edge.basis))),
    runControl(lib, (p) => lib.fdrQueries.generate(pivot, p), params, {}, { hold: m.hold, name: row.edge.target_label || row.edge.id || "what this reaches" }),
  );
}

// The record types the field rides on and its route, under the edges by
// name, for a field click.
function fieldPivots(m) {
  const el = pivotNames(m, ". Click a value for the SPL.");
  if (!el) return null;
  const fieldRec = m.view && m.view.pack;
  const events = fieldRec ? fieldRec.events || [] : [];
  if (events.length) {
    const shown = events.slice(0, 6).join(", ") + (events.length > 6 ? ` (+${events.length - 6} more)` : "");
    el.appendChild(h("div", { class: "reach-row__body reach-row__feeds" }, `On the record: ${shown}`));
  }
  const routeSummary = fieldRec && fieldRec.route && fieldRec.route.summary;
  const ROUTE_TEXT = m.lib.ROUTE_TEXT;
  if (routeSummary && ROUTE_TEXT && ROUTE_TEXT[routeSummary]) {
    el.appendChild(h("div", { class: "reach-chip", dataset: { basis: routeSummary === "direct_anchor" || routeSummary === "one_hop" ? "confirmed" : "asserted" } }, ROUTE_TEXT[routeSummary]));
  }
  return { el, n: m.edges.length };
}

export function hooks(lib) {
  return {
    // The pack name when the raw name resolves into the FDR bundle on
    // this sourcetype; the name as Splunk shows it otherwise (the dotted
    // JSON path on a nested field).
    names(raw, container) {
      const resolved = lib.resolve ? lib.resolve(raw, lib.fields.searchIndex().fields) : null;
      if (!resolved) return { name: raw, fallback: null };
      if (container) return { name: lib.fields.fieldOn(container, resolved.name) ? resolved.name : raw, fallback: raw };
      return { name: resolved.name, fallback: raw };
    },
    place: placeClick,
    insert: async () => (req) => lib.bridge.apply(req),
    // The event's own index is a fact; the configured index is the
    // fallback when the row does not say; the macro is the last resort.
    scopeFor: async (m) => m.ctx.scope || (await configuredIndex()) || null,
    pivots(m) {
      if (!m.isValue) return fieldPivots(m);
      const rows = [];
      const fdr = fdrEdgeRow(m);
      if (fdr) rows.push(fdr);
      rows.push(...packEdgeRows(m, (edge, params, pmeta) => runControl(lib, (p) => lib.pivot.generate(edge, p, { pack: lib.packs.pack(edge.packId) }), params, pmeta, { hold: m.hold, name: edge.label }), { before: (params) => { if (m.scope) params.index = m.scope; } }));
      return rows.length ? { el: h("div", { class: "reach-edges" }, ...rows), n: rows.length, fold: true } : null;
    },
    pattern(m) {
      const testIndex = m.on("pattern") && m.container ? m.scope : null;
      return {
        fieldClass: INDEXED_DEFAULTS.has(m.name) ? "indexed" : undefined,
        liveTest: m.container ? (rung) => runControl(lib, () => patternSearch(lib, rung, { index: testIndex, sourcetype: m.container, field: m.name }), {}, { hold: m.hold, name: `pattern test on ${m.container}`, origin: "pattern" }) : undefined,
      };
    },
  };
}

export default { hooks, runControl, patternSearch, aliasMap, searchPageUrl, INDEXED_DEFAULTS };
