// Guided workflows: #/w/<id>?…
// Order: situation, Inputs (N), Searches (N), Rows (N), Expected results,
// Disambiguation, Troubleshooting (the tool master's order, headings.js).
// A generic walker over a workflow definition from lib/workflows.js, a
// pack's JSON. Nothing in here knows which feed it is rendering.
//
// A hunt (def.hunt) is a workflow meant to be saved in the SIEM as a
// scheduled search. Its page adds Save as scheduled alert (Splunk: the
// search into the open tab's search bar through the editor bridge, the
// analyst schedules it there; Sentinel: the KQL to the clipboard for an
// analytics rule) and, on Splunk inside the extension, Rows: one click
// runs the chosen search through the discovery relay and draws what came
// back, each cell that names a field opening the value page. Sentinel has
// no relay: Copy KQL, and the Logs blade's grid is where a cell opens the
// value page. A click here never holds or pins.

import { h, replace, spinner } from "../components/h.js";
import { step } from "../components/step.js";
import { callout } from "../components/callout.js";
import { chip } from "../components/chip.js";
import { table } from "../components/table.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { openFold, fillFrom } from "../components/drawer.js";
import { absentPage, backAction } from "./unknown.js";
import * as fdr from "../lib/fdr-queries.js";
import * as pivot from "../lib/pivot.js";
import * as packs from "../lib/packs.js";
import * as workflows from "../lib/workflows.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import * as discovery from "../lib/discovery.js";
import * as bridge from "../lib/editor-bridge.js";
import * as searches from "../lib/searches.js";
import { TERMS, PLATFORM, isSentinel, isPortalOrigin } from "../lib/platform.js";

// The FDR five, in start-page order, kept for callers that list them.

function inputs(meta, names, params, optional = []) {
  // A step may mark a required param optional for that step.
  return names.map((n) => ({
    ...(meta[n] || { label: n }),
    name: n,
    value: params[n] ?? "",
    required: optional.includes(n) ? false : (meta[n] || {}).required,
    hint: optional.includes(n) ? "optional; narrows the search a lot" : (meta[n] || {}).hint,
  }));
}

// One result's SPL, by the generator that owns its pivot: a pack edge or
// query through pivot.js (its macro form beside it where the query has
// one), a fields-sidecar edge through fdr-queries.js. The index is scope,
// resolved here for the sourcetype the search runs on (scope.js), unless
// the drawer bound one.
function generateFor(active, bound) {
  if (active.pivot && active.pivot.kind === "pack") {
    const edge = active.pivot.edge;
    const on = (edge.dst && edge.dst.sourcetype) || (edge.src && edge.src.sourcetype);
    const params = scope.bind(bound, on);
    const pack = packs.pack(active.pivot.packId);
    const out = pivot.generate(edge, params, { pack });
    let macro = "";
    try {
      macro = pivot.generate(edge, params, { pack, form: "macro" }).spl;
    } catch {
      macro = "";
    }
    return { inline: out.spl, macro, hazards: [...out.hazards, ...scope.notes(on)], missing: out.missing };
  }
  let out = fdr.generate(active.pivot, bound);
  const params = scope.bind(bound, out.sourcetype);
  if (params !== bound) out = fdr.generate(active.pivot, params);
  let macro = "";
  try {
    macro = fdr.generate(active.pivot, params, { form: "macro" }).spl;
  } catch {
    macro = "";
  }
  return { inline: out.spl, macro, hazards: [...out.hazards, ...scope.notes(out.sourcetype)], missing: [] };
}

// ---------------------------------------------------------------------------

export function render(ctx) {
  const id = String(ctx.params.id || "");
  const def = workflows.get(id, ctx);
  if (!def) {
    const all = workflows.list();
    const known = workflows.elsewhere(id);
    return absentPage({
      name: known ? known.title : id || "workflow",
      chip: known ? `not on ${TERMS.platform}` : "no such workflow",
      why: known ? `no ${TERMS.lang} search in the ${known.packId} pack's ${id} workflow; the pivots on a value or ${TERMS.field} page carry the value into ${TERMS.lang}` : `${all.length} workflows across the loaded packs`,
      actions: [backAction(ctx.goBack), h("a", { class: "r-btn", href: "#/" }, "Start")],
      sections: [h("section", { class: "r-section" }, h("ul", { class: "r-list" }, all.map((w) => h("li", null, h("a", { href: workflows.href(w.id) }, w.title)))))],
    });
  }
  const meta = def.meta || {};
  const gate = def.gate || null;
  // URL params (explicit navigation, chain hand-off) win over held
  // facts, which win over pinned ones. A typed input is this page's and
  // its URL's, never a held fact. The index is none of these: it is
  // scope, resolved when the search is generated, and the URL never
  // carries it; one typed in the drawer applies to this page only.
  const params = { ...facts.bound(), ...ctx.params };
  delete params.id;
  for (const k of scope.SCOPE_KEYS) delete params[k];
  const urlParams = () => {
    const out = { id };
    for (const [k, v] of Object.entries(params)) if (!scope.isScopeKey(k)) out[k] = v;
    return out;
  };

  const el = h("div", { class: "r-view r-view--workflow" });

  // ---- the title block ---------------------------------------------------
  // The scope line names the sourcetype the workflow starts from: the one
  // it was opened on, else the first its entries name, with the count of
  // the others. Run opens the fold the render filled; Copy takes the drawer's text.
  const entry = workflows.list().find((w) => w.id === id) || { entries: [] };
  // A hunt starts from no value, so its entries are empty; the containers
  // its searches run on stand in.
  const onSts = [...new Set([ctx.params.st, ...entry.entries.map((e) => e.sourcetype), ...(def.containers || [])].filter(Boolean))];
  const scopeItems = onSts.length
    ? [h("span", null, "on ", h("a", { class: "r-scope__name", href: `#/st/${encodeURIComponent(onSts[0])}`, title: onSts[0] }, h("code", null, onSts[0]))), onSts.length > 1 ? `also on ${onSts.length - 1} more` : null]
    : [`a ${entry.packId || "pack"} workflow`];
  // The text of the search in the drawer, kept by refresh() so an action
  // hands on exactly what the page rendered.
  let rendered = { text: "", missing: [] };
  const saveStatus = h("p", { class: "r-hunt__status r-muted", role: "status", "aria-live": "polite" });
  const saveBtn = def.hunt
    ? h(
        "button",
        {
          type: "button",
          class: "r-btn r-hunt__save",
          title: isSentinel() ? "the KQL to the clipboard, for the rule query of a scheduled analytics rule" : "the SPL into the open Splunk tab's search bar; Save As, Alert there",
          onClick: async () => {
            if (!rendered.text || rendered.missing.length) {
              saveStatus.textContent = rendered.missing.length ? `Fill in ${rendered.missing.join(", ")} first.` : "No search rendered yet.";
              return;
            }
            const res = await bridge.apply({ text: rendered.text, mode: "set", form: "stage", platform: PLATFORM, origin: envSel.value || (origins[0] && origins[0].origin) || undefined, trace: { origin: "workflow", name: def.title, container: onSts[0] || null } });
            saveStatus.textContent = res.ok
              ? isSentinel()
                ? `${res.notice}. Analytics, Create, Scheduled query rule: paste it as the rule query and set the lookback to the window.`
                : res.how === "copied"
                  ? `${res.notice}. Then Save As, Alert, on a schedule that matches the window.`
                  : "In the search bar. In Splunk: Save As, Alert, on a schedule that matches the window."
              : res.notice || "Could not hand the search on.";
          },
        },
        "Save as scheduled alert",
      )
    : null;
  el.appendChild(
    titleBlock({
      kind: "workflow",
      h1: def.title,
      chips: [chip({ kind: "route", value: "one-hop", text: def.kicker })],
      scope: scopeItems,
      callout: def.when ? callout({ kind: "why", label: "When you are here", body: def.when }) : null,
      actions: [
        h("button", { type: "button", class: "r-btn", onClick: openFold }, "Run"),
        h("button", { type: "button", class: "r-btn", onClick: () => ctx.drawer.copy() }, `Copy ${TERMS.lang}`),
        saveBtn,
      ],
    }),
  );
  if (saveBtn) el.appendChild(h("section", { class: "r-section r-hunt__handoff" }, saveStatus, def.hunt.schedule ? h("p", { class: "r-secondary" }, def.hunt.schedule) : null));

  // ---- situation --------------------------------------------------------
  const situation = h(
    "section",
    { class: "r-section" },
    def.lead ? h("p", { class: "r-secondary" }, def.lead) : null,
    def.valueLink && params.value
      ? h("p", null, h("a", { href: `#/v/${encodeURIComponent(params.value)}` }, "See which fields carry that value"))
      : null,
  );
  if (situation.children.length) el.appendChild(situation);

  // ---- steps (why each input is needed) ---------------------------------
  const stepsWrap = h("section", { class: "r-section" }, headingNode("inputs", def.steps.length));
  let n = 0;
  for (const s of def.steps) {
    n += 1;
    const gateEl = s.gate && gate ? gateBlock() : null;
    stepsWrap.appendChild(
      step({
        n,
        title: s.title,
        required: s.required !== false,
        state: s.names.filter((name) => !(s.optional || []).includes(name)).every((name) => params[name]) ? "done" : "current",
        input: inputs(meta, s.names, params, s.optional || []),
        why: s.why,
        help: s.help,
        children: gateEl,
        onInput: (name, value) => {
          params[name] = value;
          ctx.setUrl("workflow", urlParams());
          refresh(false);
        },
      }),
    );
  }
  el.appendChild(stepsWrap);

  // ---- the searches: the results to choose from, one in the drawer ------
  const resultSlot = h("div", { class: "r-result" });
  let searchesHeading = headingNode("searches", 0);
  el.appendChild(h("section", { class: "r-section" }, searchesHeading, h("p", { class: "r-muted" }, "In the drawer, ", h("kbd", null, "c"), " copies it."), resultSlot));

  // ---- rows: the chosen search run once, here (a hunt on Splunk) --------
  let rowsHeading = headingNode("rows", 0);
  const rowsStatus = h("p", { class: "r-hunt__status r-muted", role: "status", "aria-live": "polite" });
  const rowsSlot = h("div", { class: "r-hunt__rows" });
  const envSel = h("select", { class: "r-hunt__env", "aria-label": "Splunk instance" });
  const runBtn = h("button", { type: "button", class: "r-btn r-hunt__run", disabled: true, onClick: () => runHunt() }, "Run here");
  let activeResult = null;
  let origins = [];
  if (def.hunt && !isSentinel()) {
    el.appendChild(h("section", { class: "r-section r-hunt" }, rowsHeading, h("p", { class: "r-muted" }, "The chosen search, run once through an open Splunk tab with your session. Nothing is scheduled from here."), h("div", { class: "r-hunt__controls" }, envSel, runBtn), rowsStatus, rowsSlot));
    (async () => {
      if (discovery.available()) {
        try {
          origins = (await discovery.environments()).filter((o) => !isPortalOrigin(o.origin));
        } catch (err) {
          rowsStatus.textContent = err && err.message ? err.message : String(err);
        }
      }
      replace(envSel, origins.map((o) => h("option", { value: o.origin }, `${o.origin}${o.tabs ? "" : " (no tab open)"}`)));
      envSel.hidden = origins.length < 2;
      runBtn.disabled = !origins.length;
      if (!origins.length) rowsStatus.textContent = discovery.available() ? "No Splunk instance enabled yet: enable one from the popup and keep a tab open." : "Runs from the extension, with a Splunk tab open.";
    })();
  }

  async function runHunt() {
    const origin = envSel.value || (origins[0] && origins[0].origin);
    if (!origin || !activeResult || !rendered.text) return;
    if (rendered.missing.length) {
      rowsStatus.textContent = `Fill in ${rendered.missing.join(", ")} first.`;
      return;
    }
    runBtn.disabled = true;
    runBtn.replaceChildren(spinner(), "Running…");
    rowsStatus.textContent = `Running ${activeResult.label} on ${origin}…`;
    try {
      searches.record({ text: rendered.text, platform: PLATFORM, source: "run", origin: "workflow", ran: true, name: def.title, container: onSts[0] || null }).catch(() => {});
      const r = await discovery.hunt(origin, rendered.text);
      drawRows(activeResult, r.rows);
      rowsStatus.textContent = `${r.rows.length.toLocaleString()} row${r.rows.length === 1 ? "" : "s"} from ${origin}${r.truncated ? ` (the first ${discovery.HUNT_MAX_ROWS.toLocaleString()})` : ""}.`;
      for (const m of r.messages || []) if (m.type === "ERROR" || m.type === "FATAL") rowsStatus.textContent += ` Splunk said: ${m.text}`;
    } catch (err) {
      rowsStatus.textContent = `Run failed: ${err && err.message ? err.message : String(err)}`;
    }
    runBtn.disabled = false;
    runBtn.textContent = "Run here";
  }

  // One cell that names a field is a link to the value page on that field,
  // on the container the search ran on; a count or a time is text.
  function drawRows(result, rows) {
    const next = headingNode("rows", rows.length);
    rowsHeading.replaceWith(next);
    rowsHeading = next;
    const on = result.pivot && result.pivot.edge && result.pivot.edge.dst ? result.pivot.edge.dst.sourcetype : "";
    const cols = result.shape && result.shape.columns.length ? result.shape.columns : Object.keys(rows[0] || {}).map((k) => ({ key: k, label: k, role: "value", field: k }));
    const cell = (row, c) => {
      const raw = row[c.key];
      const v = Array.isArray(raw) ? raw.join(", ") : raw == null ? "" : String(raw);
      if (!v) return "";
      if (!c.field || c.role === "count" || c.role === "time") return c.role === "count" ? { text: v, align: "right" } : v;
      const q = new URLSearchParams({ st: on, name: c.field });
      return h("a", { class: "r-hunt__cell", href: `#/v/${encodeURIComponent(v)}?${q}`, title: `${c.field} on ${on}` }, c.role === "host" ? v : h("code", null, v));
    };
    replace(
      rowsSlot,
      rows.length
        ? h("div", { class: "r-table-wrap" }, table({ caption: `${result.label}: ${rows.length} rows`, columns: cols.map((c) => ({ key: c.key, label: c.label })), rows: rows.map((row) => Object.fromEntries(cols.map((c) => [c.key, cell(row, c)]))) }))
        : h("p", { class: "r-muted" }, "No rows: nothing in the window matched."),
    );
  }

  // A question the data cannot answer, asked of the user: the definition
  // supplies the choices and what each one means; the answer is a param.
  function gateBlock() {
    const wrap = h("div", { class: "r-gate" });
    const say = h("p", { class: "r-gate__ask" }, "Not determinable from the data: ", h("b", null, gate.ask));
    const answer = h("div", { class: "r-gate__answer" });
    const choose = (which) => {
      params[gate.param] = which;
      ctx.setUrl("workflow", urlParams());
      for (const b of wrap.querySelectorAll("button")) b.setAttribute("aria-pressed", b.dataset.choice === which ? "true" : "false");
      replace(answer, answerFor(which));
      refresh(true, gate.param);
    };
    const btns = h(
      "div",
      { class: "r-gate__choices" },
      gate.choices.map((c) => h("button", { type: "button", class: "r-gate__btn", dataset: { choice: c.value }, "aria-pressed": params[gate.param] === c.value ? "true" : "false", onClick: () => choose(c.value) }, c.label)),
    );
    wrap.append(say, btns, answer);
    if (params[gate.param]) replace(answer, answerFor(params[gate.param]));
    return wrap;
  }

  function answerFor(which) {
    const c = gate.choices.find((x) => x.value === which);
    if (!c || !c.callout) return null;
    const co = c.callout;
    const body = co.link ? h("div", null, h("p", null, co.body), h("p", null, h("a", { href: co.link.href(params) }, co.link.text))) : co.body;
    return callout({ kind: co.kind, label: co.label, body });
  }

  // ---- expect / disambiguate / troubleshoot -----------------------------
  if (def.expect) el.appendChild(h("section", { class: "r-section" }, headingNode("expected-results"), callout({ kind: "expect", body: def.expect })));

  if ((def.disambiguate || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        headingNode("disambiguation"),
        h("ul", { class: "r-list" }, def.disambiguate.map((d) => h("li", null, d))),
      ),
    );
  }

  if ((def.troubleshooting || []).length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        headingNode("troubleshooting"),
        def.troubleshooting.map((t) =>
          h(
            "div",
            { class: "r-trouble" },
            h("h4", null, t.symptom),
            h("ul", { class: "r-list" }, (t.causes || []).map((c) => h("li", null, c))),
          ),
        ),
      ),
    );
  }

  let activeId = null;

  function refresh(rebuildParams, forceId) {
    const results = def.results(params) || [];
    const next = headingNode("searches", results.length);
    searchesHeading.replaceWith(next);
    searchesHeading = next;
    if (forceId) activeId = forceId;
    if (!activeId || !results.some((r) => r.id === activeId)) activeId = results[0] ? results[0].id : null;
    const active = results.find((r) => r.id === activeId) || null;
    activeResult = active;

    replace(
      resultSlot,
      h(
        "div",
        { class: "r-result__choices" },
        results.map((r) =>
          h(
            "button",
            {
              type: "button",
              class: ["r-result__btn", r.id === activeId && "is-active"],
              "aria-pressed": r.id === activeId ? "true" : "false",
              onClick: () => {
                activeId = r.id;
                refresh(true);
              },
            },
            r.label,
          ),
        ),
      ),
      active ? h("p", { class: "r-result__note" }, active.note) : null,
      active && active.caution ? callout({ kind: "caution", label: "Before you hand this on", body: active.caution }) : null,
    );

    if (!active) return;

    const noParams = rebuildParams ? [] : undefined;
    rendered = { text: "", missing: [] };
    if (active.gate && gate && (!params[gate.param] || !gate.emits(params[gate.param]) || !active.pivot)) {
      ctx.drawer.fail({ title: active.label, subtitle: "gated: answer the question above", params: noParams, error: { code: `${gate.param}_unknown`, text: gate.blocked } });
      return;
    }
    if (!active.pivot) {
      ctx.drawer.fail({ title: active.label, subtitle: def.kicker, params: noParams, error: { code: "no_pivot", text: `No ${TERMS.lang} for this result on this ${TERMS.sourcetype} yet: the pack knows the pivot, not the query.` } });
      return;
    }

    // Only an index typed in the drawer travels here; otherwise the scope
    // is resolved in generateFor. A result's own params sit on top.
    const bound = params.index ? { index: params.index } : {};
    for (const [k, v] of Object.entries(active.params || {})) if (v !== undefined && v !== null && v !== "") bound[k] = v;

    fillFrom(
      ctx.drawer,
      {
        title: active.label,
        subtitle: def.kicker,
        // A pack edge's parameter no step asked for (index, usually) renders as
        // $name$ and can be filled in the drawer, as on the field page.
        params: (out) => inputs(meta, out.missing, params).map((i) => ({ ...i, required: false })),
        errorParams: () => [],
        errorText: (err) =>
          err.code === "unscoped_pid"
            ? `An OS PID predicate needs a host and both ends of the window bound. The OS recycles PIDs, so an unscoped one matches unrelated processes. Fill in the steps above and the search appears. (${err.message})`
            : err.message,
      },
      () => {
        const out = generateFor(active, bound);
        rendered = { text: out.inline, missing: out.missing || [] };
        return out;
      },
      rebuildParams,
    );
  }

  if (ctx.setDrawerParamHandler) {
    ctx.setDrawerParamHandler((name, value) => {
      params[name] = value;
      ctx.setUrl("workflow", urlParams());
      refresh(false);
    });
  }
  // An index chosen or set under Settings lands in the open search.
  scope.follow(el, () => refresh(false));

  if (def.chain) {
    const c = def.chain(params);
    const chainWrap = h("section", { class: "r-section r-chain" });
    chainWrap.appendChild(
      step({
        n: n + 1,
        title: "Carry it forward",
        required: false,
        state: (c.inputNames || []).every((name) => params[name]) ? "done" : "todo",
        input: inputs(meta, c.inputNames || [], params),
        why: c.why,
        onInput: (name, value) => {
          params[name] = value;
          ctx.setUrl("workflow", urlParams());
          chainLink.href = def.chain(params).href;
        },
      }),
    );
    const chainLink = h("a", { class: "r-chain__link", href: c.href }, c.text, " →");
    chainWrap.appendChild(h("p", null, chainLink));
    el.appendChild(chainWrap);
  }

  el.afterMount = () => refresh(true);
  return el;
}

export default { render };
