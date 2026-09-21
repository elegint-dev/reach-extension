// drawer: the query panel. SPL block + param inputs + hazards + copy + inline/macro tabs.
//
//   drawer({
//     state: "empty" | "filled" | "copied" | "error",
//     title: "the process that caused this event",
//     subtitle: "ContextProcessId → TargetProcessId on DnsRequest",
//     spl: { inline: "…", macro: "…" },     // or a string (inline only)
//     form: "inline" | "macro",
//     params: [{ name: "aid", label: "aid", value: "", placeholder: "…", required: true, hint: "…" }],
//     missing: ["aid", "earliest"],         // names that render as $NAME$ in the text: Copy and the run link wait until they are bound
//     hazards: [{ level: "danger" | "caution" | "note", text: "…" }],
//     error: { code: "unscoped_pid", text: "…" },   // state "error": no SPL is offered
//     emptyText: "…",
//     onParam(name, value, event), onCopy(text, form), onTab(form),
//     onRun()                              // the run link was followed
//   })
//
// Element API: el.setSpl({inline, macro}), el.setState(state), el.setParams(params),
// el.setHazards(list), el.setMacros({inline, macro}), el.showTab(form), el.copy(),
// el.setEmptyText(text), el.text() (the open tab's text, inline when the macro tab is empty).
// el.fill({ title, subtitle, spl, macro, params, hazards, macros, missing }):
// one rendered query, state "filled". spl is the inline text (or {inline,
// macro}), macro the macro-form text. params undefined leaves the inputs
// alone (a keystroke refill must not rebuild the input under the cursor);
// [] clears them. macros undefined clears the macro status. missing is the
// generator's unbound parameter list: while it has a name the text carries
// a $NAME$ placeholder, so Copy is disabled with a reason naming it and the
// run link gives way to the same line; a bound input refills and frees both.
// el.fail({ title, subtitle, params, error }): state "error" with no text,
// no hazards and no macro status; params as for fill.
// fillFrom(el, spec, generate, rebuild): run generate() and fill the
// drawer from what it returns, or fail it with the query error it throws
// (SplError, PivotError; every error with spec.catchAll). The one place
// the error branch lives.
// openFold(): a title-block action opens the paste fold the drawer sits in
// on stacked surfaces and brings it under the pinned frame.
// Under the code block the advisor's line ("advisor: N notes", a fold on
// the findings) follows every setSpl; app/components/advisor.js draws it.
// Events (bubbling): `param` {name, value}, `copy` {text, form}, `tab` {form}.
//
// `$NAME$` placeholders are marked.
//
// setMacros({ inline: { env, needed: [{name, defined, hint}] }, macro: {...} }):
// which of the pack's macros the tab's text calls, per Splunk instance
// (env), and whether conf-macros found each one there. `defined` is
// true, false, or null/undefined for "not checked" (no discovery run
// yet). Only a macro read back as false (`defined === false`) greys Copy
// on that tab, with a reason naming it and the environment; an unchecked
// one is shown but never blocks. Neither tab is disabled by the other's
// state, so the expanded form stays one click away.

import { h, uid, replace } from "./h.js";
import { callout } from "./callout.js";
import { advisorLine } from "./advisor.js";
import * as modules from "../lib/modules.js";
import * as settings from "../lib/settings.js";
import * as recipe from "../lib/recipe.js";
import * as kql from "../lib/kql.js";
import { TERMS, isSentinel } from "../lib/platform.js";

// The paste fold sits under the title block on stacked surfaces; an action
// that fills the drawer on render (Sample search, Run) opens it there. On
// the wide tab the drawer is in the rail already.
export function openFold() {
  const fold = document.querySelector(".r-paste");
  if (fold && !fold.hidden) {
    fold.open = true;
    const bar = document.querySelector(".r-bar");
    const top = fold.getBoundingClientRect().top + window.scrollY - (bar ? bar.offsetHeight : 0) - 8;
    window.scrollTo(0, Math.max(0, top));
    return;
  }
  const drawer = document.querySelector(".r-drawer");
  if (drawer && typeof drawer.scrollIntoView === "function") drawer.scrollIntoView({ block: "nearest" });
}

const LEVEL_TO_KIND = { danger: "hazard", hazard: "hazard", caution: "caution", warning: "caution", note: "note", info: "note", asserted: "asserted" };

// Pure macro-tab state, exported so it is testable without a DOM: a
// missing macro (a definite `defined === false`, never a null/undefined
// "not checked") is the only thing that ever blocks Copy.
export function macroStateText(m, env) {
  if (m.defined === true) return `defined on ${env}`;
  if (m.defined === false) return `not defined on ${env}`;
  return "not checked yet";
}

export function macrosBlocking(needed) {
  return (needed || []).filter((m) => m.defined === false);
}

// "" when nothing blocks; the disabled Copy button's title otherwise.
export function copyBlockReason(info, form) {
  const missing = macrosBlocking(info && info.needed);
  if (!missing.length) return "";
  const names = missing.map((m) => m.name).join(", ");
  const other = form === "macro" ? "Inline" : "Macro";
  return `Not copied: ${names} ${missing.length === 1 ? "is" : "are"} not defined on ${info.env}. Switch to ${other}, or define ${missing.length === 1 ? "it" : "them"} first.`;
}

// "" when every parameter is bound; else the line that names the unbound
// ones, as the run hint and the disabled Copy's title. `params` supplies
// the labels the inputs carry (since/until on Sentinel), the name otherwise.
export function unboundReason(missing, params = []) {
  const names = (missing || []).filter(Boolean);
  if (!names.length) return "";
  const label = (n) => {
    const p = (params || []).find((x) => x && x.name === n);
    return p && p.label ? p.label : n;
  };
  const list = names.map(label).join(", ");
  return `${list} ${names.length === 1 ? "is" : "are"} unbound: fill ${names.length === 1 ? "it" : "them"} in above.`;
}

function renderSplLines(text) {
  const out = [];
  const lines = String(text ?? "").split("\n");
  lines.forEach((line, i) => {
    const span = h("span", { class: "r-spl__line" });
    const re = /\$([A-Za-z_][A-Za-z0-9_]*)\$/g;
    let last = 0;
    let m;
    while ((m = re.exec(line))) {
      if (m.index > last) span.appendChild(document.createTextNode(line.slice(last, m.index)));
      span.appendChild(h("mark", { class: "r-spl__param", dataset: { param: m[1] } }, m[0]));
      last = m.index + m[0].length;
    }
    if (last < line.length) span.appendChild(document.createTextNode(line.slice(last)));
    out.push(span);
    if (i < lines.length - 1) out.push(document.createTextNode("\n"));
  });
  return out;
}

export function drawer(props = {}) {
  const {
    state: initialState = "empty",
    title = "",
    subtitle = "",
    form: initialForm = "inline",
    params = [],
    hazards = [],
    error = null,
    emptyText = "Click a value or a row in the ledger and the SPL for it appears here, ready to copy.",
    onParam,
    onCopy,
    onTab,
    onRun,
  } = props;

  let spl = typeof props.spl === "string" ? { inline: props.spl, macro: "" } : { inline: "", macro: "", ...(props.spl || {}) };
  let form = initialForm;
  let state = initialState;
  let copiedTimer = null;
  let missing = Array.isArray(props.missing) ? props.missing.slice() : [];
  let paramList = params || [];
  const unbound = () => unboundReason(missing, paramList);

  // Per-tab macro status: which of the pack's macros this tab's text calls,
  // whether conf-macros found each defined on the environment, and (when
  // not) a one-line hint for defining it. Set by the caller (setMacros);
  // empty by default, which reproduces today's behaviour exactly.
  function emptyMacros() {
    return { env: null, needed: [] }; // needed: [{ name, defined: true|false|null, hint }]
  }
  let macros = { inline: emptyMacros(), macro: emptyMacros() };

  const ids = { inline: uid("tab-inline"), macro: uid("tab-macro"), panelInline: uid("panel-inline"), panelMacro: uid("panel-macro") };

  const titleEl = h("p", { class: "r-drawer__title" }, title); // the fold's summary carries the name; the drawer is not a section
  const subEl = h("p", { class: "r-drawer__sub" }, subtitle);
  const status = h("p", { class: "r-drawer__status", role: "status", "aria-live": "polite" });

  const tabs = h(
    "div",
    { class: "r-tabs", role: "tablist", "aria-label": `${TERMS.lang} form` },
    tab("inline", "Inline", "expanded, runs anywhere"),
    tab("macro", "Macro", "calls queries/macros"),
  );

  function tab(key, label, hint) {
    return h(
      "button",
      {
        type: "button",
        id: ids[key],
        class: "r-tabs__tab",
        role: "tab",
        "aria-selected": form === key ? "true" : "false",
        "aria-controls": key === "inline" ? ids.panelInline : ids.panelMacro,
        tabindex: form === key ? "0" : "-1",
        title: hint,
        onClick: () => showTab(key),
        onKeydown: (e) => {
          if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
            e.preventDefault();
            showTab(key === "inline" ? "macro" : "inline", true);
          }
        },
      },
      label,
    );
  }

  const code = h("code", { class: "r-spl__code" });
  const pre = h("pre", { class: "r-spl", tabindex: "0", "aria-label": TERMS.lang, title: "Copy to clipboard: press c or use the button" }, code);
  const hoverCopy = h(
    "button",
    { type: "button", class: "r-spl__copy", title: "Copy to clipboard", "aria-label": `Copy ${TERMS.lang} to clipboard`, onClick: () => copy() },
    "Copy",
  );
  const codeWrap = h("div", { class: "r-spl-wrap" }, pre, hoverCopy);
  const macroList = h("ul", { class: "r-drawer__macros", "aria-label": "Macro status" });
  const panel = h("div", { class: "r-drawer__panel", role: "tabpanel", id: ids.panelInline, "aria-labelledby": ids.inline }, codeWrap, macroList);

  const paramsForm = h("form", { class: "r-drawer__params", onSubmit: (e) => e.preventDefault() });
  const hazardList = h("ul", { class: "r-drawer__hazards", "aria-label": "Hazards" });

  const copyBtn = h(
    "button",
    { type: "button", class: "r-drawer__copy", onClick: () => copy() },
    h("span", { class: "r-drawer__copylabel" }, `Copy ${TERMS.lang}`),
    h("kbd", { "aria-hidden": "true" }, "c"),
  );

  // The open action beside Copy. Splunk: "Run in Splunk", the search app
  // on the base URL from Settings. Sentinel: "Open in portal", the Logs
  // blade deep link on the workspace the blade was last seen on
  // (recipe.js), the query already run. Without a base URL or a known
  // workspace the hint says what gives one; the link never points at nothing.
  const runLink = h("a", { class: "r-drawer__run", target: "_blank", rel: "noopener noreferrer", hidden: true, onClick: () => onRun && onRun() }, isSentinel() ? "Open in portal " : "Run in Splunk ", h("span", { "aria-hidden": "true" }, "↗"));
  const SENTINEL_RUN_HINT = "Open the Logs blade once so Reach knows the workspace, and an Open in portal link appears here.";
  const SPLUNK_RUN_HINT = "Set a Splunk base URL in Investigation ▸ settings to get a run link here.";
  const runHint = h("p", { class: "r-muted r-drawer__runhint", hidden: true }, isSentinel() ? SENTINEL_RUN_HINT : SPLUNK_RUN_HINT);
  let workspace = null; // Sentinel: the resource id the link opens on
  let workspaceAsk = null;
  let linkAsk = null; // the pending kql.deepLink() call, for tests to await
  let linkSeq = 0;
  function askWorkspace() {
    if (workspace || workspaceAsk) return;
    workspaceAsk = recipe
      .environments()
      .then((list) => {
        const env = list.find((e) => e.resourceId);
        if (env) workspace = env.resourceId;
      })
      .catch(() => {})
      .then(() => {
        workspaceAsk = null;
        if (workspace) renderRun();
      });
  }
  function renderRun() {
    const text = spl[form] || spl.inline || "";
    const filled = Boolean(text) && state === "filled";
    // A $NAME$ placeholder in the text is not a search to run: the hint
    // names what to bind, on either platform, and the link waits.
    const blocked = filled ? unbound() : "";
    if (blocked) {
      linkSeq += 1;
      runLink.hidden = true;
      runHint.textContent = `No run link yet: ${blocked}`;
      runHint.hidden = false;
      return;
    }
    runHint.textContent = isSentinel() ? SENTINEL_RUN_HINT : SPLUNK_RUN_HINT;
    if (isSentinel()) {
      if (filled && !workspace) askWorkspace();
      runHint.hidden = !(filled && !workspace);
      const seq = ++linkSeq;
      runLink.hidden = true;
      if (!(filled && workspace)) return;
      linkAsk = kql
        .deepLink({ resourceId: workspace, kql: text, timespan: "P1D" })
        .then((url) => {
          if (seq !== linkSeq) return;
          runLink.href = url;
          runLink.hidden = false;
        })
        .catch(() => {})
        .then(() => {
          linkAsk = null;
        });
      return;
    }
    const base = settings.splunkBase();
    const usable = base && filled;
    runLink.hidden = !usable;
    runHint.hidden = !(filled && !base);
    if (usable) {
      // Splunk's search app takes the query in `q`; a raw search needs a leading "search ".
      const q = /^\s*(search|\|)/.test(text.replace(/```[^`]*```\s*/g, "")) ? text : `search ${text}`;
      runLink.href = `${base}/app/search/search?q=${encodeURIComponent(q)}`;
    }
  }
  settings.subscribe(renderRun);

  // The advisor's quiet line under the code: what the rules would say
  // about the text, folded, never in the way of the copy. The advisor is
  // a module, off by default: off, the line is not mounted at all.
  const adviceSlot = h("div", { class: "r-drawer__advice" });
  let advice = null;
  function mountAdvice() {
    const want = modules.on("advisor");
    if (want && !advice) {
      advice = advisorLine();
      adviceSlot.replaceChildren(advice);
      advice.update(currentText());
    } else if (!want && advice) {
      advice = null;
      adviceSlot.replaceChildren();
    }
  }
  modules.subscribe(mountAdvice);

  const errorSlot = h("div", { class: "r-drawer__error" });
  const emptyLine = h("p", null, emptyText);
  const emptySlot = h("div", { class: "r-drawer__empty" }, emptyLine);

  const el = h(
    "aside",
    { class: "r-drawer", "aria-label": "Query" },
    h("header", { class: "r-drawer__head" }, h("p", { class: "r-drawer__kicker" }, "Query"), titleEl, subEl),
    emptySlot,
    errorSlot,
    h("div", { class: "r-drawer__body" }, tabs, panel, adviceSlot, paramsForm, hazardList, h("div", { class: "r-drawer__actions" }, copyBtn, runLink, status), runHint),
  );

  function currentText() {
    return form === "macro" ? spl.macro || "" : spl.inline || "";
  }

  function renderSpl() {
    replace(code, renderSplLines(currentText()));
    if (advice) advice.update(currentText());
    panel.id = form === "macro" ? ids.panelMacro : ids.panelInline;
    panel.setAttribute("aria-labelledby", ids[form]);
    renderMacros();
  }

  function currentMacros() {
    return macros[form] || emptyMacros();
  }

  function renderMacros() {
    const info = currentMacros();
    replace(
      macroList,
      info.needed.map((m) =>
        h(
          "li",
          { class: ["r-drawer__macro", m.defined === false && "r-drawer__macro--missing"] },
          h("code", null, m.name),
          h("span", { class: "r-drawer__macro-state" }, macroStateText(m, info.env)),
          m.defined === false && m.hint ? h("p", { class: "r-field__hint" }, m.hint) : null,
        ),
      ),
    );
    macroList.hidden = !info.needed.length;
    const pending = unbound();
    const reason = copyBlockReason(info, form) || (pending ? `Not copied: ${pending}` : "");
    const blocked = Boolean(reason);
    for (const btn of [copyBtn, hoverCopy]) {
      btn.disabled = blocked;
      btn.classList.toggle("r-drawer__copy--blocked", blocked);
      btn.title = reason || (btn === hoverCopy ? "Copy to clipboard" : "");
    }
  }

  function showTab(key, focus = false) {
    form = key === "macro" ? "macro" : "inline";
    renderRun();
    for (const t of tabs.children) {
      const on = t.id === ids[form];
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
    }
    renderSpl();
    if (onTab) onTab(form);
    el.dispatchEvent(new CustomEvent("tab", { bubbles: true, detail: { form } }));
  }

  function setParams(list) {
    paramList = list || [];
    replace(
      paramsForm,
      (list || []).map((p) => {
        const id = uid(`param-${p.name}`);
        return h(
          "div",
          { class: ["r-field", p.required && "r-field--required"] },
          h(
            "label",
            { class: "r-field__label", for: id },
            h("code", null, p.label ?? p.name),
            p.required ? h("span", { class: "r-field__req" }, "required") : null,
          ),
          h("input", {
            id,
            class: "r-field__input",
            type: p.type || "text",
            name: p.name,
            value: p.value ?? "",
            placeholder: p.placeholder ?? "",
            autocomplete: "off",
            spellcheck: "false",
            "aria-required": p.required ? "true" : null,
            onInput: (e) => {
              if (onParam) onParam(p.name, e.target.value, e);
              el.dispatchEvent(new CustomEvent("param", { bubbles: true, detail: { name: p.name, value: e.target.value } }));
            },
          }),
          p.hint ? h("p", { class: "r-field__hint" }, p.hint) : null,
        );
      }),
    );
    paramsForm.hidden = !(list && list.length);
  }

  function setHazards(list) {
    replace(hazardList, (list || []).map((hz) => h("li", null, callout({ kind: LEVEL_TO_KIND[hz.level] || "note", label: hz.label, body: hz.text }))));
    hazardList.hidden = !(list && list.length);
  }

  function setState(next, detail = {}) {
    state = next;
    el.classList.remove("r-drawer--empty", "r-drawer--filled", "r-drawer--copied", "r-drawer--error");
    el.classList.add(`r-drawer--${state}`);
    renderRun();
    const body = el.querySelector(".r-drawer__body");
    emptySlot.hidden = state !== "empty";
    errorSlot.hidden = state !== "error";
    body.hidden = state === "empty" || state === "error";
    if (state === "error") {
      const err = detail.error || error || { text: "This pivot cannot be emitted safely." };
      replace(
        errorSlot,
        callout({
          kind: "hazard",
          label: err.code === "unscoped_pid" ? "Not emitted: unscoped PID" : "Not emitted",
          body: err.text,
        }),
      );
    }
    if (state === "copied") {
      copyBtn.querySelector(".r-drawer__copylabel").textContent = "Copied";
      status.textContent = `Copied ${form} ${TERMS.lang} to the clipboard.`;
    } else {
      copyBtn.querySelector(".r-drawer__copylabel").textContent = `Copy ${TERMS.lang}`;
      status.textContent = "";
    }
  }

  async function copy() {
    if (state === "empty" || state === "error" || copyBtn.disabled) return;
    const text = currentText();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard unavailable (insecure context); the SPL is still selectable */
    }
    if (onCopy) onCopy(text, form);
    el.dispatchEvent(new CustomEvent("copy", { bubbles: true, detail: { text, form } }));
    setState("copied");
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      if (state === "copied") setState("filled");
    }, 1800);
  }

  function setSpl(next) {
    spl = typeof next === "string" ? { inline: next, macro: "" } : { inline: "", macro: "", ...(next || {}) };
    renderSpl();
    renderRun();
  }

  // { inline: { env, needed: [{name, defined, hint}] }, macro: {...} }.
  // Either side, or the whole argument, may be omitted: an absent side
  // keeps its needed list empty, so a caller with nothing to say about the
  // inline form need not say so.
  function setMacros(next) {
    macros = { inline: emptyMacros(), macro: emptyMacros(), ...(next || {}) };
    renderSpl();
  }

  function fill({ title: t, subtitle: sub, spl: text, macro: macroText, params: list, hazards: hz, macros: info, missing: unboundNames } = {}) {
    el.setTitle(t, sub);
    missing = Array.isArray(unboundNames) ? unboundNames.slice() : [];
    if (list !== undefined) setParams(list);
    setSpl(typeof text === "object" && text !== null ? text : { inline: text || "", macro: macroText || "" });
    setMacros(info || {});
    setHazards(hz || []);
    setState("filled");
  }

  function fail({ title: t, subtitle: sub, params: list, error: err } = {}) {
    el.setTitle(t, sub);
    missing = [];
    setSpl({ inline: "", macro: "" });
    setMacros({});
    if (list !== undefined) setParams(list);
    setHazards([]);
    setState("error", { error: err });
  }

  setParams(params);
  setHazards(hazards);
  renderSpl();
  setState(state, { error });

  mountAdvice();
  el.setSpl = setSpl;
  el.setState = setState;
  el.setParams = setParams;
  el.setHazards = setHazards;
  el.setMacros = setMacros;
  el.fill = fill;
  el.fail = fail;
  el.showTab = showTab;
  el.copy = copy;
  el.setEmptyText = (t) => {
    emptyLine.textContent = t;
  };
  el.setTitle = (t, s) => {
    titleEl.textContent = t ?? "";
    subEl.textContent = s ?? "";
  };
  el.pre = pre;
  // The open tab's text, the inline form when the macro tab is empty: the
  // same text the run link carries.
  el.text = () => currentText() || spl.inline || "";
  // Resolves once the Sentinel workspace lookup and the deep-link render it
  // may trigger have both settled; tests await this instead of a timer.
  el.ready = async () => {
    while (workspaceAsk || linkAsk) await (workspaceAsk || linkAsk);
  };
  return el;
}

// The query errors a generator throws; anything else is a bug and propagates.
function isQueryError(err) {
  return Boolean(err) && (err.name === "SplError" || err.name === "PivotError");
}

// spec: { title, subtitle, params(out), errorParams(err), notes(out),
//         macros(out), errorText(err), catchAll }
// generate() → { spl | inline, macro, missing, hazards, sourcetype, ... }
// missing goes to the drawer as it is: the unbound names gate Copy and Run.
// params(out) and errorParams(err) build the drawer inputs; both are
// consulted only when rebuild is true, so a refill leaves the inputs alone.
// notes(out) adds hazards after the generator's own (the scope notes).
// Returns what generate() returned, or null when the drawer was failed.
export function fillFrom(el, spec, generate, rebuild = true) {
  let out;
  try {
    out = generate();
  } catch (err) {
    if (!spec.catchAll && !isQueryError(err)) throw err;
    el.fail({
      title: spec.title,
      subtitle: spec.subtitle,
      params: rebuild && spec.errorParams ? spec.errorParams(err) : undefined,
      error: { code: (err && err.code) || "pivot", text: spec.errorText ? spec.errorText(err) : String((err && err.message) || err) },
    });
    return null;
  }
  el.fill({
    title: spec.title,
    subtitle: spec.subtitle,
    spl: out.inline ?? out.spl ?? "",
    macro: out.macro || "",
    params: rebuild && spec.params ? spec.params(out) : undefined,
    hazards: [...(out.hazards || []), ...(spec.notes ? spec.notes(out) : [])],
    macros: spec.macros ? spec.macros(out) : undefined,
    missing: out.missing || [],
  });
  return out;
}

export default drawer;
