// The section every popup draws its bands into: its stylesheet, its scope
// line, the parameter form a pivot may need, the field route's hash, and
// the two surfaces Reach owns itself (the side panel hand-off and the
// anchored panel). The bands are in app/lib/bands/; popup-ui.js indexes
// both.
//
//   POPUP_CSS                         one stylesheet for the section and every band
//   scopeLine(text)                   the "on <sourcetype> · <record type>" line
//   MISSING_PARAM_META                the words for a parameter no pack names (earliest, latest, aid), per platform
//   missingParamMeta(name, meta, platform) → { label, placeholder, hint? }
//       the pack's words for the parameter, else the platform's, else the bare name
//   missingParamInputs({ missing, meta, platform, onChange, onPreview }) → [Element]
//       a line naming the still-unbound parameters, one labelled input per
//       one, then a Preview button: onChange(name, value) on every
//       keystroke, onPreview() on the button, disabled until every input
//       carries something. The caller regenerates locally; nothing here
//       runs or records
//   fieldHash(name, params)           the app's field route for a click, value and scope carried
//   offerToPanel(selection) → Promise<boolean>
//       the click, offered to the window's side panel; true when one took it
//   panelLine()                       the one line the page shows in that case
//   hostTheme(el)                     "dark" | "light", read off the host's own background
//   anchoredPanel({ section, x, y, theme, place?, closeWith? }) → Element
//       the one surface Reach draws itself: for a click the host wires no
//       popup to (fixed, near (x, y)), or beside a host menu the section
//       does not fit under (place: { left, top, width, maxHeight } from
//       menu-fit.js besideMenu, closeWith: the host menu, whose removal
//       closes the panel); one at a time; closePanel() removes it
//
// DOM module (uses h.js). Never fetches. Imports the bands' stylesheets
// only; no band imports this module back except meaning.js, which carries
// no stylesheet, so POPUP_CSS is whole whichever module loads first.

import { h } from "../components/h.js";
import { PLATFORM } from "./platform.js";
import { ask } from "./runtime.js";
import { PATTERN_CSS } from "./bands/pattern.js";
import { VERDICT_CSS } from "./bands/verdict.js";
import { ENRICH_CSS } from "./bands/enrich.js";
import { HOLD_CSS, BENIGN_CSS } from "./bands/hold-and-benign.js";

// Fluent palettes for the in-portal section. Light is the default; dark is
// selected by data-theme="dark" on the section (or the floating panel), which
// sentinel-grid.js reads off the portal's own surfaces. Only variables differ
// between the two, so every component rule below is written once.
const RC_LIGHT = `--rc-bg:#ffffff;--rc-bg2:#faf9f8;--rc-bg3:#f3f2f1;--rc-bg4:#edebe9;--rc-line:#edebe9;--rc-line2:#e1dfdd;--rc-line3:#8a8886;--rc-fg:#323130;--rc-fg2:#605e5c;--rc-accent:#0078d4;--rc-accent-hover:#106ebe;--rc-accent-press:#005a9e;--rc-accent-fg:#ffffff;--rc-link:#0078d4;--rc-ok:#107c10;--rc-ok-bg:#dff6dd;--rc-warn:#8a6d00;--rc-warn-bg:#fff4ce;--rc-warn-line:#ffb900;--rc-err:#a4262c;--rc-err-bg:#fde7e9;--rc-info:#004578;--rc-info-bg:#deecf9;--rc-purple:#5c2e91;--rc-purple-bg:#efe6fc;--rc-disabled:#a19f9d;--rc-disabled-bg:#f3f2f1;--rc-code-fg:#323130;`;
const RC_DARK = `--rc-bg:#1b1a19;--rc-bg2:#201f1e;--rc-bg3:#292827;--rc-bg4:#323130;--rc-line:#3b3a39;--rc-line2:#484644;--rc-line3:#8a8886;--rc-fg:#f3f2f1;--rc-fg2:#c8c6c4;--rc-accent:#2899f5;--rc-accent-hover:#3aa0f3;--rc-accent-press:#6cb8f6;--rc-accent-fg:#1b1a19;--rc-link:#2899f5;--rc-ok:#92c353;--rc-ok-bg:#1f3a1c;--rc-warn:#f2c661;--rc-warn-bg:#3d3016;--rc-warn-line:#ffb900;--rc-err:#f1707b;--rc-err-bg:#442726;--rc-info:#a8d4f8;--rc-info-bg:#0f3357;--rc-purple:#c3a5f0;--rc-purple-bg:#322346;--rc-disabled:#797775;--rc-disabled-bg:#292827;--rc-code-fg:#f3f2f1;`;
export const POPUP_CSS = `
.reach-section,.reach-panel{${RC_LIGHT}}
.reach-section[data-theme="dark"],.reach-panel[data-theme="dark"],.reach-panel[data-theme="dark"]>.reach-section{${RC_DARK}}
@media (prefers-color-scheme: dark){.reach-section:not([data-theme="light"]),.reach-panel:not([data-theme="light"]){${RC_DARK}}}
.reach-panel[data-theme="light"],.reach-panel[data-theme="light"]>.reach-section{${RC_LIGHT}}
.reach-section{border-top:1px solid var(--rc-line);margin-top:4px;padding:12px 16px 14px;font:13px/1.45 "Segoe UI","Segoe UI Web (West European)",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",sans-serif;background:var(--rc-bg);color:var(--rc-fg);width:min(560px,calc(100vw - 32px));max-height:70vh;overflow-y:auto;box-sizing:border-box;text-align:left;-webkit-font-smoothing:antialiased}
.reach-section *{box-sizing:border-box}
.reach-panel{background:var(--rc-bg);border:1px solid var(--rc-line2)}
.reach-panel[data-theme]>.reach-section{border-radius:4px}
.reach-section code{font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;color:var(--rc-code-fg);background:var(--rc-bg3);border:1px solid var(--rc-line);border-radius:2px;padding:0 4px;white-space:normal;word-break:break-all}
.reach-badge{display:inline-block;color:var(--rc-fg2);font-weight:600;font-size:11px;line-height:16px;letter-spacing:.06em;text-transform:uppercase;margin-bottom:2px}
.reach-scope{font-size:12px;color:var(--rc-fg2);margin:0 0 10px}
.reach-scope code{color:var(--rc-fg)}
.reach-row{margin:0 0 12px}.reach-row:last-child{margin-bottom:0}
.reach-row__title{color:var(--rc-fg);font-weight:600;margin-bottom:4px}
.reach-summary>.reach-row__title{display:inline;margin:0}
.reach-band{margin-top:10px}
.reach-band>.reach-row__title{margin-bottom:6px}
.reach-enrich__label{color:var(--rc-fg);font-weight:600;margin-bottom:4px}
.reach-note{font-size:12px;color:var(--rc-fg2);margin:0 0 10px}
.reach-row__body{color:var(--rc-fg);margin:0 0 6px;overflow-wrap:anywhere}
.reach-row__body--warn{color:var(--rc-fg);background:var(--rc-warn-bg);border-left:3px solid var(--rc-warn-line);border-radius:2px;padding:6px 10px;margin:6px 0}
.reach-row__body--danger{color:var(--rc-fg);background:var(--rc-err-bg);border-left:3px solid var(--rc-err);border-radius:2px;padding:6px 10px;margin:6px 0}
.reach-row__body--muted{color:var(--rc-fg2);font-style:italic}
.reach-row__body--note,.reach-row__body--caution,.reach-row__body--asserted{color:var(--rc-fg2);font-size:12px;padding-left:10px;border-left:2px solid var(--rc-line2);margin:4px 0}
.reach-row__body--caution{border-left-color:var(--rc-warn-line)}
.reach-section--panelline{min-width:0;width:auto;max-height:none;overflow:visible;padding:8px 16px 10px;white-space:nowrap}
.reach-section--panelline .reach-scope{display:inline;margin:0 0 0 6px}
.reach-section--flyout{position:absolute;top:0;left:100%;margin:0 0 0 12px;border-top:0;border-left:1px solid var(--rc-line2);min-width:0;width:440px;max-width:440px;max-height:calc(100vh - 48px);overflow-y:auto;border-radius:4px;box-shadow:0 10px 30px rgba(0,0,0,.45)}
.reach-row__body--asserted{border-left-color:var(--rc-accent)}
.reach-row__feeds{font-size:12px;color:var(--rc-fg2)}
.reach-chip{display:inline-block;font-size:11px;line-height:18px;font-weight:600;border-radius:9px;padding:0 8px;margin:0 4px 2px 0;background:var(--rc-warn-bg);color:var(--rc-warn);vertical-align:middle;white-space:nowrap}
.reach-chip[data-basis="confirmed"],.reach-chip[data-basis="validated"]{background:var(--rc-ok-bg);color:var(--rc-ok)}
.reach-chip[data-basis="user"]{background:var(--rc-info-bg);color:var(--rc-info)}
.reach-chip[data-basis="pack"]{background:var(--rc-bg3);color:var(--rc-fg)}
.reach-chip[data-basis="asserted"]{background:var(--rc-warn-bg);color:var(--rc-warn)}
.reach-chip[data-basis="proposed"]{background:var(--rc-purple-bg);color:var(--rc-purple)}
.reach-chip[data-basis="pending"]{background:var(--rc-bg3);color:var(--rc-fg2)}
.reach-runbook__line{display:flex;flex-wrap:wrap;align-items:center;gap:2px 6px;margin-bottom:2px}
.reach-runbook__name{font-weight:600;color:var(--rc-fg);overflow-wrap:anywhere}
.reach-chip[data-basis="danger"]{background:var(--rc-err-bg);color:var(--rc-err)}
.reach-value{margin:0 0 12px}
.reach-value__body{color:var(--rc-fg);margin:0 0 4px;overflow-wrap:anywhere;word-break:break-all}
.reach-value__body .reach-chip{margin-left:2px}
.reach-value__note,.reach-value__cite{color:var(--rc-fg2);font-size:12px;margin-top:2px;overflow-wrap:anywhere}
.reach-value__cite a{color:var(--rc-link);text-decoration:none}
.reach-value__cite a:hover{color:var(--rc-accent-hover);text-decoration:underline}
.reach-value__quote q{font-style:italic}
.reach-meaning{margin:2px 0 12px}
.reach-meaning__text{color:var(--rc-fg);line-height:1.5}
.reach-meaning__notes{color:var(--rc-fg2);font-size:12px;margin-top:4px}
.reach-meaning__concept{color:var(--rc-fg);margin-bottom:4px}
.reach-meaning__concept b{font-weight:600}
.reach-meaning__tags{font-size:12px;color:var(--rc-fg2);margin-top:4px}
.reach-meaning__tags code{color:var(--rc-fg)}
.reach-meaning__format{color:var(--rc-fg2)}
.reach-meaning__formatText{color:var(--rc-fg)}
.reach-edit{color:var(--rc-link);font-size:12px;text-decoration:none;cursor:pointer;background:none;border:0;padding:0;font-family:inherit}
.reach-edit:hover{color:var(--rc-accent-hover);text-decoration:underline}
.reach-form{margin-top:8px;display:grid;gap:8px}
.reach-form label{font-size:12px;font-weight:600;color:var(--rc-fg)}
.reach-form textarea,.reach-form input,.reach-form select{width:100%;box-sizing:border-box;min-height:32px;background:var(--rc-bg);border:1px solid var(--rc-line3);border-radius:2px;color:var(--rc-fg);font:inherit;padding:5px 8px}
.reach-form textarea:hover,.reach-form input:hover,.reach-form select:hover{border-color:var(--rc-fg)}
.reach-form textarea:focus,.reach-form input:focus,.reach-form select:focus,.reach-input:focus{outline:0;border-color:var(--rc-accent);box-shadow:inset 0 -2px 0 var(--rc-accent)}
.reach-form textarea::placeholder,.reach-form input::placeholder,.reach-input::placeholder{color:var(--rc-fg2)}
.reach-form textarea{min-height:64px;resize:vertical}
.reach-profile__top{line-height:1.7}
.reach-profile__val{white-space:nowrap;margin-right:4px}
.reach-profile__n{color:var(--rc-fg2);font-size:11px}
.reach-profile__when{font-size:11px;color:var(--rc-fg2);font-style:italic}
.reach-profile__when--old{color:var(--rc-warn)}
.reach-everywhere__list{list-style:none;margin:0;padding:0}
.reach-everywhere__row{margin:0 0 2px}
.reach-everywhere__st{text-decoration:none}
.reach-everywhere__st:hover code{text-decoration:underline}
.reach-everywhere__how{font-size:11px;color:var(--rc-fg2)}
.reach-workflows__link{margin-top:2px}
.reach-form__row{display:flex;gap:8px;align-items:center}
.reach-form__row>*{flex:1}
.reach-form__actions{display:flex;gap:8px;margin-top:4px;align-items:center}
.reach-btn{min-height:32px;padding:5px 16px;border-radius:2px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);font:inherit;font-size:14px;font-weight:600;cursor:pointer}
.reach-btn:hover{background:var(--rc-bg3)}
.reach-btn:active{background:var(--rc-bg4)}
.reach-btn--primary{border-color:var(--rc-accent);background:var(--rc-accent);color:var(--rc-accent-fg)}
.reach-btn--primary:hover{border-color:var(--rc-accent-hover);background:var(--rc-accent-hover)}
.reach-btn--primary:active{border-color:var(--rc-accent-press);background:var(--rc-accent-press)}
.reach-btn:disabled,.reach-btn--primary:disabled{background:var(--rc-disabled-bg);border-color:var(--rc-disabled-bg);color:var(--rc-disabled);cursor:default}
.reach-link{display:block;margin-top:6px;color:var(--rc-link);font-size:12px;text-decoration:none}
.reach-link:hover{color:var(--rc-accent-hover);text-decoration:underline}
.reach-spl{background:var(--rc-bg2);border:1px solid var(--rc-line);border-radius:2px;padding:8px 10px;color:var(--rc-code-fg);font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;margin:6px 0 8px;max-height:220px;overflow:auto}
@keyframes reach-spin{to{transform:rotate(360deg)}}
.reach-spinner{display:inline-block;width:11px;height:11px;margin-right:6px;vertical-align:-1px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:reach-spin .6s linear infinite;opacity:.85}
.reach-spl-wrap{margin:6px 0 8px}
.reach-spl-bar{display:flex;align-items:center;gap:6px}
.reach-spl-label{font-size:10px;color:var(--rc-fg2);font-weight:700;letter-spacing:.05em;text-transform:uppercase;margin-right:2px}
.reach-spl[hidden],.reach-spl-notes[hidden]{display:none}
.reach-spl-notes{margin-top:6px}
.reach-details{margin-top:4px}
.reach-summary{color:var(--rc-fg);font-weight:600;cursor:pointer;list-style:none;padding:2px 0}
.reach-summary::-webkit-details-marker{display:none}
.reach-summary::before{content:"▸ ";color:var(--rc-fg2)}
details[open]>.reach-summary::before{content:"▾ "}
.reach-details .reach-run-box{margin-top:8px}
.reach-edges{display:grid;gap:6px;margin-top:6px}
.reach-edge{border:1px solid var(--rc-line2);border-radius:4px;padding:6px 10px;background:var(--rc-bg)}
.reach-edge:hover{border-color:var(--rc-line3)}
.reach-edge>.reach-summary{font-weight:600}
.reach-edge .reach-row__body--muted{margin:2px 0 0 14px;font-size:12px}
.reach-run-btn{width:100%;margin-top:8px;min-height:32px;padding:5px 12px;border-radius:2px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);font:inherit;font-size:14px;font-weight:600;cursor:pointer}
.reach-run-btn:hover{background:var(--rc-bg3)}
.reach-run-btn:active{background:var(--rc-bg4)}
.reach-run-btn:disabled{background:var(--rc-disabled-bg);border-color:var(--rc-disabled-bg);color:var(--rc-disabled);cursor:default}
.reach-run-btn--live{border-color:var(--rc-accent);background:var(--rc-accent);color:var(--rc-accent-fg)}
.reach-run-btn--live:hover{border-color:var(--rc-accent-hover);background:var(--rc-accent-hover)}
.reach-run-split{display:flex;margin-top:8px}
.reach-run-split .reach-run-btn{margin-top:0;width:auto;flex:1;border-radius:2px 0 0 2px}
.reach-run-split .reach-run-btn--tab{flex:0 0 auto;border-left:0;border-radius:0 2px 2px 0;text-decoration:none;text-align:center;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;color:var(--rc-fg);padding:5px 14px;font-weight:600}
.reach-run-split .reach-run-btn--tab:hover{background:var(--rc-bg3);text-decoration:none}
.reach-input{background:var(--rc-bg);border:1px solid var(--rc-line3);border-radius:2px;color:var(--rc-fg);font:inherit;padding:4px 8px;min-height:28px;width:160px}
.reach-input:hover{border-color:var(--rc-fg)}
.reach-results{margin-top:12px;border-top:1px solid var(--rc-line);padding-top:12px}
.reach-results__head{display:flex;align-items:baseline;gap:10px;margin-bottom:8px}
.reach-results__title{font-weight:600;color:var(--rc-fg)}
.reach-results__hint{font-size:12px;color:var(--rc-fg2);flex:1}
.reach-mini{font:inherit;font-size:12px;min-height:24px;padding:2px 8px;border-radius:2px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);cursor:pointer}
.reach-mini:hover{background:var(--rc-bg3)}
.reach-result{background:var(--rc-bg2);border:1px solid var(--rc-line);border-radius:4px;padding:8px 10px;margin-bottom:8px;position:relative}
.reach-result__n{position:absolute;top:6px;right:10px;font-size:11px;color:var(--rc-fg2)}
.reach-result__kv{display:grid;grid-template-columns:max-content 1fr;gap:3px 12px;margin:0;align-items:baseline}
.reach-result__kv dt{color:var(--rc-fg2);font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:11px;white-space:nowrap}
.reach-result__kv dd{margin:0;display:flex;align-items:baseline;gap:6px;min-width:0}
.reach-result__v{font:inherit;font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;color:var(--rc-fg);background:none;border:0;padding:0;text-align:left;cursor:copy;word-break:break-all;white-space:pre-wrap;min-width:0}
.reach-result__v:hover{background:var(--rc-bg4);border-radius:2px;box-shadow:0 0 0 3px var(--rc-bg4)}
.reach-result__go{color:var(--rc-link);text-decoration:none;font-size:12px;flex:0 0 auto;opacity:.8}
.reach-result__go:hover{opacity:1;text-decoration:underline}
.reach-results__more{font-size:12px;color:var(--rc-fg2);margin-top:4px}
.reach-chip[data-basis="danger"]{background:var(--rc-err-bg);color:var(--rc-err)}
${PATTERN_CSS}
${VERDICT_CSS}
${ENRICH_CSS}
${HOLD_CSS}
${BENIGN_CSS}`;


export function scopeLine(text) {
  return h("div", { class: "reach-scope" }, text);
}

export const MISSING_PARAM_META = Object.freeze({
  splunk: Object.freeze({
    earliest: { placeholder: "-24h", label: "earliest" },
    latest: { placeholder: "now", label: "latest" },
    aid: { placeholder: "32-hex agent id", label: "aid" },
  }),
  sentinel: Object.freeze({
    earliest: { placeholder: "-24h", label: "since" },
    latest: { placeholder: "now", label: "until" },
    aid: { placeholder: "32-hex sensor id", label: "aid" },
  }),
});

export function missingParamMeta(name, meta = {}, platform = PLATFORM) {
  const own = MISSING_PARAM_META[platform === "sentinel" ? "sentinel" : "splunk"];
  return (meta && meta[name]) || own[name] || { placeholder: name, label: name };
}

export function missingParamInputs({ missing = [], meta = {}, platform = PLATFORM, onChange, onPreview } = {}) {
  const out = [];
  const labels = missing.map((name) => missingParamMeta(name, meta, platform).label);
  out.push(h("div", { class: "reach-row__body reach-row__body--muted" }, `needs ${labels.join(", ")}`));
  const inputs = [];
  const previewBtn = h("button", { class: "reach-run-btn", type: "button", onClick: () => onPreview() }, "Preview");
  // Preview stays disabled (it would only re-show the same placeholders)
  // until every listed name has something typed in; a keystroke never
  // rebuilds these inputs, so checking them directly is enough.
  const sync = () => { previewBtn.disabled = inputs.some((i) => !i.value.trim()); };
  for (const name of missing) {
    const m = missingParamMeta(name, meta, platform);
    const input = h("input", { class: "reach-input", type: "text", placeholder: m.placeholder, title: m.hint || "", "aria-label": m.label, onInput: (e) => { onChange(name, e.target.value); sync(); } });
    inputs.push(input);
    out.push(h("div", { class: "reach-row__body" }, `${m.label}: `, input));
  }
  sync();
  out.push(previewBtn);
  return out;
}
// The field route's hash, carrying whatever facts the click actually had.
// field.js reads the value off ?value= on every render (the side-panel
// path builds the same route from its message, app/lib/selection.js) and
// learns the index as scope, so a tab opened from "Open in Reach →" lands
// on the value the click was on, not a bare field page. Nothing is held.
export function fieldHash(name, params) {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  return `#/f/${encodeURIComponent(name)}${qs ? `?${qs}` : ""}`;
}
// --- the side panel ----------------------------------------------------------
// A click's selection, offered to the window's side panel through the
// background worker (background.js, reach:selection), before the page
// draws anything. True when a panel took it: the page then shows
// panelLine() and the panel shows the field. False with no panel open,
// and on any failure, so the page falls back to its own section.
export async function offerToPanel(selection) {
  try {
    const res = await ask({ type: "reach:selection", selection });
    return Boolean(res && res.ok && res.panel);
  } catch {
    return false;
  }
}

export function panelLine() {
  return h("div", { class: "reach-section reach-section--panelline" }, h("span", { class: "reach-badge" }, "REACH"), h("span", { class: "reach-scope" }, "in the side panel →"));
}

// --- the anchored panel -----------------------------------------------------
//
// Reach appends into the host's own popup wherever the host has one: Splunk's
// value drilldown and field-info popdown, the Sentinel grid's cell menu. Two
// clicks have no host popup at all: a key name in Splunk's JSON event view,
// which Splunk renders as plain text, and a Sentinel cell when the blade's
// menu cannot be found (or Alt+click, which asks for Reach directly). For
// those, Reach draws a small fixed panel of its own next to the click. The
// same panel opens beside a host menu when the section does not fit under
// the menu's own items (menu-fit.js): the host's menu is never moved to
// make room. One at a time; a mousedown outside it or Escape closes it.

// Relative luminance of a CSS colour, or null for none/transparent. The
// background Reach draws under says which palette is on: dark → the dark
// section.
function luminance(rgb) {
  const m = /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)/.exec(rgb || "");
  if (!m) return null;
  if (m[4] !== undefined && Number(m[4]) === 0) return null; // transparent
  const [r, g, b] = [m[1], m[2], m[3]].map((v) => Number(v) / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function hostTheme(el) {
  let n = el;
  let guard = 0;
  while (n && n.nodeType === 1 && guard++ < 12) {
    const l = luminance(getComputedStyle(n).backgroundColor);
    if (l !== null) return l < 0.5 ? "dark" : "light";
    n = n.parentElement;
  }
  const body = luminance(getComputedStyle(document.body).backgroundColor);
  if (body !== null) return body < 0.5 ? "dark" : "light";
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

let panel = null;
let dismissWired = false;
let panelEngaged = false; // a mousedown has landed inside the open panel

// closePanel(el): only that panel, when it is still the open one; a
// removal observer for a menu that has already been replaced must not
// close the panel that came after it.
export function closePanel(el = null) {
  if (el && el !== panel) return;
  if (panel) panel.remove();
  panel = null;
}

// The host removes its menu on any mousedown outside it, a mousedown in
// Reach's panel included; a panel the user has clicked into stays, and
// closes on its own outside-mousedown or Escape rule instead.
function closeWhenGone(host, el) {
  if (!host || typeof MutationObserver !== "function") return;
  const obs = new MutationObserver(() => {
    if (el !== panel || panelEngaged) return obs.disconnect();
    if (document.body.contains(host)) return;
    obs.disconnect();
    closePanel(el);
  });
  obs.observe(document.body, { childList: true, subtree: true });
}

export function anchoredPanel({ section, x, y, theme, place = null, closeWith = null }) {
  closePanel();
  panelEngaged = false;
  if (!dismissWired) {
    dismissWired = true;
    document.addEventListener("mousedown", (e) => {
      if (!panel) return;
      if (panel.contains(e.target)) panelEngaged = true;
      else closePanel();
    }, true);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePanel(); }, true);
  }
  const t = theme || hostTheme(document.body);
  section.dataset.theme = t;
  // A string, not an object: h() hands object keys to style.setProperty,
  // which wants kebab-case and silently drops z-index written as zIndex;
  // the panel then sat under the host's sticky headers.
  panel = h("div", { class: "reach-panel", dataset: { theme: t }, style: "position:fixed;z-index:2147483000;left:0;top:0;max-height:70vh;overflow:auto;box-shadow:0 1.6px 3.6px rgba(0,0,0,.13),0 0.3px 0.9px rgba(0,0,0,.11);border-radius:4px" }, h("style", null, POPUP_CSS + "\n.reach-panel>.reach-section{border-top:0;margin-top:0;border-radius:8px}"), section);
  document.body.appendChild(panel);
  if (place) {
    // Beside a host menu: the placement is the caller's (menu-fit.js
    // besideMenu), the panel and its section share one height cap and
    // the section scrolls inside it.
    panel.style.left = `${place.left}px`;
    panel.style.top = `${place.top}px`;
    panel.style.width = `${place.width}px`;
    panel.style.maxHeight = `${place.maxHeight}px`;
    section.style.width = "100%";
    section.style.maxHeight = `${place.maxHeight}px`;
    closeWhenGone(closeWith, panel);
    return panel;
  }
  const r = panel.getBoundingClientRect();
  const left = Math.max(8, Math.min(x, window.innerWidth - r.width - 8));
  const top = y + r.height + 12 > window.innerHeight ? Math.max(8, y - r.height - 8) : y + 8;
  panel.style.left = `${left}px`;
  panel.style.top = `${top}px`;
  return panel;
}
