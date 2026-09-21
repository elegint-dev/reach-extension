// Value page: #/v/<value>?st=<container>&name=<field>. The popups' twin:
// the title block (the value, its kind and verdict chips, the scope line,
// the callout slot, Hold and Mark benign), then the sections in the order
// modules.js SECTIONS gives, each drawn from the block the popups draw
// (popup-ui.js) and titled from the heading registry. Pivots carries the
// pack's edges first, then on Splunk the FDR carriers ledger: the fields
// that carry this value, folded. A bare value (no field named) keeps the
// kind reading, the carriers and the pattern.

import { h } from "../components/h.js";
import { fillFrom } from "../components/drawer.js";
import { fieldLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { ledger } from "../components/ledger.js";
import { provenanceChip } from "../components/dictionary.js";
import { valueEntry, whenValuesLand, patternBlock, verdictBlock, enrichBlock, hold, holdBlock, benignBlock, meaningBlock, everywhereBlock, workflowsBlock, recordPivot, plan as bandPlan, BAND_HEADING, SENTINEL_PIVOTS_LINE_PAGE, SENTINEL_NO_PIVOTS_NOTE } from "../lib/popup-ui.js";
import { PATTERN_CSS } from "../lib/bands/pattern.js";
import { VERDICT_CSS } from "../lib/bands/verdict.js";
import { ENRICH_CSS } from "../lib/bands/enrich.js";
import { HOLD_CSS, BENIGN_CSS } from "../lib/bands/hold-and-benign.js";
import { titleBlock, midEllipsis } from "../components/titleBlock.js";
import { packPivots } from "../components/packPivots.js";
import { heading, headingNode } from "../lib/headings.js";
import * as workflows from "../lib/workflows.js";
import { edgeRowsFor, pivotForEdgeRow, baseParamsForRow } from "../lib/reachability.js";
import * as bridge from "../lib/editor-bridge.js";
import * as lastEvent from "../lib/last-event.js";
import * as investigation from "../lib/investigation.js";
import { classify } from "../lib/search.js";
import * as fdr from "../lib/fdr-queries.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import { isSentinel, PLATFORM, TERMS } from "../lib/platform.js";
import { KEYS } from "../lib/storage-keys.js";
import * as enrich from "../lib/enrich.js";
import * as modules from "../lib/modules.js";
import * as efficiency from "../lib/efficiency.js";
import { source as kevSource } from "../lib/enrich/kev.js";
import { source as vtSource } from "../lib/enrich/virustotal.js";
import { ask, optionsUrl, copyText } from "../lib/runtime.js";

// Registered once, at module load: the app page imports this module once
// per session (unlike the content scripts, which re-register per popup
// open). Guarded so a hot reload during development never throws on a
// repeat id.
try {
  enrich.register(kevSource);
  enrich.register(vtSource);
} catch {
  /* already registered */
}

// Role per value kind, used to widen the seed carriers.
const KIND_ROLE = {
  sha256: "hash",
  sha1: "hash",
  md5: "hash",
  aid: "agent_id",
  ipv4: "ip",
  ipv6: "ip",
  domain: "domain",
  os_pid: "process_id",
  falcon_pid: "process_id",
  image: "file_path",
  file: "file_path",
};

// Path readings widen by name within the role: image names and modules, then
// everything else the role holds; registry fields by name alone.
const PATH_NAMES = {
  image: (n) => /Image|Module|Dll|Driver|BaseFileName|Interpreter|Pdb|Shell/i.test(n),
  registry: (n) => /^Reg|Registry/i.test(n),
};
PATH_NAMES.file = (n) => !PATH_NAMES.image(n) && !PATH_NAMES.registry(n);

const KIND_NOTE = {
  os_pid:
    "Small enough to be an OS PID. OS PIDs are recycled, so a PID on its own names a different process every few hours on a busy host; searches on one are scoped to a host and a window.",
  falcon_pid:
    "Too large for an OS PID, so this is almost certainly a Falcon process id (the TargetProcessId space). Those do not repeat on a host.",
  sha256: "SHA-256 is the hash the sensor carries and the one the TA's appinfo lookup is keyed on: the confirmed file join.",
  md5: "The corpus carries MD5 on far fewer events than SHA-256; if you have a choice, hunt the SHA-256.",
  aid: "An aid is per sensor install: reimage a host and you get a new one. It is still the stable key; ComputerName is not.",
};

const MAX_ROWS = 30;
const H1_CHARS = 40;

// What the value means as a literal of one field on one container: the
// one value line under Meaning, in the app's own markup (the popups draw
// the same model with popup-ui.js valueBlock). Drawn from what the
// catalogue holds; the pack's sidecar, fetched now for this container
// only, refills it in place. Null when the URL names no field, or the
// value carries no information (an open field with only a format).
export function valueLine({ catalogue, container, field, value }) {
  if (!catalogue || !container || !field || value === undefined || value === null) return null;
  const body = h("div", { class: "r-dict__body r-value__line" });
  const draw = (view) => {
    const row = valueEntry({ catalogue, container, field, value, view });
    body.replaceChildren();
    if (!row) return false;
    if (row.kind === "closed") {
      body.appendChild(h("p", { class: "r-secondary" }, h("code", null, row.value), `: not one of the ${row.count} documented values`));
      return true;
    }
    const own = row.source === "discovered" ? chip({ kind: "trust", value: "confirmed", text: row.lookup ? `${isSentinel() ? "your watchlist" : "your lookup"} · ${row.lookup}` : isSentinel() ? "your watchlist" : "your lookup" }) : row.source === "decode" ? chip({ kind: "trust", value: "confirmed", text: "decode table" }) : provenanceChip(row.provenance);
    body.appendChild(h("p", { class: "r-value__meaning" }, h("code", null, row.value), ": ", row.meaning, own ? [" ", own] : null));
    if (row.note) body.appendChild(h("p", { class: "r-secondary" }, row.note));
    if (row.quote && row.cite) body.appendChild(h("p", { class: "r-dict__quote r-secondary" }, h("q", null, row.quote), " ", h("span", { class: "r-muted" }, "(the reference's words)")));
    if (row.cite) body.appendChild(h("p", { class: "r-dict__ref r-secondary" }, h("span", { class: "r-muted" }, "Reference "), h("a", { href: row.cite.url, rel: "noreferrer", target: "_blank", class: "r-idlink" }, row.cite.title), h("span", { class: "r-muted" }, `, read ${row.cite.read_on}`)));
    return true;
  };
  const drawn = whenValuesLand({ catalogue, container, el: body, fill: () => draw(catalogue.fieldOn(container, field)) });
  if (!drawn) {
    if (catalogue.valuesReady(container)) return null;
    body.appendChild(h("p", { class: "r-muted r-dict__loading" }, `Looking ${field} up on ${container}…`));
  }
  return body;
}

// The pattern block draws with the popups' own classes; its stylesheet is
// self-contained and reads the popup palette, mapped here onto the app's
// tokens once per document.
const PATTERN_STYLE_ID = "reach-pattern-style";
const PATTERN_TOKENS = ".reach-pattern{--rc-bg:var(--bg-1);--rc-bg2:var(--bg-0);--rc-bg3:var(--bg-2);--rc-bg4:var(--bg-3);--rc-line:var(--line);--rc-line2:var(--line);--rc-line3:var(--control-line);--rc-fg:var(--fg-0);--rc-fg2:var(--fg-1);--rc-accent:var(--accent);--rc-accent-hover:var(--accent);--rc-accent-fg:var(--accent-fg);--rc-info-bg:var(--accent-bg);--rc-warn-line:var(--trust-asserted);--rc-code-fg:var(--fg-0);--rc-disabled:var(--fg-2);--rc-disabled-bg:var(--bg-2)}";
function ensurePatternStyle() {
  if (document.getElementById(PATTERN_STYLE_ID)) return;
  document.head.appendChild(h("style", { id: PATTERN_STYLE_ID }, PATTERN_CSS + PATTERN_TOKENS));
}

// The pattern builder for the value as one field's literal: the same block
// the popups draw, with the discovered profile's top values as the offline
// preview. Insert reaches the active tab's search bar through the editor
// bridge (Splunk); on Sentinel the block copies, since the Logs blade's
// editor is reachable only from inside its frame (sentinel-grid.js), not
// from the panel.
export function patternSection({ catalogue, container, field, value }) {
  if (!catalogue || !container || !field || value === undefined || value === null) return null;
  const view = catalogue.fieldOn(container, field);
  const block = patternBlock({
    value,
    field,
    container,
    platform: PLATFORM,
    samples: view && view.profile ? view.profile.top : null,
    fieldClass: efficiency.classOf(view || { name: field }, { platform: PLATFORM, resolve: (n) => catalogue.fieldOn(container, n) }).class,
    onInsert: isSentinel() ? undefined : (req) => bridge.apply(req),
  });
  if (!block) return null;
  ensurePatternStyle();
  return block;
}

// The Hold row draws with the popups' classes too: its own stylesheet plus
// the button and input rules it uses, mapped onto the app's tokens.
const HOLD_STYLE_ID = "reach-hold-style";
const HOLD_TOKENS = [
  ".reach-hold,.reach-attach{--rc-fg:var(--fg-0);--rc-fg2:var(--fg-1);--rc-bg:var(--bg-1);--rc-bg3:var(--bg-2);--rc-bg4:var(--bg-3);--rc-line3:var(--control-line);--rc-accent:var(--accent);--rc-accent-fg:var(--accent-fg);--rc-accent-hover:var(--accent);--rc-accent-press:var(--accent);--rc-link:var(--accent);--rc-disabled:var(--fg-2);--rc-disabled-bg:var(--bg-2);margin:0;min-width:0}",
  ".reach-hold .reach-btn,.reach-attach .reach-mini{min-height:32px;padding:5px 14px;border-radius:var(--radius-1);border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);font:inherit;font-size:var(--fs-2);font-weight:600;cursor:pointer}",
  ".reach-attach .reach-mini{min-height:28px;padding:2px 10px;font-weight:500}",
  ".reach-hold .reach-btn:hover,.reach-attach .reach-mini:hover{background:var(--rc-bg3)}",
  ".reach-hold .reach-btn--primary{border-color:var(--rc-accent);background:var(--rc-accent);color:var(--rc-accent-fg)}",
  ".reach-hold .reach-btn--primary:hover{filter:brightness(0.92);background:var(--rc-accent)}",
  ".reach-hold .reach-btn:disabled,.reach-attach .reach-mini:disabled{background:var(--rc-disabled-bg);border-color:var(--rc-disabled-bg);color:var(--rc-disabled);cursor:default;filter:none}",
  ".reach-hold .reach-input{background:var(--rc-bg);border:1px solid var(--rc-line3);border-radius:var(--radius-1);color:var(--rc-fg);font:inherit;padding:4px 8px;min-height:32px}",
  ".reach-hold .reach-input:focus{outline:2px solid var(--rc-accent);outline-offset:-1px}",
  "@media (max-width: 599px){.reach-hold .reach-btn,.reach-hold .reach-input,.reach-attach .reach-mini{min-height:var(--tap)}}",
].join("\n");
function ensureHoldStyle() {
  if (document.getElementById(HOLD_STYLE_ID)) return;
  document.head.appendChild(h("style", { id: HOLD_STYLE_ID }, HOLD_CSS + HOLD_TOKENS));
}

// The Known benign row shares the Hold row's classes and tokens; its own
// rules cover the offer under it.
const BENIGN_STYLE_ID = "reach-benign-style";
const BENIGN_TOKENS = [
  ".reach-benign .reach-benign__offer code{font-family:var(--font-mono);font-size:var(--fs-3);color:var(--rc-fg);background:var(--rc-bg3);border-radius:var(--radius-1);padding:4px 8px}",
  ".reach-benign .reach-input.reach-benign__expiry{padding-right:24px}",
].join("\n");
function ensureBenignStyle() {
  ensureHoldStyle();
  if (document.getElementById(BENIGN_STYLE_ID)) return;
  document.head.appendChild(h("style", { id: BENIGN_STYLE_ID }, BENIGN_CSS + BENIGN_TOKENS));
}

// The Mark benign action: the value into the known-benign set for this
// field and container, and the exclusion the set makes, inserted through
// the editor bridge (Splunk, into the active tab's bar) or copied
// (Sentinel). Null when the URL names no field or the field is scope.
export function benignAction({ catalogue, container, field, value }) {
  if (!field || value === undefined || value === null || value === "") return null;
  const view = catalogue && container ? catalogue.fieldOn(container, field) : null;
  // The editor write is the module's inject setting; off, the offer copies.
  const inject = modules.setting("benign", KEYS.benignInject) === true;
  const block = benignBlock({ ...holdContext({ container, field, value }), samples: view && view.profile ? view.profile.top : null, onInsert: inject ? (req) => bridge.apply(req) : null, compact: true });
  if (!block) return null;
  ensureBenignStyle();
  return block;
}

// The compact blocks' buttons lifted into the action row, their bodies in
// one .r-title__keep row after it. The row is hidden while nothing in it
// shows (a status line, the reason form, an exclusion offer), and the
// blocks fill those in on their own time, so an observer keeps it in step.
// The runbook page lifts its Hold and Mark benign the same way.
export function keepRow(blocks) {
  const row = h("div", { class: "r-title__keep" });
  row.hidden = true; // the property, not the attribute alone: a reflected boolean some DOM shims don't sync
  const buttons = [];
  for (const block of blocks.filter(Boolean)) {
    const btn = block.querySelector(".reach-hold__btn, .reach-benign__btn");
    if (btn) {
      const hold = btn.classList.contains("reach-hold__btn");
      btn.className = hold ? "r-btn r-btn--primary r-action-hold reach-hold__btn" : "r-btn r-action-benign reach-benign__btn";
      buttons.push(btn);
    }
    row.appendChild(block);
  }
  const shown = (n) => {
    for (let p = n; p && p !== row; p = p.parentNode) if (p.hidden) return false;
    return true;
  };
  const showing = () => Array.from(row.querySelectorAll(".reach-hold__status, .reach-benign__offer, .reach-benign__form, .reach-hold__after")).some((n) => shown(n) && (n.children.length > 0 || n.textContent.trim() !== ""));
  const sync = () => {
    const hide = !showing();
    if (row.hidden !== hide) row.hidden = hide;
  };
  if (typeof MutationObserver === "function") {
    // Each block is watched, not the row: the row's own hidden flip is this function's.
    const mo = new MutationObserver(sync);
    for (const block of row.children) mo.observe(block, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["hidden"] });
  }
  for (const btn of buttons) btn.addEventListener("click", () => queueMicrotask(sync));
  return { row, buttons };
}

// Where the value came from, for the notebook pin: the last click's
// selection (last-event.js) when it was on this container, else what the
// page knows (the container, the field, the scope Settings holds).
function holdContext({ container, field, value }) {
  const prov = lastEvent.provenance(container) || {};
  const scopeValue = prov.scope || (isSentinel() ? "" : scope.index() || "");
  const search = prov.search && (prov.search.text || prov.search.sid) ? prov.search : null;
  return { field, value, container, platform: PLATFORM, scope: scopeValue || null, event: prov.event || null, search, notebookUrl: "#/notebook" };
}

// The Hold action: the value into the investigation notebook with where
// it came from, and into this tab's held facts (investigation.js), which
// later pages bind. Only this button, Attach and the Holding add form
// write those stores; the page's own value is bound without them
// (facts.carried). Null when the URL names no field or the field is scope.
// `origin` is the alert rule the row came from (runbooks.originOf), for
// the investigation this Hold starts. Not compact: once held the row reads
// "Held · ... · Release" and Release clears the tab fact too, the same row
// as the field page's own action row draws (holdContext, keepRow below).
export function holdAction({ container, field, value, origin = null }) {
  if (!field || value === undefined || value === null || value === "") return null;
  const block = holdBlock({ ...holdContext({ container, field, value }), origin, onHeld: (pin) => investigation.set(pin.field, pin.value), onReleased: (e) => investigation.remove(e.field) });
  if (!block) return null;
  ensureHoldStyle();
  return block;
}

// The Hold of a value page that names no field (a typed value, a search
// hit): a pin needs a key, so the button opens the keep row with one, as
// the Holding rail's Add form does, and holds under that key on the next
// click or Enter. The block carries the Hold row's classes so the title
// block lifts its button the same way.
export function bareHoldAction({ container, value }) {
  if (value === undefined || value === null || value === "") return null;
  const status = h("div", { class: "reach-hold__status" });
  const key = h("input", { class: "reach-input reach-hold__reason", type: "text", placeholder: "key: the field this value is on", "aria-label": "Fact key", autocomplete: "off", spellcheck: "false" });
  const after = h("div", { class: "reach-hold__after" }, key);
  after.hidden = true;
  const btn = h("button", { type: "button", class: "reach-btn reach-btn--primary reach-hold__btn", title: "Put this value in the investigation notebook under a key you name" }, "Hold");
  let busy = false;
  async function submit() {
    const k = key.value.trim();
    if (!k) {
      after.hidden = false;
      key.focus();
      return;
    }
    if (busy) return;
    busy = true;
    btn.disabled = true;
    try {
      const { entry } = await hold({ field: k, value, container, platform: PLATFORM, onHeld: (pin) => investigation.set(pin.field, pin.value) });
      btn.textContent = "Held ✓";
      key.disabled = true;
      status.replaceChildren(`In the notebook as ${k} = ${value}. `, h("a", { href: "#/notebook" }, "open the notebook →"));
      return entry;
    } catch (err) {
      btn.disabled = false;
      status.textContent = String((err && err.message) || err);
      return null;
    } finally {
      busy = false;
    }
  }
  btn.addEventListener("click", submit);
  key.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      submit();
    }
  });
  ensureHoldStyle();
  return h("div", { class: "reach-row reach-hold reach-hold--compact reach-hold--bare" }, h("div", { class: "reach-hold__bar" }, btn), status, after);
}

// The same two as full rows in a section of their own, with the provenance
// line and the reason inputs open: what a page draws under a heading
// rather than in its action row.
export function holdSection({ container, field, value, origin = null }) {
  if (!field || value === undefined || value === null || value === "") return null;
  const block = holdBlock({ ...holdContext({ container, field, value }), origin, onHeld: (pin) => investigation.set(pin.field, pin.value), onReleased: (e) => investigation.remove(e.field) });
  if (!block) return null;
  ensureHoldStyle();
  return h("section", { class: "r-section r-holdrow" }, block);
}

export function benignSection({ catalogue, container, field, value }) {
  if (!field || value === undefined || value === null || value === "") return null;
  const view = catalogue && container ? catalogue.fieldOn(container, field) : null;
  const inject = modules.setting("benign", KEYS.benignInject) === true;
  const block = benignBlock({ ...holdContext({ container, field, value }), samples: view && view.profile ? view.profile.top : null, onInsert: inject ? (req) => bridge.apply(req) : null });
  if (!block) return null;
  ensureBenignStyle();
  return h("section", { class: "r-section r-benignrow" }, block);
}

// The verdict row draws with the popups' classes too: its own stylesheet
// plus the few row and chip rules it uses, mapped onto the app's tokens.
const VERDICT_STYLE_ID = "reach-verdict-style";
const VERDICT_TOKENS = [
  ".reach-verdict{--rc-fg:var(--fg-0);--rc-fg2:var(--fg-1);--rc-bg3:var(--bg-2);--rc-err:var(--hazard-fg);--rc-err-bg:var(--hazard-bg);--rc-ok:var(--trust-confirmed-fg);--rc-ok-bg:var(--trust-confirmed-bg);--rc-warn:var(--trust-asserted-fg);--rc-warn-bg:var(--trust-asserted-bg);margin:0;min-width:0}",
  ".reach-verdict .reach-row__title{font-weight:600;color:var(--rc-fg);margin-bottom:4px}",
  ".reach-verdict .reach-row__feeds{font-size:12px;color:var(--rc-fg2);font-weight:400}",
  ".reach-verdict .reach-row__body{color:var(--rc-fg);margin:0}",
  ".reach-verdict .reach-row__body--muted{color:var(--rc-fg2);font-style:italic}",
  ".reach-verdict .reach-row__body--danger{background:var(--rc-err-bg);border-left:3px solid var(--rc-err);border-radius:2px;padding:6px 10px}",
  ".reach-verdict .reach-chip{display:inline-block;font-size:11px;line-height:18px;font-weight:600;border-radius:9px;padding:0 8px;background:var(--rc-bg3);color:var(--rc-fg);white-space:nowrap}",
  '.reach-verdict .reach-chip[data-basis="confirmed"]{background:var(--rc-ok-bg);color:var(--rc-ok)}',
  '.reach-verdict .reach-chip[data-basis="asserted"]{background:var(--rc-warn-bg);color:var(--rc-warn)}',
  '.reach-verdict .reach-chip[data-basis="danger"]{background:var(--rc-err-bg);color:var(--rc-err)}',
].join("\n");
function ensureVerdictStyle() {
  if (document.getElementById(VERDICT_STYLE_ID)) return;
  document.head.appendChild(h("style", { id: VERDICT_STYLE_ID }, VERDICT_CSS + VERDICT_TOKENS));
}

// The known-good verdict for the value as one field's literal on a Falcon
// process event: the same row the popups draw, over the sibling fields the
// last click's selection carried (last-event.js). Null when no row of this
// container was clicked, or the value is not a hash, signing id or path.
export function verdictSection({ catalogue, container, field, value, event, onTier = null }) {
  if (!catalogue || !container || !field || value === undefined || value === null) return null;
  const fields = event || lastEvent.recall(container);
  if (!fields) return null;
  const block = verdictBlock({ field, value, container, platform: PLATFORM, event: fields, catalogue, view: catalogue.fieldOn(container, field), hold: holdContext({ container, field, value }), onTier, titled: false, appUrl: (hash) => hash });
  if (!block) return null;
  ensureVerdictStyle();
  ensureHoldStyle();
  return block;
}

// The enrichment row draws with the popups' classes too: its own
// stylesheet plus the row, button and link rules it uses, mapped onto the
// app's tokens, the same as the verdict row above.
const ENRICH_STYLE_ID = "reach-enrich-style";
const ENRICH_TOKENS = [
  ".reach-enrich{--rc-fg:var(--fg-0);--rc-fg2:var(--fg-1);--rc-bg:var(--bg-1);--rc-bg3:var(--bg-2);--rc-bg4:var(--bg-3);--rc-line3:var(--control-line);--rc-accent:var(--accent);--rc-accent-fg:var(--accent-fg);--rc-accent-hover:var(--accent);--rc-link:var(--accent);--rc-disabled:var(--fg-2);--rc-disabled-bg:var(--bg-2);--rc-warn-line:var(--trust-asserted);--rc-warn-bg:var(--trust-asserted-bg)}",
  ".reach-enrich .reach-row__title{font-weight:600;color:var(--rc-fg);margin-bottom:4px}",
  ".reach-enrich .reach-row__body{color:var(--rc-fg);margin:0 0 6px}",
  ".reach-enrich .reach-row__body--muted{color:var(--rc-fg2);font-style:italic}",
  ".reach-enrich .reach-row__body--warn{color:var(--rc-fg);background:var(--rc-warn-bg);border-left:3px solid var(--rc-warn-line);border-radius:2px;padding:6px 10px;margin:6px 0}",
  ".reach-enrich .reach-link{display:block;margin-top:6px;color:var(--rc-link);font-size:12px;text-decoration:none}",
  ".reach-enrich .reach-link:hover{color:var(--rc-accent-hover);text-decoration:underline}",
  ".reach-enrich .reach-run-split{display:flex;margin-top:8px}",
  ".reach-enrich .reach-run-btn{width:100%;margin-top:8px;min-height:32px;padding:5px 12px;border-radius:2px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);font:inherit;font-size:14px;font-weight:600;cursor:pointer}",
  ".reach-enrich .reach-run-split .reach-run-btn{margin-top:0;width:auto;flex:1;border-radius:2px 0 0 2px}",
  ".reach-enrich .reach-run-btn:hover{background:var(--rc-bg3)}",
  ".reach-enrich .reach-run-btn:active{background:var(--rc-bg4)}",
  ".reach-enrich .reach-run-btn:disabled{background:var(--rc-disabled-bg);border-color:var(--rc-disabled-bg);color:var(--rc-disabled);cursor:default}",
  ".reach-enrich .reach-run-btn--live{border-color:var(--rc-accent);background:var(--rc-accent);color:var(--rc-accent-fg)}",
  ".reach-enrich .reach-run-btn--live:hover{border-color:var(--rc-accent-hover);background:var(--rc-accent-hover)}",
  ".reach-enrich .reach-run-split .reach-run-btn--tab{flex:0 0 auto;border-left:0;border-radius:0 2px 2px 0;text-decoration:none;text-align:center;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;color:var(--rc-fg);padding:5px 14px;font-weight:600}",
  ".reach-enrich .reach-run-split .reach-run-btn--tab:hover{background:var(--rc-bg3);text-decoration:none}",
  ".reach-enrich .reach-spinner{display:inline-block;width:11px;height:11px;margin-right:6px;vertical-align:-1px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:reach-spin .6s linear infinite;opacity:.85}",
  "@keyframes reach-spin{to{transform:rotate(360deg)}}",
].join("\n");
function ensureEnrichStyle() {
  if (document.getElementById(ENRICH_STYLE_ID)) return;
  document.head.appendChild(h("style", { id: ENRICH_STYLE_ID }, ENRICH_CSS + ENRICH_TOKENS));
}

// The enrichment row for the value as one field's literal: CISA KEV on a
// CVE (a bundled read, no network), VirusTotal on a public IP, hostname or
// file hash (the user's own key, only on an explicit click). Null off
// every kind the registry answers. Drawn immediately with VirusTotal
// (and any other fetch/stream source) assumed off, so a bundle source's
// row never waits on the background worker; if VirusTotal turns out to be
// set up, the row is redrawn in place once that answer is back, the only
// part of this section the background worker's round trip can change.
export function enrichSection({ value, fieldName, container = null, openSettings = null }) {
  if (value === undefined || value === null || value === "") return null;
  if (!enrich.kindsFor(value, { fieldName }).length && !enrich.refusalFor(value, { fieldName })) return null;
  // Only the sources whose module is on may offer (an off module's row is
  // absent, never greyed); an on-but-unconfigured source's row links the
  // settings surface on that module's head.
  const sources = modules.sources();
  if (!sources.length) return null;
  ensureEnrichStyle();
  ensureHoldStyle();
  const settingsUrl = (source) => {
    const owner = modules.sourceOwner(source.id);
    const href = optionsUrl(PLATFORM, modules.anchor(owner ? owner.id : ""));
    return openSettings ? { href, onClick: (e) => { e.preventDefault(); openSettings(owner ? owner.id : null); } } : href;
  };
  const hold = fieldName ? holdContext({ container, field: fieldName, value }) : null;
  const draw = (enabledIds) => enrichBlock({ value, offers: enrich.offersFor(value, { fieldName, enabledIds, sources }), ask, settingsUrl, hold });
  const first = draw([]);
  if (!first) return null;
  const section = h("div", { class: "r-enrich" }, first);
  // Every fetch-mode source gated behind Settings (VirusTotal, CIRCL, EPSS,
  // the self-hosted relay), asked once via enrich.enabledIds() so this
  // section lights up exactly the same set the in-page popups do.
  enrich.enabledIds(ask).then((enabledIds) => {
    if (enabledIds.length) section.replaceChildren(draw(enabledIds));
  });
  return section;
}

// The carriers ledger (Splunk, FDR): the fields that carry this value read
// as each kind the shape allows, one band, each row tracing the observable
// back to the process that produced it. Pure: { specs, rows } for the
// candidates; the drawer's fill lives in render.
export function carriers({ fields, value, candidates }) {
  const specs = new Map();
  const rows = [];
  const ambiguous = candidates.length > 1;
  for (const cand of candidates) {
    const role = KIND_ROLE[cand.kind];
    const seeds = (cand.fields || []).filter((n) => fields.field(n));
    // Unobserved fields are not offered. The `hash` role spans every digest
    // algorithm, so hash carriers are restricted to fields named for the kind.
    const algo = { sha256: /sha256|sha-256/i, sha1: /sha1(?!\d)|sha-1(?!\d)/i, md5: /md5/i }[cand.kind] || null;
    const nameFilter = PATH_NAMES[cand.kind] || null;
    const pool = role ? fields.fieldsWithRole(role) : cand.kind === "registry" ? fields.searchIndex().fields : [];
    const others = pool.filter((n) => !seeds.includes(n) && fields.field(n).observed
          && (!nameFilter || nameFilter(n))
          && (!algo || algo.test(n) || algo.test((fields.field(n).meaning || {}).data_format || "")));
    const reading = ambiguous ? `as ${cand.label} · ` : "";

    if (cand.kind === "aid") {
      const e = fields.edge("e_aid_to_aidmaster");
      if (e) {
        specs.set("v-aidmaster", { pivot: { kind: "edge", edge: e }, params: { value }, title: e.target_label, subtitle: "aid → aidmaster", errorParams: ["value"] });
        rows.push({ id: "v-aidmaster", cells: [{ mono: "aidmaster" }, { text: `${reading}${e.target_label}`, wrap: true }, chip({ kind: "trust", value: "confirmed" })] });
      }
      specs.set("v-proctable", {
        pivot: { kind: "process_table" },
        params: { aid: value },
        title: "Every process on this host in the window",
        subtitle: "aid → ProcessRollup2 / SyntheticProcessRollup2",
        errorParams: ["aid", "earliest", "latest"],
      });
      rows.push({
        id: "v-proctable",
        cells: [{ mono: "process table" }, { text: `${reading}Every process the sensor recorded on this host for a window. Needs earliest and latest.`, wrap: true }, chip({ kind: "trust", value: "confirmed" })],
      });
    }

    for (const name of [...seeds, ...others].slice(0, MAX_ROWS)) {
      const rec = fields.field(name);
      const id = `v-${cand.kind}-${name}`;
      // External-only fields: the sensor-sourcetype trace would return nothing,
      // so offer an event sample on the external sourcetype instead.
      const externalOnly = rec.events.length > 0
        && rec.events.every((ev) => (fields.event(ev) || {}).sourcetype === "crowdstrike:events:external");
      if (externalOnly) {
        specs.set(id, {
          pivot: { kind: "event_sample" },
          params: { event: rec.events[0], sourcetype: "crowdstrike:events:external", value, field: name },
          title: `${name} on detection summary events`,
          subtitle: "external sourcetype: not traceable to a sensor process from here",
          hazards: [{ level: "note", text: `${name} rides only on ${rec.events.join(", ")} (crowdstrike:events:external). The process trace searches sensor telemetry and would return nothing. Use the detection workflow to cross to the sensor side by hash or host.` }],
          errorParams: ["event", "earliest"],
        });
        rows.push({
          id,
          cells: [
            fieldLink(name),
            { text: `${reading}detection summary events only (external sourcetype): see the events, then cross by hash or host via the detection workflow`, wrap: true },
            chip({ kind: "trust", value: "inferred", text: "not traceable here" }),
          ],
        });
        continue;
      }
      specs.set(id, {
        pivot: { kind: "trace" },
        params: { field: name, value },
        title: `The process behind ${name}=${value}`,
        subtitle: "cs_trace_process: observable → the process that produced it",
        errorParams: ["field", "value", "earliest", "aid"],
      });
      rows.push({
        id,
        cells: [
          fieldLink(name),
          {
            text: `${reading}${rec.layer === "cim" ? "L3 CIM" : rec.layer === "ta_derived" ? "L2 TA" : "L1 raw"} · ${rec.event_count} event${rec.event_count === 1 ? "" : "s"} · ${
              (rec.route && rec.route.summary) || "no route"
            }`,
            wrap: true,
          },
          seeds.includes(name) ? chip({ kind: "trust", value: "confirmed", text: "carries this" }) : chip({ kind: "trust", value: "inferred", text: `role ${role}` }),
        ],
      });
    }
  }
  return { specs, rows };
}

// The tier chip for the title block: the corpus's word, its hue by tier.
function tierChip(m) {
  if (m.tier === "impersonation") return chip({ kind: "hazard", text: "impersonation" });
  if (m.tier === "normal" || m.tier === "consistent") return chip({ kind: "trust", value: "confirmed", text: m.tier });
  return chip({ kind: "trust", value: "inferred", text: m.tier });
}

// The field page's route for this value, with the sourcetype when known.
function fieldHref(name, st, value) {
  const q = [st ? `st=${encodeURIComponent(st)}` : null, `value=${encodeURIComponent(value)}`].filter(Boolean).join("&");
  return `#/f/${encodeURIComponent(name)}?${q}`;
}

function section(id, n, ...kids) {
  return h("section", { class: "r-section", dataset: { band: id } }, headingNode(BAND_HEADING[id], n), ...kids);
}

// The section ids the page draws for a given set of blocks: the popups'
// own walk (bands/band.js plan) over SECTIONS, so the page and the popup
// agree on the bands for the same click by construction. Pure, so the
// order can be held without a document.
export function plan(bands, blocks) {
  return bandPlan(bands, (id) => modules.SECTIONS.includes(id) && Boolean(blocks[id]));
}

export function render(ctx) {
  const { fields } = ctx;
  const value = String(ctx.params.value || "");
  const st = ctx.params.st || null;
  const name = ctx.params.name || null;
  const recordType = ctx.params.on || null;
  const idx = fields.searchIndex();
  const c = classify(value, idx);
  const el = h("div", { class: "r-view r-view--value" });
  const bands = modules.bands(PLATFORM);
  const has = (id) => bands.includes(id);
  const catalogue = ctx.catalogue;

  // A catalogue name typed where a value goes: the title block alone, with
  // the way to the name's own page. Only when the route itself names no
  // field: classify() has no route to consult, so a route that already
  // carries st and name (the field page's own arrow link) keeps the value
  // page and reads the literal as that field's value, not a stray name.
  if (c.kind === "name" && !(st && name)) {
    const first = c.candidates[0];
    el.appendChild(
      titleBlock({
        kind: "value",
        h1: value,
        chips: [chip({ kind: "trust", value: "confirmed", text: "a name, not a value" })],
        scope: ["a catalogue name, not a value"],
        actions: [
          first
            ? h("a", { class: "r-btn", href: `#/${first.kind === "field" ? "f" : "e"}/${encodeURIComponent(first.name)}` }, `Open ${first.name}`)
            : h("a", { class: "r-btn", href: `#/unknown/${encodeURIComponent(value)}` }, "Nearest names"),
        ],
      }),
    );
    return el;
  }

  const view = catalogue && st && name ? catalogue.fieldOn(st, name) : null;
  // The shape's reading holds when the field agrees with it (a hash in a
  // hash field, a small integer in a PID field); a decode value in an enum
  // field is that field's kind, not the shape's, and carries nothing.
  const role = view && view.taxonomy ? view.taxonomy.role : null;
  const candidates = role ? c.candidates.filter((cand) => KIND_ROLE[cand.kind] === role) : c.candidates;
  const ambiguous = candidates.length > 1;
  const kindLabel = candidates.map((x) => x.label).join(" or ") || (role ? role.replace(/_/g, " ") : "unrecognised");
  const everywhereRows = catalogue && name ? catalogue.fieldEverywhere(name).filter((r) => r.sourcetype !== st) : [];

  // ---- the blocks, each from the component the popups draw --------------
  let active = null; // "ledger" | "pack": whose selection the drawer shows
  let packHandler = null;
  const blocks = {};
  blocks.hold = has("hold") ? (name ? holdAction({ container: st, field: name, value }) : bareHoldAction({ container: st, value })) : null;
  blocks.benign = has("benign") ? benignAction({ catalogue, container: st, field: name, value }) : null;
  // The value's own line, and the kind's reading (an OS PID is recycled, an aid is per install) under it.
  const literal = has("value") ? valueLine({ catalogue, container: st, field: name, value }) : null;
  const kindNote = KIND_NOTE[candidates[0] && candidates[0].kind] ? h("p", { class: "r-secondary r-value__kind" }, KIND_NOTE[candidates[0].kind]) : null;
  blocks.value = literal || kindNote ? h("div", { class: "r-value" }, literal, kindNote) : null;
  blocks.meaning = has("meaning") && name && st ? meaningBlock({ view, sourcetype: st, name, catalogue, appUrl: null, value, editable: false, fieldHref: fieldHref(name, st, value) }) : null;
  blocks.everywhere = has("everywhere") ? everywhereBlock({ rows: everywhereRows, name, appUrl: (hash) => hash, titled: false, newTab: false }) : null;
  blocks.verdict = has("verdict") ? verdictSection({ catalogue, container: st, field: name, value, onTier: (m) => onTier(m) }) : null;
  blocks.enrich = has("enrich") ? enrichSection({ value, fieldName: name || "", container: st, openSettings: ctx.openSettings }) : null;
  blocks.pattern = has("pattern") ? patternSection({ catalogue, container: st, field: name, value }) : null;

  // Pivots: the pack's edges from this field, then on Splunk the carriers
  // ledger. N counts every row a click can take to the drawer.
  const edges = has("pivots") && catalogue && st && name ? catalogue.edgesFrom(st, name) : [];
  const carried = name ? facts.carried(name, value) : {};
  const packEl = edges.length
    ? packPivots({
        ctx: { ...ctx, setDrawerParamHandler: (fn) => { packHandler = fn; } },
        sourcetype: st,
        name,
        edges,
        titled: false,
        carried,
        setSel: (id) => {
          active = "pack";
          ctx.setUrl("value", { ...ctx.params, value, sel: id });
        },
      })
    : null;
  const led = has("pivots") && !isSentinel() ? carriers({ fields, value, candidates }) : { specs: new Map(), rows: [] };
  // The FDR bundle's first move off this record type, the row the Splunk
  // popup offers for the same click, ahead of the carriers.
  const eventRec = has("pivots") && !isSentinel() && recordType && name && fields.field(name) ? fields.event(recordType) : null;
  const fdrRow = eventRec ? edgeRowsFor(fields.edges(), eventRec, name)[0] : null;
  if (fdrRow) {
    const e = fdrRow.edge;
    const id = `v-fdr-${e.id}`;
    const via = `${e.src} → ${e.dst || "lookup"}`;
    led.specs.set(id, {
      pivot: pivotForEdgeRow(fdrRow, name),
      params: { value, ...baseParamsForRow(fdrRow, name, recordType) },
      title: e.target_label,
      subtitle: fdrRow.viaSelf ? `${via} from ${name} on ${recordType}` : `${name} → ${via} on ${recordType}`,
      errorParams: ["value", "aid", "earliest", "latest"],
    });
    led.rows.unshift({
      id,
      hazard: Boolean(e.hazard) || e.cardinality === "unsafe",
      cells: [h("span", null, e.target_label), { text: `${via} on ${recordType}`, wrap: true }, chip({ kind: "trust", value: e.basis === "confirmed_ta" ? "confirmed" : e.basis === "validated" ? "validated" : "asserted", text: e.basis === "confirmed_ta" ? "confirmed" : e.basis })],
    });
  }
  const ledgerEl = led.rows.length
    ? ledger({
        selectedId: ctx.params.sel || null,
        caption: heading("pivots", led.rows.length),
        bands: [
          {
            id: "carriers",
            kind: "one-join",
            title: heading("one-join-away"),
            note: `Fields that carry this value read as ${kindLabel}. Select one and the drawer traces that observable back to the process that produced it.`,
            columns: ["field", "what it is", "basis"],
            rows: led.rows,
            collapsible: true,
            closed: true,
          },
        ],
      })
    : null;
  const pivotCount = edges.length + led.rows.length;
  blocks.pivots = pivotCount ? h("div", { class: "r-pivots" }, packEl, ledgerEl, isSentinel() ? h("p", { class: "r-secondary r-pivots__platform" }, SENTINEL_PIVOTS_LINE_PAGE) : null) : null;
  const workflowRows = has("workflows") && st && name ? workflows.forField(st, name) : [];
  blocks.workflows = workflowRows.length ? workflowsBlock({ rows: workflowRows, value, appUrl: (hash) => hash, href: workflows.href, sourcetype: st, titled: false, newTab: false }) : null;

  // ---- the title block ---------------------------------------------------
  const chips = candidates.length
    ? candidates.map((cand) => chip({ kind: "trust", value: ambiguous ? "inferred" : "confirmed", text: cand.label }))
    : [chip({ kind: "trust", value: role ? "confirmed" : "inferred", text: kindLabel })];
  const copyBtn = h(
    "button",
    { type: "button", class: "r-chip r-chip--action r-title__copy", title: value, "aria-label": "Copy the value", onClick: (e) => copyText(value, e.currentTarget, "copied") },
    "copy",
  );
  chips.push(copyBtn);
  const scopeItems = [];
  if (name) scopeItems.push(h("a", { href: fieldHref(name, st, value), class: "r-idlink" }, h("code", null, name)));
  if (st) scopeItems.push(h("span", null, "on ", h("a", { href: `#/st/${encodeURIComponent(st)}`, class: "r-idlink" }, st)));
  if (recordType) scopeItems.push(modules.routeStatus("event", PLATFORM) === "on" ? h("a", { href: `#/e/${encodeURIComponent(recordType)}`, class: "r-idlink" }, recordType) : h("span", null, recordType));
  if (everywhereRows.length && blocks.everywhere) {
    scopeItems.push(
      h("a", { href: "#", class: "r-scope__more", onClick: (e) => {
        e.preventDefault();
        const fold = el.querySelector('[data-band="everywhere"] details');
        if (fold) {
          fold.open = true;
          fold.scrollIntoView({ block: "start" });
        }
      } }, `also on ${everywhereRows.length} more`),
    );
  }
  if (!name && !st) scopeItems.push(c.kind === "empty" || !c.candidates.length ? "unrecognised value shape: try it as a name in the search box" : `bare value, no ${TERMS.field} named`);

  // The callout slot: one hazard-class callout by priority (the danger
  // verdict banner replaces Ambiguous once the corpus answers), and beside
  // it the Sentinel platform note when there are no pivots to carry the value.
  let callout0 = ambiguous
    ? callout({
        kind: "caution",
        label: "Ambiguous",
        body: "32 hexadecimal characters is an MD5 file hash and it is also the shape of a CrowdStrike aid. Nothing in the value itself separates them. Both readings are below. Pick the one that matches where you got it: a hash comes off a file, an aid comes off a host.",
      })
    : null;
  const platformNote = isSentinel() && name && st && !blocks.pivots ? callout({ kind: "note", label: "Sentinel", body: SENTINEL_NO_PIVOTS_NOTE }) : null;
  const calloutSlot = callout0 || platformNote ? h("div", null, callout0, platformNote) : null;

  // Two lines of a 24 px name at 288 px hold about 40 characters; a longer
  // id middle-ellipsizes with the full value in title and on the copy chip.
  // The action row holds the two buttons; what each opens (the reason
  // and the expiry, the status, the exclusion offer) is the keep row under
  // it, a sibling of the action row, shown once it has something to show.
  const keep = keepRow([blocks.hold, blocks.benign]);
  const title = titleBlock({
    kind: "value",
    h1: value.length > H1_CHARS ? h("span", { title: value }, midEllipsis(value, H1_CHARS)) : value,
    chips,
    scope: scopeItems,
    callout: calloutSlot,
    actions: keep.buttons,
  });
  if (keep.buttons.length) title.appendChild(keep.row);
  el.appendChild(title);

  function onTier(m) {
    const chipRow = title.querySelector(".r-title__chips");
    const old = title.querySelector(".r-title__tier");
    const next = tierChip(m);
    next.classList.add("r-title__tier");
    if (old) old.replaceWith(next);
    else if (chipRow) chipRow.insertBefore(next, copyBtn);
    if (m.tier !== "impersonation") return;
    const banner = callout({ kind: "hazard", label: "Impersonation", body: [m.headline, m.detail ? ` ${m.detail}` : ""].join("") });
    callout0 = banner;
    let slot = title.querySelector(".r-title__callout");
    if (!slot) {
      slot = h("div", { class: "r-title__callout" }, h("div", null, banner, platformNote));
      const actions = title.querySelector(".r-actions");
      if (actions) actions.before(slot);
      else title.appendChild(slot);
      return;
    }
    const inner = slot.firstElementChild;
    if (inner) inner.replaceChildren(banner, platformNote);
  }

  // ---- the sections, in SECTIONS order ---------------------------------
  for (const id of plan(bands, blocks)) {
    if (id === "meaning") {
      el.appendChild(section("meaning", undefined, blocks.meaning, blocks.value));
      continue;
    }
    if (id === "everywhere") {
      el.appendChild(h("section", { class: "r-section", dataset: { band: id } }, h("details", { class: "r-fold" }, h("summary", { class: "r-fold__summary" }, headingNode("other-sourcetypes", everywhereRows.length)), blocks.everywhere)));
      continue;
    }
    if (id === "pivots") {
      el.appendChild(section("pivots", pivotCount, blocks.pivots));
      continue;
    }
    el.appendChild(section(id, undefined, blocks[id]));
  }

  // ---- the drawer ---------------------------------------------------------
  const userParams = {};
  let currentId = null;

  function fill(rowId, rebuild) {
    const spec = led.specs.get(rowId);
    if (!spec) return;
    currentId = rowId;
    active = "ledger";
    // The index is scope, resolved for the sourcetype the generator picks
    // for this pivot: one pass to learn it, one more with the index bound.
    const base = { ...facts.bound(), ...carried, ...spec.params, ...userParams };
    fillFrom(
      ctx.drawer,
      {
        title: spec.title,
        subtitle: spec.subtitle,
        params: (out) =>
          out.missing.map((n) => ({
            name: n,
            label: n,
            value: userParams[n] ?? "",
            placeholder: n === "earliest" ? "-24h" : n === "latest" ? "now" : "",
            hint: n === "aid" ? "Optional here, but orders of magnitude faster." : undefined,
            required: n !== "aid",
          })),
        errorParams: () => (spec.errorParams || []).map((n) => ({ name: n, label: n, value: userParams[n] ?? "", required: true })),
        notes: (out) => scope.notes(out.sourcetype),
      },
      () => {
        let params = base;
        let out = fdr.generate(spec.pivot, base);
        params = scope.bind(base, out.sourcetype);
        if (params !== base) out = fdr.generate(spec.pivot, params);
        let macro = "";
        try {
          macro = fdr.generate(spec.pivot, params, { form: "macro" }).spl;
        } catch {
          macro = "";
        }
        return { ...out, macro };
      },
      rebuild,
    );
  }

  // One drawer, two lists: a parameter edit refills whichever row was
  // selected last.
  ctx.setDrawerParamHandler((n, v) => {
    if (active === "pack") {
      if (packHandler) packHandler(n, v);
      return;
    }
    userParams[n] = v;
    if (currentId) fill(currentId, false);
  });
  // A pivot copied from a held value is an edge in the notebook; the
  // ledger's row title names it. Nothing is recorded for a value not held.
  ctx.setDrawerCopyHandler((text) => {
    const spec = active === "ledger" && currentId ? led.specs.get(currentId) : null;
    if (!spec || !name) return;
    recordPivot({ field: name, value, container: st, platform: PLATFORM, query: text, name: spec.title }).catch(() => {});
  });
  // An index chosen or set under Settings lands in the open pivot.
  scope.follow(el, () => {
    if (active === "ledger" && currentId) fill(currentId, false);
  });

  if (ledgerEl) {
    ledgerEl.addEventListener("select", (e) => {
      ctx.setUrl("value", { ...ctx.params, value, sel: e.detail.rowId });
      fill(e.detail.rowId, true);
    });
  }

  el.selectRow = (id) => {
    if (led.specs.has(id) && ledgerEl) {
      ledgerEl.select(id);
      fill(id, true);
      return;
    }
    if (packEl && edges.some((e) => e.id === id)) packEl.selectRow(id);
  };
  el.afterMount = () => {
    if (ctx.params.sel) el.selectRow(ctx.params.sel);
  };

  return el;
}

export default { render, plan };
