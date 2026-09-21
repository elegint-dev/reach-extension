// The notebook rows: Hold, what attaches to a held value, and Known benign
// with the exclusion the marked values make. Only Hold, Attach and Mark
// benign write; a click anywhere else here records nothing.
//
//   HOLD_CSS, BENIGN_CSS              the rows' stylesheets, for the app's value page (POPUP_CSS carries them too)
//   pinFrom({ field, value, container, platform, scope, event, search, reason }) → pin | null   (pure)
//       the notebook pin for a clicked value with its provenance; null for a scope
//       key (the index, the workspace), which is never held
//   eventSummary({ container, discriminator, time }) → string   (pure)
//   heldPin({ field, value, container }) → entry | null
//       the current investigation's pin for the same value on the same field
//   hold({ field, value, container, platform, scope, event, search, reason, origin, onHeld }) → Promise<{ pin, entry }>
//       the action itself: the pin recorded in the current investigation
//       (started when there is none), then onHeld(pin, entry), where the app
//       sets its held store, which a content script cannot reach; search is
//       read here when it is a function (the Splunk editor bridge)
//   holdBlock({ ...the same, notebookUrl, compact }) → Element | null
//       the Hold row: the button, a reason beside it, and where the pin went;
//       the search is read on the click, never at render
//   recordPivot({ field, value, container, platform, query, language, name, found }) → Promise<entry | null>
//       a pivot edge from the held pin when the value is held, nothing otherwise
//   noteSearch({ text, platform, source, origin, container, field, value, name, ran, sid }) → Promise<entry | null>
//       the search-history entry for a query handed on (app/lib/searches.js), held or not
//   attachButton({ kind, source, summary, result, verdict, ...pin fields }) → Element
//       "Attach to notebook" under an enrichment or verdict row; records the
//       pin first when the value is not held yet
//   benignBlock({ ...pin fields, reason?, onInsert?, samples?, notebookUrl, compact }) → Element | null
//       the Known benign row: Mark benign with a reason and an expiry, the
//       mark noted on the held pin when there is one, and under it the
//       exclusion the marked values on this field make (benign.exclusion),
//       inserted through onInsert (editor-bridge apply, either editor) or copied, on a click
//   exclusionOffer({ field, container, platform, onInsert?, samples? }) → Element
//       that offer alone; el.redraw() after the set changes
//   exclusionStrip({ container, fields, platform, onInsert?, query?, onClose? }) → Element | null
//       one line for the focused editor: per field with marked values on the
//       container, the count and an Insert (or Copy); a field whose exclusion
//       the query already holds says applied; null with nothing to offer
//
// DOM module (uses h.js). Never fetches; nothing leaves the browser.

import { h, replace } from "../../components/h.js";
import { PLATFORM } from "../platform.js";
import * as notebook from "../notebook.js";
import * as benign from "../benign.js";
import * as searches from "../searches.js";
import { displayTitle } from "../notebook-md.js";
import { isScopeKey } from "../scope.js";
import { when } from "../when.js";
import { copyText } from "../runtime.js";

// The Hold row and the attach buttons, written against the --rc-* palette only
// so the app's value page can carry them with a variable map instead of POPUP_CSS.
export const HOLD_CSS = `
.reach-hold__bar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;min-width:0}
.reach-hold__bar[hidden]{display:none}
.reach-hold__reason{flex:1 1 140px;min-width:0;width:auto}
.reach-hold__status{font-size:12px;color:var(--rc-fg2);margin-top:4px;overflow-wrap:anywhere}
.reach-hold__status:empty{display:none}
.reach-hold__status a{color:var(--rc-link);text-decoration:none}
.reach-hold__status a:hover{color:var(--rc-accent-hover);text-decoration:underline}
.reach-hold__where{font-size:11px;color:var(--rc-fg2);margin-top:2px;overflow-wrap:anywhere}
.reach-attach{margin-top:6px}
.reach-attach__note{font-size:12px;color:var(--rc-fg2);margin-left:6px}
.reach-attach__note a{color:var(--rc-link);text-decoration:none}
`;

// The Known benign row and the editor strip, on the same palette.
export const BENIGN_CSS = `
.reach-benign__expiry{flex:0 0 auto;width:auto}
.reach-benign__offer{margin-top:8px;font-size:12px;color:var(--rc-fg2)}
.reach-benign__offer:empty{display:none}
.reach-benign__offer code{display:block;margin:4px 0;white-space:pre-wrap;word-break:break-all}
.reach-benign__why{font-size:12px;color:var(--rc-fg2);overflow-wrap:anywhere}
.reach-benign__bar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:4px}
.reach-benign__form[hidden]{display:none}
.reach-benign__alt{margin-top:6px}
.reach-benign__line{margin-right:6px}
.reach-benign-strip{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:6px 16px;border-top:0;border-bottom:1px solid var(--rc-line);min-width:0;width:auto;max-width:none;max-height:none;overflow:visible;font-size:12px}
.reach-benign-strip__item{display:inline-flex;gap:6px;align-items:center}
.reach-benign-strip__close{margin-left:auto;background:none;border:0;color:var(--rc-fg2);cursor:pointer;font:inherit;font-size:14px;line-height:1}
`;

// ---------------------------------------------------------------------------
// The notebook: Hold, and what attaches to a held value
//
// A clicked value becomes a thread in the investigation notebook
// (app/lib/notebook.js) when the analyst presses Hold: the pin carries where
// it was seen (platform, container, column, scope, the event, the search)
// and the reason typed beside the button. The in-page popups and the app's
// value page draw the same row. The app's Hold also puts the value in the
// tab's held facts (investigation.js); a content script cannot reach that
// store, so from the page the notebook is the record. A pivot taken from a held
// value is an edge from its pin; an enrichment result or a verdict attaches
// to it.

function clean(v, max = 4000) {
  const s = String(v ?? "").trim();
  return s.length > max ? s.slice(0, max) : s;
}

export function pinFrom({ field, value, container = null, platform = PLATFORM, scope = null, event = null, search = null, reason = "", at = undefined } = {}) {
  const f = clean(field, 500);
  const v = clean(value);
  if (!f || !v || isScopeKey(f)) return null;
  const from = { platform: platform === "sentinel" ? "sentinel" : "splunk", column: f };
  if (clean(container, 500)) from.container = clean(container, 500);
  if (clean(scope, 500)) from.scope = clean(scope, 500);
  if (event && typeof event === "object") {
    const ev = {};
    if (clean(event.id, 500)) ev.id = clean(event.id, 500);
    const t = typeof event.time === "string" ? Date.parse(event.time) : event.time;
    if (typeof t === "number" && Number.isFinite(t)) ev.time = t;
    if (clean(event.summary, 2000)) ev.summary = clean(event.summary, 2000);
    if (Object.keys(ev).length) from.event = ev;
  }
  if (search && typeof search === "object") {
    const sr = {};
    if (clean(search.text)) sr.text = clean(search.text);
    if (clean(search.sid, 200)) sr.sid = clean(search.sid, 200);
    if (Object.keys(sr).length) from.search = sr;
  }
  const pin = { field: f, value: v, from };
  if (clean(reason, 2000)) pin.reason = clean(reason, 2000);
  if (typeof at === "number") pin.at = at;
  return pin;
}

// The event of a click, in the words the pin keeps: the container and its
// record type, and the row's time when the page shows one.
export function eventSummary({ container, discriminator, time } = {}) {
  const bits = [];
  if (container) bits.push(`${container}${discriminator ? ` · ${discriminator}` : ""} event`);
  else if (discriminator) bits.push(`${discriminator} event`);
  // time is the row's own rendered text, or an ISO instant when the host
  // page carries one (app/lib/context.js rowEvent); when() reads either,
  // and its own text stands when time is neither (a host page that shows
  // no parseable time at all).
  if (time) bits.push(`at ${when(time) || clean(time, 80)}`);
  return bits.join(" ");
}

function sameKey(a, b) {
  return String(a ?? "").trim().toLowerCase() === String(b ?? "").trim().toLowerCase();
}

export function heldPin({ field, value, container = null } = {}) {
  const inv = notebook.current();
  if (!inv) return null;
  const v = clean(value);
  const hits = inv.entries.filter((e) => e.kind === "pin" && e.value === v && sameKey(e.field || (e.from && e.from.column), field));
  if (!hits.length) return null;
  return (container && hits.find((e) => e.from && sameKey(e.from.container, container))) || hits[hits.length - 1];
}

function notebookLink(notebookUrl, label = "open the notebook →") {
  return notebookUrl ? h("a", { href: notebookUrl, target: notebookUrl.startsWith("#") ? null : "_blank", rel: "noopener" }, label) : null;
}

// `origin` is the alert rule the row came from (runbooks.originOf); it
// lands on the investigation only when this Hold is the one that starts it.
export async function hold({ field, value, container = null, platform = PLATFORM, scope = null, event = null, search = null, reason = "", origin = null, onHeld = null } = {}) {
  const s = typeof search === "function" ? await search() : search;
  const pin = pinFrom({ field, value, container, platform, scope, event, search: s, reason });
  if (!pin) throw new Error(`${field} is scope, not a value to hold.`);
  await notebook.load();
  const entry = await notebook.record(pin, { origin });
  if (onHeld) {
    try {
      onHeld(pin, entry);
    } catch {
      /* the held store is the app's concern; the pin is recorded */
    }
  }
  return { pin, entry };
}

// `compact` is the title block's action row (the value page): the bar is
// the button alone, the reason input comes under the row once the value
// is held and writes onto the pin, and the provenance line is left to the
// scope line above.
export function holdBlock({ field, value, container = null, platform = PLATFORM, scope = null, event = null, search = null, origin = null, onHeld = null, onReleased = null, notebookUrl = null, compact = false } = {}) {
  const probe = pinFrom({ field, value, container, platform, scope, event });
  if (!probe) return null;
  const status = h("div", { class: "reach-hold__status" });
  const reason = h("input", { class: "reach-input reach-hold__reason", type: "text", placeholder: compact ? "add a reason (optional)" : "why you are holding it (optional)", "aria-label": "Reason", autocomplete: "off", spellcheck: "false" });
  const btn = h("button", { type: "button", class: "reach-btn reach-btn--primary reach-hold__btn", title: "Put this value in the investigation notebook, with where it came from" }, "Hold");
  const w = platform === "sentinel" ? { container: "table", scope: "workspace" } : { container: "sourcetype", scope: "index" };
  const whereBits = [container ? `${w.container} ${container}` : `${w.container} unknown`, scope ? `${w.scope} ${scope}` : null, event && event.summary ? event.summary : null].filter(Boolean);
  const where = compact ? null : h("div", { class: "reach-hold__where" }, `Provenance: ${whereBits.join(" · ")}${search === null ? "; search: unavailable here" : ""}`);
  const after = compact ? h("div", { class: "reach-hold__after", hidden: true }, reason) : null;
  const root = h("div", { class: `reach-row reach-hold${compact ? " reach-hold--compact" : ""}` }, h("div", { class: "reach-hold__bar" }, btn, compact ? null : reason), where, status, after);

  const showHeld = (entry) => {
    const inv = notebook.current() || (entry && notebook.list().find((i) => i.entries.some((e) => e.id === entry.id)));
    btn.disabled = true;
    const invTitle = inv ? displayTitle(inv) : "";
    btn.textContent = compact && inv ? `Held · in ${invTitle.length > 20 ? `${invTitle.slice(0, 19)}…` : invTitle}` : "Held ✓";
    if (compact && inv) btn.title = invTitle;
    if (compact && entry) {
      // The reason is written onto the pin as it is typed.
      after.hidden = false;
      reason.value = entry.reason || "";
      const save = () => notebook.update(entry.id, { reason: reason.value.trim() }).catch(() => {});
      reason.addEventListener("change", save);
      status.replaceChildren(notebookLink(notebookUrl, inv ? `${displayTitle(inv)} →` : "open the notebook →"));
      return;
    }
    reason.hidden = true;
    const rel = h("button", { type: "button", class: "reach-mini reach-hold__release", title: "Take it out of the investigation notebook" }, "Release");
    rel.addEventListener("click", async () => {
      rel.disabled = true;
      try {
        await notebook.removeEntry(entry.id);
        if (onReleased) {
          try {
            onReleased(entry);
          } catch {
            /* the release stands without the caller's own bookkeeping */
          }
        }
        btn.disabled = false;
        btn.textContent = "Hold";
        reason.hidden = false;
        reason.value = "";
        status.replaceChildren();
      } catch (err) {
        rel.disabled = false;
        status.textContent = `Not released: ${err && err.message ? err.message : String(err)}`;
      }
    });
    const middle = entry.reason || when(entry.at) || "";
    status.replaceChildren(`Held${middle ? ` · ${middle}` : ""} · `, rel);
  };

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Holding…";
    try {
      const { entry } = await hold({ field, value, container, platform, scope, event, search, reason: reason.value, origin, onHeld });
      showHeld(entry);
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Hold";
      status.textContent = `Not held: ${err && err.message ? err.message : String(err)}`;
    }
  });
  reason.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      btn.click();
    }
  });

  notebook
    .load()
    .then(() => {
      const had = heldPin({ field, value, container });
      if (had && btn.textContent === "Hold") showHeld(had);
    })
    .catch(() => {});
  return root;
}

// The search history's entry for a query handed on from a popup or a
// band: written held or not, never throws, never starts an investigation.
export function noteSearch(input) {
  return searches.record(input).catch(() => null);
}

// An edge from the held pin. The same pivot taken twice (same origin, same
// text) is one entry.
export async function recordPivot({ field, value, container = null, platform = PLATFORM, query, language = null, name = null, found = null } = {}) {
  const text = clean(query);
  if (!text) return null;
  await notebook.load();
  const pin = heldPin({ field, value, container });
  if (!pin) return null;
  const inv = notebook.current();
  const dup = inv.entries.find((e) => e.kind === "pivot" && e.origin === pin.id && e.query && e.query.text === text);
  if (dup) return dup;
  const lang = language || (pin.from.platform === "sentinel" ? "KQL" : "SPL");
  return notebook.pivot({ origin: pin.id, query: { text, language: lang }, name, found, from: { platform: pin.from.platform, container: pin.from.container, scope: pin.from.scope } });
}

export function attachButton({ kind = "enrichment", source, summary = "", result = null, verdict = null, field, value, container = null, platform = PLATFORM, scope = null, event = null, search = null, notebookUrl = null } = {}) {
  const note = h("span", { class: "reach-attach__note" });
  const btn = h("button", { type: "button", class: "reach-mini reach-attach__btn", title: "Keep this result on the held value in the investigation notebook" }, "Attach to notebook");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await notebook.load();
      let pin = heldPin({ field, value, container });
      if (!pin) {
        const p = pinFrom({ field, value, container, platform, scope, event, search: typeof search === "function" ? await search() : search, reason: `held for the ${source} result` });
        if (!p) throw new Error("this value is scope, not something to hold");
        pin = await notebook.record(p);
      }
      if (kind === "verdict") await notebook.add({ kind: "verdict", on: pin.id, verdict: clean(verdict || summary, 2000), source: clean(source, 200) });
      else await notebook.enrich({ on: pin.id, source: clean(source, 200), summary: clean(summary, 20000), result });
      btn.textContent = "Attached ✓";
      const inv = notebook.current();
      note.replaceChildren(inv ? `in ${displayTitle(inv)} ` : "", notebookLink(notebookUrl, "open →"));
    } catch (err) {
      btn.disabled = false;
      note.textContent = `Not attached: ${err && err.message ? err.message : String(err)}`;
    }
  });
  return h("div", { class: "reach-attach" }, btn, note);
}

// --- known benign --------------------------------------------------------------
// The clicked value marked known benign (app/lib/benign.js) with the same
// provenance a pin carries, and the exclusion the marked values make on
// this field. Everything here is drawn; inserting the exclusion is a
// click on Insert (editor-bridge apply: the search bar, the Logs editor when
// it answers, the clipboard otherwise) or Copy, never automatic. Nothing leaves the browser.

const EXPIRIES = [
  ["0", "no expiry"],
  ["7", "7 days"],
  ["30", "30 days"],
  ["90", "90 days"],
];

function offerLine(ex, { onInsert, platform }) {
  const note = h("span", { class: "reach-attach__note" });
  const bar = h("div", { class: "reach-benign__bar" });
  if (onInsert) {
    const ins = h("button", { type: "button", class: "reach-mini", title: "Append it to the query editor" }, "Insert");
    ins.addEventListener("click", async () => {
      ins.disabled = true;
      try {
        const res = await onInsert(ex.apply);
        note.textContent = res && res.notice ? res.notice : res && res.ok ? "inserted" : "not inserted";
      } catch (err) {
        note.textContent = `Not inserted: ${err && err.message ? err.message : String(err)}`;
      } finally {
        ins.disabled = false;
      }
    });
    bar.appendChild(ins);
  }
  const cp = h("button", { type: "button", class: "reach-mini", title: "Copy the exclusion" }, "Copy");
  cp.addEventListener("click", () => {
    copyText(ex.text, cp, "copied ✓");
    noteSearch({ text: ex.text, platform, source: "copy", origin: "exclusion", field: ex.field, container: ex.container });
  });
  bar.append(cp, note);
  return h("div", null, h("code", null, ex.text), h("div", { class: "reach-benign__why" }, ex.why), ex.caveats.length ? h("div", { class: "reach-benign__why" }, ex.caveats.join(". ")) : null, bar);
}

export function exclusionOffer({ field, container = null, platform = PLATFORM, onInsert = null, samples = null } = {}) {
  const P = platform === "sentinel" ? "sentinel" : "splunk";
  const cont = clean(container, 500);
  const root = h("div", { class: "reach-benign__offer" });
  const draw = () => {
    root.replaceChildren();
    let ex;
    try {
      ex = benign.exclusion(field, cont, P, { samples });
    } catch (err) {
      root.textContent = `No exclusion: ${err && err.message ? err.message : String(err)}`;
      return;
    }
    if (!ex) return;
    root.appendChild(h("div", null, `Exclude ${ex.count} known-benign value${ex.count === 1 ? "" : "s"} on ${field}${cont ? ` (${cont})` : ""}:`));
    root.appendChild(offerLine(ex, { onInsert, platform: P }));
    if (ex.alternative) root.appendChild(h("div", { class: "reach-benign__alt" }, ex.alternative.form === "wildcard" ? "Or folded to one pattern, wider than the marked values:" : "Or the exact list:", offerLine(ex.alternative, { onInsert, platform: P })));
  };
  root.redraw = draw;
  benign
    .load()
    .then(draw)
    .catch(() => {});
  return root;
}

// `compact` is the title block's action row: the bar is the button alone,
// and the click opens the reason and the expiry under the row with a
// `Mark` button that records.
export function benignBlock({ field, value, container = null, platform = PLATFORM, scope = null, event = null, search = null, reason = "", onInsert = null, samples = null, notebookUrl = null, compact = false } = {}) {
  const probe = pinFrom({ field, value, container, platform, scope, event });
  if (!probe) return null;
  const P = platform === "sentinel" ? "sentinel" : "splunk";
  const cont = clean(container, 500);
  const status = h("div", { class: "reach-hold__status" });
  const reasonEl = h("input", { class: "reach-input reach-hold__reason", type: "text", placeholder: "why it is benign (optional)", "aria-label": "Reason", value: clean(reason, 2000), autocomplete: "off", spellcheck: "false" });
  const expiry = h("select", { class: "reach-input reach-benign__expiry", "aria-label": "Expiry", title: "The mark lapses after this" }, EXPIRIES.map(([v, label]) => h("option", { value: v }, label)));
  const btn = h("button", { type: "button", class: "reach-btn reach-benign__btn", title: "Keep this value in the known-benign set for this field and container; nothing leaves the browser" }, "Mark benign");
  const mark = compact ? h("button", { type: "button", class: "reach-btn reach-btn--primary reach-benign__mark" }, "Mark") : null;
  const form = compact ? h("div", { class: "reach-hold__bar reach-benign__form", hidden: true }, reasonEl, expiry, mark) : null;
  const bar = compact ? h("div", { class: "reach-hold__bar" }, btn) : h("div", { class: "reach-hold__bar" }, btn, reasonEl, expiry);
  const offer = exclusionOffer({ field, container: cont, platform: P, onInsert, samples });
  const root = h("div", { class: `reach-row reach-hold reach-benign${compact ? " reach-benign--compact" : ""}` }, bar, form, status, offer);

  // Marked: the row collapses to one status line (reason, expiry, when it
  // was marked, then Unmark at the end); the reason input and the expiry
  // select return only once Unmark takes the entry out again.
  const showMarked = (entry, noted) => {
    bar.hidden = true;
    btn.hidden = true; // the button itself too: the value page lifts it out of the bar
    if (form) form.hidden = true;
    const un = h("button", { type: "button", class: "reach-mini reach-benign__unmark", title: "Take it out of the known-benign set" }, "Unmark");
    un.addEventListener("click", async () => {
      un.disabled = true;
      await benign.remove(entry.id).catch(() => {});
      reasonEl.value = "";
      expiry.value = EXPIRIES[0][0];
      bar.hidden = false;
      btn.hidden = false;
      btn.disabled = false;
      if (form) form.hidden = true;
      replace(status);
      offer.redraw();
    });
    const line = [
      "Known benign",
      entry.reason || "no reason given",
      entry.expires_at ? `expires ${when(entry.expires_at)}` : "no expiry",
      `marked ${when(entry.added_at)}`,
    ].join(" · ");
    replace(status, h("span", { class: "reach-benign__line" }, line), un, noted ? " Noted in the notebook. " : null, noted ? notebookLink(notebookUrl, "open →") : null);
  };

  const record = async () => {
    btn.disabled = true;
    if (mark) mark.disabled = true;
    try {
      const s = typeof search === "function" ? await search() : search;
      const pin = pinFrom({ field, value, container, platform, scope, event, search: s });
      const days = Number(expiry.value) || 0;
      const entry = await benign.add({ value: pin.value, field: pin.field, container: cont, platform: P, reason: reasonEl.value, expires_at: days ? Date.now() + days * 86_400_000 : undefined, from: pin.from });
      let noted = false;
      try {
        await notebook.load();
        const held = heldPin({ field, value, container });
        if (held) noted = (await benign.attach(entry.id, { on: held.id })).ok;
      } catch {
        /* the mark stands without the note */
      }
      showMarked(entry, noted);
      offer.redraw();
    } catch (err) {
      btn.disabled = false;
      if (mark) mark.disabled = false;
      status.textContent = `Not marked: ${err && err.message ? err.message : String(err)}`;
    }
  };
  if (compact) {
    btn.addEventListener("click", () => {
      form.hidden = !form.hidden;
      if (!form.hidden) reasonEl.focus();
    });
    mark.addEventListener("click", record);
  } else {
    btn.addEventListener("click", record);
  }
  reasonEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      (mark || btn).click();
    }
  });

  benign
    .load()
    .then(() => {
      const v = clean(value);
      const had = benign.list({ container: cont, field: clean(field, 500) }).find((e) => e.value === v);
      if (had && !bar.hidden) showMarked(had, false);
    })
    .catch(() => {});
  return root;
}

export function exclusionStrip({ container, fields = [], platform = PLATFORM, onInsert = null, query = "", onClose = null } = {}) {
  const P = platform === "sentinel" ? "sentinel" : "splunk";
  const cont = clean(container, 500);
  const items = [];
  for (const field of fields) {
    let ex;
    try {
      ex = benign.exclusion(field, cont, P);
    } catch {
      continue;
    }
    if (!ex) continue;
    const label = h("span", null, `${ex.count} value${ex.count === 1 ? "" : "s"} on ${field}`);
    const note = h("span", { class: "reach-attach__note" });
    if (query && query.includes(ex.text)) {
      items.push(h("span", { class: "reach-benign-strip__item", title: ex.text }, label, h("span", { class: "reach-attach__note" }, "applied ✓")));
      continue;
    }
    const insert = Boolean(onInsert);
    const act = h("button", { type: "button", class: "reach-mini", title: `${ex.text}\n${ex.why}` }, insert ? "Insert" : "Copy");
    act.addEventListener("click", async () => {
      act.disabled = true;
      try {
        if (insert) {
          const res = await onInsert(ex.apply);
          note.textContent = res && res.notice ? res.notice : res && res.ok ? "inserted" : "not inserted";
        } else {
          copyText(ex.text, act, "copied ✓");
          noteSearch({ text: ex.text, platform: P, source: "copy", origin: "exclusion", field, container: cont });
        }
      } catch (err) {
        note.textContent = `Not inserted: ${err && err.message ? err.message : String(err)}`;
      } finally {
        act.disabled = false;
      }
    });
    items.push(h("span", { class: "reach-benign-strip__item" }, label, act, note));
  }
  if (!items.length) return null;
  const close = h("button", { type: "button", class: "reach-benign-strip__close", title: "Hide for this page", "aria-label": "Hide" }, "×");
  const root = h("div", { class: "reach-section reach-benign-strip" }, h("span", { class: "reach-badge" }, "REACH"), h("span", null, `known benign on ${cont}:`), items, close);
  close.addEventListener("click", () => {
    root.remove();
    if (onClose) onClose();
  });
  return root;
}
