// The pattern builder: the clicked value cut into segments, a state per
// segment, the ladder's rungs for those states and an offline preview.
//
//   PATTERN_CSS                       the block's stylesheet, for the app's value page (POPUP_CSS carries it too)
//   patternModel({ value, field, platform, samples, fieldClass, shape }) → PatternModel | null   (pure)
//       the value cut into segments (segments.js), a state per segment (keep,
//       any, like; cycle() walks them), the ladder's rungs for the current
//       states (ladder.js) and the offline preview counted over the discovered
//       profile's top values
//   patternBlock({ value, field, container, platform, samples, fieldClass, onInsert, liveTest }) → Element | null
//       that model, drawn: segment chips, the cheapest rung with its why line,
//       the preview line, Insert / Replace term when the caller hands an onInsert
//       (Sentinel: only the blade script does, once the Monaco bridge answers),
//       Copy, a fold with the other rungs and, when the caller hands one, a
//       fold that mounts a live test on the rung
//
// DOM module (uses h.js). Never fetches; nothing here inserts or runs on its own.

import { h } from "../../components/h.js";
import { PLATFORM, TERMS } from "../platform.js";
import { heading } from "../headings.js";
import * as ladder from "../ladder.js";
import { copyText } from "../runtime.js";
import * as searches from "../searches.js";

// Written against the --rc-* palette only and self-contained, so the app's
// value page can carry it with a variable map instead of the whole POPUP_CSS.
export const PATTERN_CSS = `
.reach-pattern{margin:0 0 12px;max-width:100%;min-width:0}
.reach-pattern__title{color:var(--rc-fg);font-weight:600;margin-bottom:2px}
.reach-pattern__hint{font-size:11px;color:var(--rc-fg2);font-weight:400;margin-bottom:4px}
.reach-pattern__chips{display:flex;flex-wrap:wrap;gap:4px 2px;align-items:center;margin:4px 0 8px;max-width:100%}
.reach-pattern__sep{color:var(--rc-fg2);font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:11px;padding:0 1px}
.reach-pattern__chip{font:inherit;font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;line-height:18px;padding:1px 7px;border-radius:10px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);cursor:pointer;max-width:100%;overflow-wrap:anywhere;text-align:left;min-width:0}
.reach-pattern__chip:hover{background:var(--rc-bg3)}
.reach-pattern__chip[data-state="any"]{border-style:dashed;color:var(--rc-fg2);background:var(--rc-bg3)}
.reach-pattern__chip[data-state="any"] .reach-pattern__text{text-decoration:line-through;opacity:.75}
.reach-pattern__chip[data-state="like"]{border-style:dotted;border-color:var(--rc-accent);background:var(--rc-info-bg);color:var(--rc-fg)}
.reach-pattern__chip--merged{border-width:2px}
.reach-pattern__chip--merged .reach-pattern__text{text-decoration:none;opacity:1;font-style:italic}
.reach-pattern__state{font-family:inherit;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin-left:5px;color:var(--rc-accent)}
.reach-pattern__chip[data-state="any"] .reach-pattern__state{color:var(--rc-fg2)}
.reach-pattern__code{background:var(--rc-bg2);border:1px solid var(--rc-line);border-radius:2px;padding:6px 8px;color:var(--rc-code-fg);font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;margin:0 0 4px;max-height:160px;overflow:auto;max-width:100%}
.reach-pattern__why{font-size:12px;color:var(--rc-fg2);overflow-wrap:anywhere}
.reach-pattern__why b{color:var(--rc-fg);font-weight:600}
.reach-pattern__caveat{font-size:12px;color:var(--rc-fg2);padding-left:10px;border-left:2px solid var(--rc-warn-line);margin:4px 0;overflow-wrap:anywhere}
.reach-pattern__preview{font-size:12px;color:var(--rc-fg);margin-top:4px}
.reach-pattern__preview--none{color:var(--rc-fg2);font-style:italic}
.reach-pattern__actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.reach-pattern__btn{font:inherit;font-size:12px;font-weight:600;min-height:26px;padding:2px 10px;border-radius:2px;border:1px solid var(--rc-line3);background:var(--rc-bg);color:var(--rc-fg);cursor:pointer}
.reach-pattern__btn:hover{background:var(--rc-bg3)}
.reach-pattern__btn--primary{border-color:var(--rc-accent);background:var(--rc-accent);color:var(--rc-accent-fg)}
.reach-pattern__btn--primary:hover{border-color:var(--rc-accent-hover);background:var(--rc-accent-hover)}
.reach-pattern__btn:disabled{background:var(--rc-disabled-bg);border-color:var(--rc-disabled-bg);color:var(--rc-disabled);cursor:default}
.reach-pattern__notice{font-size:12px;color:var(--rc-fg2);margin-top:4px;overflow-wrap:anywhere}
.reach-pattern__notice:empty{display:none}
.reach-pattern__more{margin-top:6px}
.reach-pattern__more>summary{color:var(--rc-fg);font-weight:600;cursor:pointer;list-style:none;padding:2px 0;font-size:12px}
.reach-pattern__more>summary::-webkit-details-marker{display:none}
.reach-pattern__more>summary::before{content:"▸ ";color:var(--rc-fg2)}
.reach-pattern__more[open]>summary::before{content:"▾ "}
.reach-pattern__alt{display:block;width:100%;text-align:left;font:inherit;font-size:12px;background:none;border:0;border-top:1px solid var(--rc-line);padding:6px 0;color:var(--rc-fg);cursor:pointer;min-width:0}
.reach-pattern__alt:hover{background:var(--rc-bg2)}
.reach-pattern__alt[aria-pressed="true"]{color:var(--rc-fg2);cursor:default}
.reach-pattern__alt code{display:block;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;border:0;background:none;padding:0;font-family:"Cascadia Code","Cascadia Mono",Consolas,Menlo,ui-monospace,monospace;font-size:12px;color:var(--rc-code-fg)}
.reach-pattern__alt small{color:var(--rc-fg2);font-size:11px}
.reach-pattern__live{margin-top:6px}
`;

// ---------------------------------------------------------------------------
// The pattern builder

const STATE_ORDER = ["keep", "any", "like"];
const STATE_LABEL = { keep: "", any: "any", like: "like this" };
const STATE_TITLE = {
  keep: "Kept: exactly this text. Tap to open it to anything.",
  any: "Open: anything at all in its place. Tap to ask for the same kind of thing instead.",
  like: "Like this: the same kind of thing in this position (digits for digits, one path segment for a directory). Tap to keep the text again.",
};
const CONSTRUCT_LABEL = {
  term: "TERM()",
  literal: "exact",
  trailing_wildcard: "prefix",
  cidr: "CIDR",
  in: "IN list",
  wildcard: "wildcard",
  like: "where",
  regex: "regex",
  rex: "extract",
};
const KQL_CONSTRUCT_LABEL = { ...CONSTRUCT_LABEL, term: "has", like: "endswith / contains", rex: "extend" };

// Segment kinds that read as one run of "levels": adjacent same-kind
// segments sharing a state (any or like) merge into one chip. dir is a
// path's directories, label a domain's (or an email/UPN's) labels, octet
// and group an IPv4/IPv6 address's pieces. The ladder itself already folds
// an adjacent-any run into one wildcard star (segments.js partsOf); the
// merge here is the chip's display and the "exactly N" cycle on top of it.
const MERGE_KIND = {
  dir: { noun: "directory", nounPlural: "directories", any: "any path", exactly: (n) => `exactly ${n} level${n === 1 ? "" : "s"}` },
  label: { noun: "label", nounPlural: "labels", any: "any labels", exactly: (n) => `exactly ${n} label${n === 1 ? "" : "s"}` },
  octet: { noun: "octet", nounPlural: "octets", any: "any octets", exactly: () => "network (CIDR)" },
  group: { noun: "group", nounPlural: "groups", any: "any groups", exactly: () => "network (CIDR)" },
};

// Runs of two or more adjacent segments of the same mergeable kind, all in
// the same non-keep state: { start, end (inclusive), kind, state }. A run
// dissolves back to individual chips the moment its state stops matching
// (any->like moves the whole run together, via cycleRun; keep never merges).
function mergeRuns(segments) {
  const runs = [];
  let i = 0;
  while (i < segments.length) {
    const g = segments[i];
    if (MERGE_KIND[g.kind] && g.state !== "keep") {
      let j = i + 1;
      while (j < segments.length && segments[j].kind === g.kind && segments[j].state === g.state) j++;
      if (j - i >= 2) {
        runs.push({ start: i, end: j - 1, kind: g.kind, state: g.state });
        i = j;
        continue;
      }
    }
    i += 1;
  }
  return runs;
}

// The pure model behind patternBlock. Null when there is nothing to cut
// (no field, an empty value). Rungs come from ladder.build for the current
// states; a build the ladder refuses leaves rungs() empty and error set.
export function patternModel({ value, field, platform = PLATFORM, samples = null, fieldClass, shape, ci, dynamic } = {}) {
  if (value === undefined || value === null || !field) return null;
  const literal = String(value);
  if (!literal.trim()) return null;
  const lang = platform === "sentinel" || platform === "kql" ? "kql" : "spl";
  let spec;
  try {
    spec = ladder.specFor(literal, undefined, shape);
  } catch {
    return null;
  }
  const list = Array.isArray(samples) ? samples.filter((v) => v && v.value !== undefined && v.value !== null && String(v.value) !== "") : [];
  const sampleEvents = list.reduce((n, v) => n + (Number.isFinite(Number(v.count)) ? Number(v.count) : 1), 0);
  let memo = null;
  const m = {
    value: literal,
    field,
    platform: lang,
    shape: spec.shape,
    detail: spec.detail,
    truncated: spec.truncated,
    segments: spec.segments,
    sampleValues: list.length,
    sampleEvents,
    error: null,
    states() {
      return spec.segments.map((g) => g.state);
    },
    state(i) {
      return spec.segments[i] ? spec.segments[i].state : undefined;
    },
    set(i, state) {
      if (!spec.segments[i] || !STATE_ORDER.includes(state)) return m.state(i);
      spec.segments[i].state = state;
      memo = null;
      return state;
    },
    cycle(i) {
      const cur = m.state(i);
      if (cur === undefined) return undefined;
      return m.set(i, STATE_ORDER[(STATE_ORDER.indexOf(cur) + 1) % STATE_ORDER.length]);
    },
    reset() {
      for (const g of spec.segments) g.state = "keep";
      memo = null;
    },
    allOpen() {
      return spec.segments.every((g) => g.state !== "keep");
    },
    // Adjacent any/like runs of the same mergeable kind, one merged chip
    // apiece; see mergeRuns above.
    mergeRuns() {
      return mergeRuns(spec.segments);
    },
    // Cycles every segment in [start, end] together, one step in STATE_ORDER
    // (the run shares one state by construction, so state(start) speaks for
    // all of it). any -> like carries the run to "exactly N"; like -> keep
    // un-merges it back to individual chips.
    cycleRun(start, end) {
      const cur = m.state(start);
      if (cur === undefined) return undefined;
      const next = STATE_ORDER[(STATE_ORDER.indexOf(cur) + 1) % STATE_ORDER.length];
      for (let i = start; i <= end; i++) m.set(i, next);
      return next;
    },
    rungs() {
      if (memo) return memo;
      m.error = null;
      try {
        memo = ladder.build({ ...spec, segments: spec.segments.map((g) => ({ ...g })) }, { platform: lang, field, fieldClass, samples: list.length ? list : undefined, ci, dynamic });
      } catch (err) {
        m.error = err && err.message ? err.message : String(err);
        memo = [];
      }
      return memo;
    },
    cheapest() {
      const r = m.rungs();
      return r.length ? r[0] : null;
    },
    label(rung) {
      return (lang === "kql" ? KQL_CONSTRUCT_LABEL : CONSTRUCT_LABEL)[rung.construct] || rung.construct;
    },
    // { values, ofValues, events, ofEvents } for a rung, or null without samples
    preview(rung) {
      if (!rung || !rung.preview || !list.length) return null;
      return { values: rung.preview.hits, ofValues: list.length, events: rung.preview.matched, ofEvents: rung.preview.total };
    },
    previewLine(rung) {
      const p = m.preview(rung);
      if (!p) return null;
      const ev = p.ofEvents !== p.ofValues ? ` (${p.events.toLocaleString()} of ${p.ofEvents.toLocaleString()} events profiled)` : "";
      return `Matches ${p.values} of ${p.ofValues} sample value${p.ofValues === 1 ? "" : "s"}${ev}`;
    },
  };
  return m;
}

// The builder, below the value row. `samples` is the discovered profile's
// top list for the container and column (view.profile.top), `onInsert(req)`
// resolves to { ok, notice } (app/lib/editor-bridge.js apply), `liveTest(rung)`
// returns the control that runs the rung on the user's Splunk, mounted only
// when its fold is opened. Nothing here inserts or runs on its own.
export function patternBlock({ value, field, container, platform = PLATFORM, samples = null, fieldClass, shape, onInsert, liveTest } = {}) {
  const m = patternModel({ value, field, platform, samples, fieldClass, shape });
  if (!m) return null;
  const kql = m.platform === "kql";
  const langWord = kql ? "KQL" : "SPL";
  const root = h("div", { class: "reach-pattern", dataset: { shape: m.shape } });
  let chosen = null; // a rung picked from the fold; null follows the cheapest
  const chips = h("div", { class: "reach-pattern__chips", role: "group", "aria-label": "value segments" });
  const out = h("div", { class: "reach-pattern__out" });
  const notice = h("div", { class: "reach-pattern__notice", "aria-live": "polite" });

  function current() {
    const rungs = m.rungs();
    if (chosen && rungs.some((r) => r.construct === chosen)) return rungs.find((r) => r.construct === chosen);
    chosen = null;
    return rungs[0] || null;
  }

  function chipButton(g, i) {
    return h(
      "button",
      {
        type: "button",
        class: "reach-pattern__chip",
        dataset: { state: g.state, kind: g.kind, index: i },
        title: `${g.kind}. ${STATE_TITLE[g.state]}`,
        onClick: (e) => {
          e.stopPropagation();
          m.cycle(i);
          chosen = null;
          drawChips();
          drawOut();
        },
      },
      h("span", { class: "reach-pattern__text" }, g.text),
      STATE_LABEL[g.state] ? h("span", { class: "reach-pattern__state" }, STATE_LABEL[g.state]) : null,
    );
  }

  // One chip for a whole merge run: "any path", "any labels", "any octets",
  // or once cycled, "exactly N levels" / "exactly N labels" / "network
  // (CIDR)" for an IP run (the ladder already prefers cidr there over a
  // depth regex; see mergeRuns). Tapping it cycles the whole run together.
  // The merged count rides on the title, a tap detail.
  function mergedChipButton(run) {
    const count = run.end - run.start + 1;
    const info = MERGE_KIND[run.kind];
    const label = run.state === "any" ? info.any : info.exactly(count);
    const detail =
      run.state === "any"
        ? `${count} ${count === 1 ? info.noun : info.nounPlural} merged: any depth, zero or more. Tap for exactly ${count}.`
        : run.kind === "octet" || run.kind === "group"
          ? `${count} ${info.nounPlural} open: an address width, not a level count. Expressed below as a CIDR range, the rung a wildcard cannot state. Tap to keep the text again.`
          : `${count} ${info.nounPlural} kept as exactly this many. Tap to keep the text again.`;
    return h(
      "button",
      {
        type: "button",
        class: "reach-pattern__chip reach-pattern__chip--merged",
        dataset: { state: run.state, kind: run.kind, merged: "true", count: String(count) },
        title: detail,
        onClick: (e) => {
          e.stopPropagation();
          m.cycleRun(run.start, run.end);
          chosen = null;
          drawChips();
          drawOut();
        },
      },
      h("span", { class: "reach-pattern__text" }, label),
    );
  }

  function drawChips() {
    chips.replaceChildren();
    const runAt = new Map(m.mergeRuns().map((r) => [r.start, r]));
    let skipTo = -1;
    m.segments.forEach((g, i) => {
      if (i <= skipTo && !runAt.has(i)) return;
      if (g.sep) chips.appendChild(h("span", { class: "reach-pattern__sep", "aria-hidden": "true" }, g.sep));
      const run = runAt.get(i);
      if (run) {
        chips.appendChild(mergedChipButton(run));
        skipTo = run.end;
        return;
      }
      chips.appendChild(chipButton(g, i));
    });
  }

  function drawOut() {
    out.replaceChildren();
    notice.textContent = "";
    const rung = current();
    if (!rung) {
      out.appendChild(h("div", { class: "reach-pattern__preview reach-pattern__preview--none" }, m.error ? `No ${langWord} for this: ${m.error}` : `No ${langWord} form reaches this pattern.`));
      return;
    }
    const rungs = m.rungs();
    out.appendChild(h("pre", { class: "reach-pattern__code", tabindex: "0", "aria-label": langWord }, rung.text));
    out.appendChild(h("div", { class: "reach-pattern__why" }, h("b", null, m.label(rung)), rung === rungs[0] ? ", the cheapest form here: " : ": ", rung.why));
    for (const c of rung.caveats || []) out.appendChild(h("div", { class: "reach-pattern__caveat" }, c));
    if (m.allOpen()) out.appendChild(h("div", { class: "reach-pattern__caveat" }, "Nothing kept: this matches every value of the field."));
    const depth = m.mergeRuns().find((r) => r.state === "like" && (r.kind === "dir" || r.kind === "label"));
    if (depth && rung.construct === "regex") {
      out.appendChild(h("div", { class: "reach-pattern__caveat" }, "Wildcards cannot express depth: a star matches any number of levels, so an exact count takes the regex rung."));
    }
    const line = m.previewLine(rung);
    if (line) out.appendChild(h("div", { class: "reach-pattern__preview", title: "Counted offline over the top values discovery profiled for this column; no search runs." }, line, m.truncated ? " (the stored value was cut at 200 characters, so this matches by prefix)" : ""));
    else out.appendChild(h("div", { class: "reach-pattern__preview reach-pattern__preview--none" }, `No sample values for ${field} on ${container || `this ${TERMS.sourcetype}`} yet; profile it on the Discover page for an offline preview.`));

    const actions = h("div", { class: "reach-pattern__actions" });
    const act = async (mode, btn) => {
      if (!onInsert) return;
      btn.disabled = true;
      try {
        const res = await onInsert({ text: rung.text, form: rung.form, field, mode, platform: kql ? "sentinel" : "splunk", trace: { origin: "pattern", container } });
        notice.textContent = res && res.notice ? res.notice : res && res.ok ? "Done" : "Nothing happened";
      } catch (err) {
        notice.textContent = err && err.message ? err.message : String(err);
      } finally {
        btn.disabled = false;
      }
    };
    if (onInsert) {
      actions.appendChild(h("button", { type: "button", class: "reach-pattern__btn reach-pattern__btn--primary", title: rung.form === "stage" ? "Add this stage at the end of the query" : kql ? "Add this as a | where stage at the end of the query" : "Add this term to the search block (AND)", onClick: (e) => act("append", e.currentTarget) }, "Insert"));
      if (rung.form === "term") actions.appendChild(h("button", { type: "button", class: "reach-pattern__btn", title: `Swap the ${field} term already in the query for this one`, onClick: (e) => act("replace", e.currentTarget) }, "Replace term"));
    }
    actions.appendChild(h("button", { type: "button", class: `reach-pattern__btn${onInsert ? "" : " reach-pattern__btn--primary"}`, onClick: (e) => { copyText(rung.text, e.currentTarget, "copied ✓"); searches.record({ text: rung.text, platform: kql ? "sentinel" : "splunk", source: "copy", origin: "pattern", field, container }).catch(() => {}); } }, `Copy ${langWord}`));
    out.appendChild(actions);
    out.appendChild(notice);
    if (kql && !onInsert) out.appendChild(h("div", { class: "reach-pattern__notice" }, "Paste it into the Logs editor: Insert needs the editor open in KQL mode in this frame."));

    const others = rungs.filter((r) => r !== rung);
    if (others.length) {
      const fold = h("details", { class: "reach-pattern__more" }, h("summary", null, heading("other-forms", others.length)));
      for (const r of others) {
        const alt = m.previewLine(r);
        fold.appendChild(
          h(
            "button",
            {
              type: "button",
              class: "reach-pattern__alt",
              dataset: { construct: r.construct },
              title: "Use this form instead",
              onClick: (e) => {
                e.stopPropagation();
                chosen = r.construct;
                drawOut();
                const f = out.querySelector(".reach-pattern__more");
                if (f) f.open = true;
              },
            },
            h("code", null, r.text),
            h("small", null, `${m.label(r)} · ${r.why}${alt ? ` · ${alt.replace(/^Matches /, "matches ")}` : ""}`),
          ),
        );
      }
      out.appendChild(fold);
    }

    if (liveTest && !kql) {
      const body = h("div");
      out.appendChild(
        h(
          "details",
          {
            class: "reach-pattern__more reach-pattern__live",
            onToggle: (e) => {
              if (e.target.open && !body.childElementCount) {
                const ctl = liveTest(rung);
                if (ctl) body.appendChild(ctl);
              }
            },
          },
          h("summary", { title: "Opens a run control for this form; nothing runs until its own button is clicked." }, heading("live-test")),
          body,
        ),
      );
    }
  }

  root.appendChild(h("div", { class: "reach-pattern__hint" }, "Tap a piece to cycle it: keep, any, like this."));
  root.appendChild(chips);
  root.appendChild(out);
  drawChips();
  drawOut();
  return root;
}
