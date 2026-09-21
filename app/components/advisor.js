// The advisor on the page: the field's efficiency class as a chip with its
// evidence and the cheapest filter, the lint over a search (the one the
// last click rode in on, or one pasted here) on an explicit click, and on
// Splunk the measured side: the job's own counts read on a click.
//
//   efficiencyChip(cls)                              → chip element (cls from efficiency.js)
//   advisorSection({ ctx, view, sourcetype, name })  → section element
//   advisorLine({ platform })                        → element with .update(text): the drawer's quiet line
//   findingsList(findings)                           → ul element
//   classContext(catalogue, sourcetype, platform)    → { classOf }   the lint context for a container
//   controlsFor({ platform, sid, available })        → { advise, measure, measureEnabled, hint }   pure
//   adviseText({ live, input })                       → text                                        pure
//
// Advise reads the search bar (Splunk) or the Logs editor (Sentinel) live
// when it can reach one, through editor-bridge.js: read() directly if the
// section is drawn in the host page itself, readFromTab() when it is the
// side panel or a served page with no editor in its own document. The
// pasted/carried text in the textarea is the fallback, and what a live
// read is shown against, never overwritten in place of it.
//
// Job stats are Splunk's only: Reach never runs a query on Sentinel, so
// there is nothing measured to read there and the Measure control is not
// drawn, not disabled.

import { h, replace } from "./h.js";
import { headingNode } from "../lib/headings.js";
import { chip } from "./chip.js";
import * as efficiency from "../lib/efficiency.js";
import * as advisor from "../lib/advisor.js";
import * as lastEvent from "../lib/last-event.js";
import * as discovery from "../lib/discovery.js";
import * as bridge from "../lib/editor-bridge.js";
import { PLATFORM, TERMS } from "../lib/platform.js";

const GLYPH = { indexed: "≡", raw_token: "≡", search_time: "·", calculated: "ƒ", lookup_output: "⤳", pipeline_derived: "|" };

export function efficiencyChip(cls) {
  if (!cls) return null;
  const el = chip({ kind: "route", value: cls.class, text: cls.label, title: cls.advice });
  const g = el.querySelector(".r-chip__glyph");
  if (g) g.textContent = GLYPH[cls.class] || "·";
  el.classList.add("r-chip--efficiency", `r-chip--efficiency-${cls.class}`);
  return el;
}

export function classContext(catalogue, sourcetype, platform = PLATFORM) {
  const memo = new Map();
  const resolve = (n) => (catalogue && sourcetype ? catalogue.fieldOn(sourcetype, n) : null);
  return {
    classOf(field) {
      if (memo.has(field)) return memo.get(field);
      const view = resolve(field);
      const c = view ? efficiency.classOf(view, { platform, resolve }).class : null;
      memo.set(field, c);
      return c;
    },
  };
}

function severityChip(sev) {
  return sev === "caution" ? chip({ kind: "trust", value: "asserted", text: "caution" }) : chip({ kind: "trust", value: "inferred", text: "note" });
}

export function findingsList(findings) {
  const list = findings || [];
  if (!list.length) return h("p", { class: "r-muted r-advisor__none" }, "No notes: nothing here the rules would say differently.");
  return h(
    "ul",
    { class: "r-list r-advisor__findings" },
    list.map((f) =>
      h(
        "li",
        { class: `r-advisor__finding r-advisor__finding--${f.severity}` },
        h("p", { class: "r-advisor__head" }, severityChip(f.severity), " ", h("b", null, f.title), " ", h("code", { class: "r-advisor__span" }, f.text.length > 80 ? `${f.text.slice(0, 77)}...` : f.text)),
        h("p", { class: "r-advisor__why" }, f.why),
        f.fix && f.fix.text ? h("p", { class: "r-advisor__fix" }, h("span", { class: "r-muted" }, f.fix.label ? `${f.fix.label}: ` : "try: "), h("code", null, f.fix.text)) : null,
      ),
    ),
  );
}

// The drawer's line: "advisor: N notes" as a fold that opens on the
// findings. Empty text draws nothing.
export function advisorLine({ platform = PLATFORM } = {}) {
  const summary = h("summary", { class: "r-advisor__line" }, "advisor: no notes");
  const body = h("div", { class: "r-advisor__body" });
  const el = h("details", { class: "r-advisor r-advisor--line", hidden: true }, summary, body);
  el.update = (text, ctx) => {
    const s = String(text || "");
    if (!s.trim()) {
      el.hidden = true;
      return [];
    }
    const findings = advisor.lint(s, platform, ctx);
    summary.textContent = advisor.summary(findings);
    el.classList.toggle("r-advisor--cautions", findings.some((f) => f.severity === "caution"));
    replace(body, findingsList(findings));
    el.hidden = false;
    return findings;
  };
  return el;
}

// Which controls the section draws (pure): Advise on both platforms;
// Measure only on Splunk, enabled only with a job id from a row click and
// the extension to relay through. Sentinel never gets the control, since
// Reach never runs a query there and so has nothing measured to read.
export function controlsFor({ platform = PLATFORM, sid = "", available = false } = {}) {
  const sentinel = platform === "sentinel" || platform === "kql";
  return {
    advise: true,
    measure: !sentinel,
    measureEnabled: !sentinel && Boolean(sid) && Boolean(available),
    hint: sentinel
      ? "measured on Splunk only: Reach never runs a query on Sentinel"
      : sid
        ? "the job's id rode in on the row click; then press Measure"
        : "Measure needs a row click on a run search, then press Measure",
  };
}

// What Advise lints: the live read when the bridge found text, the box
// otherwise. A live read with empty text (the bar is there but blank)
// still counts as live, since that is the honest state of the page.
export function adviseText({ live, input = "" } = {}) {
  return live && live.ok && typeof live.text === "string" && live.text.trim() ? live.text : input;
}

// The live read for the platform this section is drawn on: the page's own
// editor first (the section is running in the host page itself), the tab
// relay next (the side panel or a served page has no editor in its own
// document). Sentinel has only the in-page probe for now: sentinel-grid.js
// owns the content-script side of a tab relay and does not answer one yet.
async function liveQueryText(platform) {
  if (platform === "sentinel" || platform === "kql") {
    const kql = await bridge.readKql().catch(() => null);
    return kql && kql.ok ? kql : null;
  }
  const here = await bridge.read().catch(() => null);
  if (here && here.ok) return here;
  const viaTab = await bridge.readFromTab().catch(() => null);
  return viaTab && viaTab.ok ? viaTab : null;
}

// The Splunk origins with a tab open, tried in turn for the job: a sid is
// unique to the search head that made it.
async function readJob(sid) {
  const envs = await discovery.environments();
  const mine = envs.filter((o) => o.tabs && !/portal\.azure\.com/.test(o.origin));
  if (!mine.length) throw new Error("No open Splunk tab: keep the tab the search ran in open.");
  const errors = [];
  for (const o of mine) {
    try {
      const entry = await discovery.jobStats(o.origin, sid);
      const stats = advisor.parseJob(entry);
      if (stats) return { stats, origin: o.origin };
      errors.push(`${o.origin}: the job carried no counts`);
    } catch (err) {
      errors.push(`${o.origin}: ${err && err.message ? err.message : String(err)}`);
    }
  }
  throw new Error(errors.join("; "));
}

export function advisorSection({ ctx, view, sourcetype, name }) {
  const catalogue = ctx && ctx.catalogue;
  const platform = PLATFORM;
  const cls = efficiency.classOf(view || { name }, { platform, resolve: (n) => (catalogue && sourcetype ? catalogue.fieldOn(sourcetype, n) : null) });
  const lintCtx = classContext(catalogue, sourcetype, platform);

  const prov = sourcetype ? lastEvent.provenance(sourcetype) : null;
  const carried = prov && prov.search && prov.search.text ? prov.search : null;
  const sid = carried && carried.sid ? carried.sid : "";

  const input = h("textarea", {
    class: "r-input r-advisor__input",
    rows: 3,
    spellcheck: "false",
    placeholder: `Paste ${TERMS.lang} here, or click a row in ${TERMS.host}: its search lands here. Then press Advise.`,
    value: carried ? carried.text : "",
  });
  const out = h("div", { class: "r-advisor__out" });
  const status = h("p", { class: "r-muted r-advisor__status", role: "status", "aria-live": "polite" });

  async function advise() {
    adviseBtn.disabled = true;
    try {
      const live = await liveQueryText(platform);
      const text = adviseText({ live, input: input.value });
      if (live) input.value = text; // shows what got advised, not just what was pasted
      const findings = advisor.lint(text, platform, lintCtx);
      status.textContent = advisor.summary(findings);
      replace(out, findingsList(findings));
    } finally {
      adviseBtn.disabled = false;
    }
  }

  const adviseBtn = h("button", { type: "button", class: "r-btn r-btn--small", onClick: advise }, "Advise");
  const actions = h("div", { class: "r-advisor__actions" }, adviseBtn);
  const controls = controlsFor({ platform, sid, available: discovery.available() });

  if (controls.measure) {
    const measureBtn = h("button", { type: "button", class: "r-btn r-btn--small r-advisor__measure", disabled: !controls.measureEnabled, title: sid ? `job ${sid}` : "Run the search in Splunk and click a row: its id rides in on the click. Then press Measure." }, "Measure");
    measureBtn.addEventListener("click", async () => {
      measureBtn.disabled = true;
      status.textContent = `Reading job ${sid} from your Splunk...`;
      try {
        const { stats } = await readJob(sid);
        const reading = advisor.explain(stats, input.value, lintCtx);
        replace(
          out,
          h(
            "div",
            { class: "r-advisor__measured" },
            h("p", { class: "r-advisor__reading" }, chip({ kind: "trust", value: "confirmed", text: "measured" }), " ", reading.line),
            h("p", { class: "r-muted" }, `scanCount ${stats.scanCount ?? "?"} · eventCount ${stats.eventCount ?? "?"} · resultCount ${stats.resultCount ?? "?"} · runDuration ${stats.runDuration ?? "?"} s`),
            stats.optimizedSearch ? h("pre", { class: "r-prov__stmt", tabindex: "0" }, h("code", null, stats.optimizedSearch)) : null,
            reading.finding ? findingsList([reading.finding]) : null,
          ),
        );
        status.textContent = `Job ${sid}: ${advisor.summary(reading.findings)}`;
      } catch (err) {
        status.textContent = err && err.message ? err.message : String(err);
      } finally {
        measureBtn.disabled = !controls.measureEnabled;
      }
    });
    actions.appendChild(measureBtn);
  }
  actions.appendChild(h("span", { class: "r-muted r-advisor__hint" }, controls.hint));

  return h(
    "section",
    { class: "r-section r-advisor" },
    headingNode("query-advisor"),
    h(
      "p",
      { class: "r-advisor__class" },
      efficiencyChip(cls),
      " ",
      h("span", { class: "r-secondary" }, cls.evidence.join("; ")),
    ),
    h("p", { class: "r-advisor__advice" }, h("span", { class: "r-muted" }, "Cheapest filter: "), cls.advice),
    input,
    actions,
    status,
    out,
  );
}

export default { efficiencyChip, advisorSection, advisorLine, findingsList, classContext, adviseText };
