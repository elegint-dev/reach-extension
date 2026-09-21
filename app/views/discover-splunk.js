// Discover on Splunk: #/discover?env=<origin>&index=<index>
// Run the fixed discovery searches against an enabled Splunk instance and
// see what came back. Every search runs from a click, in an open Splunk tab
// with the user's own session, and lands in the discovered layer: one
// search per row button, or the whole inventory's worth from "Full
// discovery" (discovery-sweep.js), which runs the same per-row steps one
// sourcetype at a time and can be cancelled between them.

import { titleBlock } from "../components/titleBlock.js";
import { headingNode, heading } from "../lib/headings.js";
import { stLink } from "../components/links.js";
import { h, spinner } from "../components/h.js";
import { callout } from "../components/callout.js";
import { table } from "../components/table.js";
import * as discovery from "../lib/discovery.js";
import * as layer from "../lib/layer.js";
import * as sweep from "../lib/discovery-sweep.js";
import * as packs from "../lib/packs.js";
import { PACK_ID as FDR_PACK_ID } from "../lib/fdr-queries.js";
import { sourceChips } from "./catalogue.js";
import { healthChips, deltaLine } from "../components/health.js";
import { copy } from "../lib/copy.js";
import { isPortalOrigin } from "../lib/platform.js";
import { when } from "../lib/when.js";

// The CrowdStrike Falcon pack's own macro allowlist, when this sourcetype
// is one its queries run on; else none, so the provenance step's conf-macros
// read stays scoped to sourcetypes that could ever need it.
function macrosFor(sourcetype) {
  const pack = packs.pack(FDR_PACK_ID);
  if (!pack || !Array.isArray(pack.macros) || !pack.macros.length) return [];
  const onIt = (pack.queries || []).some((q) => (q.containers || []).includes(sourcetype));
  return onIt ? pack.macros : [];
}

// The enabled origins this page can run on: the Azure portal is enabled
// for the Sentinel scripts and runs no SPL, so it is not a Splunk instance
// whatever order the extension lists it in.
export function splunkOrigins(origins) {
  return (origins || []).filter((o) => !isPortalOrigin(o.origin));
}

// The origin the buttons arm on: the one the URL asked for only when the
// extension lists it as enabled, else the first enabled one, else none.
// ?env= is a prefill, never an authority; the relay refuses anything else
// anyway, and the button should not offer it.
export function pickOrigin(wanted, origins) {
  const mine = splunkOrigins(origins);
  if (wanted && mine.some((o) => o.origin === wanted)) return wanted;
  return mine.length ? mine[0].origin : null;
}

export function render(ctx) {
  const { catalogue } = ctx;
  const el = h("div", { class: "r-view r-view--discover" });

  const envLine = h("span", { class: "r-discover__env" }, "no Splunk instance enabled yet");
  const invBtn = h("button", { type: "button", class: "r-btn r-btn--primary", disabled: true }, "Inventory sourcetypes");
  const fullBtn = h("button", { type: "button", class: "r-btn", disabled: true, title: "Re-run the inventory, then profile, structure and decodes for every sourcetype it knows, one at a time. Cancel any time; the step in flight finishes." }, "Full discovery");
  el.appendChild(
    titleBlock({
      kind: "page",
      h1: "Discover",
      scope: [envLine, "runs searches in your open Splunk tab"],
      actions: [invBtn, fullBtn],
    }),
  );
  el.appendChild(
    h(
      "p",
      { class: "r-secondary" },
      "Ask your own Splunk what it carries. Each button runs one fixed reporting search in a Splunk tab you already have open, with that tab's session. Nothing is stored anywhere but this browser. Facts from here fill the catalogue; they never overwrite a description.",
    ),
  );

  if (!discovery.available()) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        callout({
          kind: "note",
          label: "Needs the extension",
          body: "Discovery talks to Splunk through the extension's content script, so it only works on the extension's own copy of this page. Open it from the Reach toolbar popup (Open the catalogue →). Served as a plain page, the catalogue is read-only apart from your notes.",
        }),
      ),
    );
    return el;
  }

  const status = h("p", { class: "r-secondary", "aria-live": "polite" });
  const envSel = h("select", { class: "r-input", style: { maxWidth: "360px" } });
  const indexIn = h("input", { class: "r-input", type: "text", placeholder: copy("discover.indexPlaceholder"), value: ctx.params.index || "", style: { maxWidth: "200px" } });
  const windowSel = h(
    "select",
    { class: "r-input", style: { maxWidth: "180px" } },
    ["-24h", "-7d", "-30d", "0"].map((w) => h("option", { value: w, selected: w === "-7d" }, w === "0" ? "all time" : `last ${w.slice(1)}`)),
  );
  const skipFresh = h("input", { type: "checkbox", checked: true });
  const skipFreshLabel = h("label", { class: "r-secondary r-nowrap" }, skipFresh, copy("discover.skipFresh"));
  const progress = h("p", { class: "r-secondary", "aria-live": "polite" });
  const resumeBtn = h("button", { type: "button", class: "r-btn r-btn--small", hidden: true }, "Resume");
  const results = h("div");

  let origins = [];
  let origin = ctx.params.env || null;

  async function refreshEnvs() {
    try {
      origins = splunkOrigins(await discovery.environments());
      status.textContent = origins.length
        ? ""
        : "No Splunk instance is enabled. Open a Splunk Web page, click the Reach toolbar icon and press “Enable on this Splunk instance”, then refresh here.";
    } catch (err) {
      status.textContent = `Could not reach the extension's background worker: ${err.message}`;
      origins = [];
    }
    origin = pickOrigin(origin, origins);
    // replaceChildren takes nodes, not an array; an array is stringified.
    envSel.replaceChildren(
      ...(origins.length
        ? origins.map((o) => h("option", { value: o.origin, selected: o.origin === origin }, `${o.origin}${o.tabs ? ` (${o.tabs} tab${o.tabs === 1 ? "" : "s"} open)` : " (no tab open)"}`))
        : [h("option", { value: "" }, "no Splunk instance enabled yet")]),
    );
    if (origin) envSel.value = origin;
    invBtn.disabled = !origin;
    envLine.textContent = origin || "no Splunk instance enabled yet";
    drawResults();
  }
  envSel.addEventListener("change", () => {
    origin = envSel.value || null;
    ctx.setUrl("discover", { ...ctx.params, env: origin || undefined });
    invBtn.disabled = !origin;
    envLine.textContent = origin || "no Splunk instance enabled yet";
    drawResults();
  });

  // What the layer's byte budget dropped on this write, for the status line.
  function noticeText(r) {
    return r && r.notice ? ` ${r.notice}` : "";
  }

  async function drawResults() {
    results.replaceChildren();
    discoveredHead.textContent = heading("discovered-sourcetypes", 0);
    if (!origin) return;
    const env = await layer.read(origin);
    const running = sweep.state().running;
    fullBtn.disabled = !running && !(env && env.inventory);
    if (!env || !Object.keys(env.sourcetypes || {}).length) {
      results.appendChild(h("p", { class: "r-muted" }, `Nothing discovered on ${origin} yet.`));
      return;
    }
    const sts = Object.entries(env.sourcetypes).sort(([a], [b]) => a.localeCompare(b));
    discoveredHead.textContent = heading("discovered-sourcetypes", sts.length);
    const rows = sts.map(([name, rec]) => {
      const cat = catalogue.sourcetype(name);
      const hl = discovery.health(rec);
      const profiled = rec.profiled_at ? `${Object.keys(rec.fields || {}).length} fields · sample ${rec.sample}` : "-";
      const moved = hl && hl.delta ? deltaLine(hl.delta) : null;
      const profBtn = h(
        "button",
        {
          type: "button",
          class: "r-btn r-btn--small",
          onClick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            btn.replaceChildren(spinner(), "profiling…");
            status.textContent = `Profiling ${name} on ${origin}…`;
            try {
              const idx = rec.indexes && rec.indexes.length ? rec.indexes : indexIn.value.trim() || "*";
              const r = await discovery.profile(origin, name, { index: idx, sample: 5000, earliest: windowSel.value === "0" ? "0" : windowSel.value });
              status.replaceChildren(`Profiled ${name}: ${r.fields} fields over ${r.total} sampled events. `, h("a", { href: `#/coverage?env=${encodeURIComponent(origin)}&st=${encodeURIComponent(name)}` }, "Coverage"), noticeText(r));
              const disc = (cat && cat.discriminator) || null;
              if (disc) {
                const rt = await discovery.recordTypes(origin, name, disc, { index: idx, earliest: windowSel.value === "0" ? "0" : windowSel.value });
                status.append(noticeText(rt));
              }
            } catch (err) {
              status.textContent = `Profile failed: ${err.message}`;
            }
            drawResults();
          },
        },
        rec.profiled_at ? "re-profile" : "profile fields",
      );
      const provBtn = h(
        "button",
        {
          type: "button",
          class: "r-btn r-btn--small",
          onClick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            btn.replaceChildren(spinner(), "reading…");
            status.textContent = `Reading props/transforms for ${name} on ${origin}…`;
            try {
              const r = await discovery.provenance(origin, name, { macros: macrosFor(name) });
              const c = r.counts;
              status.textContent = `Provenance for ${name}: ${r.fields} fields produced by ${c.aliases} aliases, ${c.calculated} calculated fields, ${c.lookups} lookups, ${c.extractions} extractions.${noticeText(r)}`;
              const base = status.textContent;
              const d = await discovery.decodes(origin, name, {
                force: Boolean(rec.decodes_at),
                onProgress: (p) => {
                  status.textContent = `${base} Decode tables: ${p.done}/${p.total} lookups read, ${p.tables} tables so far…`;
                },
              });
              status.textContent = `${base} Decode tables: ${d.tables} of ${d.candidates} single-key lookups read.${d.errors.length ? " " + d.errors.join("; ") : ""}${noticeText(d)}`;
            } catch (err) {
              status.textContent = `Provenance failed: ${err.message}`;
            }
            drawResults();
          },
        },
        rec.provenance_at ? "re-read structure" : "structure + decodes",
      );
      const structure = rec.provenance_at
        ? `${Object.values(rec.fields || {}).filter((f) => f.provenance).length} produced fields · ${Object.keys(rec.decodes || {}).length} decode tables`
        : "-";
      return {
        sourcetype: h("span", null, stLink(name), " ", cat ? sourceChips(cat.sources) : null),
        index: { mono: (rec.indexes || []).join(", ") || "-" },
        events: { text: rec.count ? rec.count.toLocaleString() : "-", align: "right" },
        first: { text: when(rec.first_seen) || "-", muted: true },
        last: h("span", null, h("span", { class: "r-muted" }, when(rec.last_seen) || "-"), " ", ...healthChips({ lastSeen: rec.last_seen, missingSince: rec.missing_since })),
        profile: h("span", null, h("span", { class: rec.profiled_at ? "" : "r-muted" }, profiled), moved ? h("span", null, " · ", moved) : null),
        structure: { text: structure, muted: !rec.provenance_at },
        action: h("span", { class: "r-stlist__src" }, profBtn, provBtn),
      };
    });
    results.appendChild(
      table({
        caption: `Discovered on ${origin}`,
        columns: [
          { key: "sourcetype", label: "sourcetype" },
          { key: "index", label: "index" },
          { key: "events", label: "events", align: "right" },
          { key: "first", label: "first seen" },
          { key: "last", label: "last seen" },
          { key: "profile", label: "profile" },
          { key: "structure", label: "structure" },
          { key: "action", label: "" },
        ],
        rows,
      }),
    );
    results.appendChild(
      h(
        "p",
        { class: "r-muted" },
        `Last discovery ${env.discovered_at ? new Date(env.discovered_at).toLocaleString() : "-"}${env.inventory ? `; last inventory ${new Date(env.inventory.at).toLocaleString()} over ${env.inventory.window === "0" ? "all time" : `the last ${String(env.inventory.window).replace(/^-/, "")}`} of index ${env.inventory.index}` : ""}${env.sweep ? `; last full discovery ${new Date(env.sweep.at).toLocaleString()}, ${env.sweep.done} of ${env.sweep.total} sourcetypes` : ""}. A sourcetype that inventory stops returning is kept and marked missing; re-profiling records what moved. `,
        h(
          "button",
          {
            type: "button",
            class: "r-btn r-btn--small",
            onClick: async () => {
              if (!window.confirm(`Forget everything discovered on ${origin}? Your notes are not affected.`)) return;
              await layer.forget(origin);
              drawResults();
            },
          },
          "forget this environment",
        ),
      ),
    );
  }

  invBtn.addEventListener("click", async () => {
    invBtn.disabled = true;
    invBtn.replaceChildren(spinner(), "Running inventory…");
    status.textContent = `Running inventory on ${origin}…`;
    try {
      const r = await discovery.inventory(origin, { index: indexIn.value.trim() || "*", earliest: windowSel.value === "0" ? "0" : windowSel.value });
      const n = Object.keys(r.env.sourcetypes).length;
      status.textContent = `Inventory: ${r.rows.length} index/sourcetype pair${r.rows.length === 1 ? "" : "s"}, ${n} sourcetype${n === 1 ? "" : "s"} known on ${origin}.${noticeText(r)}`;
      for (const m of r.messages || []) if (m.type === "ERROR" || m.type === "FATAL") status.textContent += ` Splunk said: ${m.text}`;
    } catch (err) {
      status.textContent = `Inventory failed: ${err.message}`;
    }
    invBtn.disabled = false;
    invBtn.textContent = "Inventory sourcetypes";
    drawResults();
  });


  // --- full discovery -----------------------------------------------------
  // The runner lives in discovery-sweep.js and outlives this view: a hash
  // navigation mid-sweep keeps it going, and coming back here picks the
  // live state up again. The view only reflects it and sends two
  // messages: start (or resume) and cancel.
  const windowValue = () => (windowSel.value === "0" ? "0" : windowSel.value);
  const discriminatorFor = (st) => {
    const cat = catalogue.sourcetype(st);
    return (cat && cat.discriminator) || null;
  };
  let lastDone = -1;

  function reflect(s) {
    const mine = s.origin === origin;
    const running = s.running && mine;
    fullBtn.replaceChildren(running ? "Cancel full discovery" : "Full discovery");
    fullBtn.classList.toggle("r-btn--danger", running);
    invBtn.disabled = running || !origin;
    skipFresh.disabled = running;
    if (running) {
      progress.replaceChildren(spinner(), " ", sweep.progressLine(s));
      resumeBtn.hidden = true;
      if (s.done !== lastDone) {
        lastDone = s.done;
        drawResults();
      }
      return;
    }
    if (mine && s.started_at) {
      progress.textContent = s.abort
        ? `Full discovery ${sweep.progressLine(s)}. ${s.abort}`
        : s.cancelled
          ? `Full discovery cancelled, ${sweep.progressLine(s)}.`
          : `Full discovery finished, ${sweep.progressLine(s)}.${s.errors.length ? " " + s.errors.map((e) => `${e.sourcetype || "inventory"} (${e.step}): ${e.error}`).join("; ") : ""}`;
      resumeBtn.hidden = !sweep.incomplete(s);
      drawResults();
      return;
    }
    showStopped();
  }

  // A page opened after a sweep stopped: what the store remembers.
  async function showStopped() {
    if (!origin) {
      progress.textContent = "";
      resumeBtn.hidden = true;
      return;
    }
    const rec = await sweep.load(origin);
    if (rec && sweep.incomplete(rec) && !sweep.state().running) {
      progress.textContent = `Full discovery stopped after ${rec.done} of ${rec.total}${rec.abort ? `: ${rec.abort}` : rec.cancelled ? " (cancelled)" : ""}.`;
      resumeBtn.hidden = false;
    } else {
      progress.textContent = "";
      resumeBtn.hidden = true;
    }
  }

  async function runSweep({ resume }) {
    if (!origin) return;
    lastDone = -1;
    status.textContent = "";
    try {
      await sweep.start(origin, { index: indexIn.value.trim() || "*", earliest: windowValue(), discriminatorFor, macrosFor, skipFresh: skipFresh.checked, skipMissing: true, resume });
    } catch (err) {
      status.textContent = `Full discovery failed: ${err.message}`;
    }
  }

  fullBtn.addEventListener("click", () => {
    if (sweep.state().running) sweep.cancel();
    else runSweep({ resume: false });
  });
  resumeBtn.addEventListener("click", () => runSweep({ resume: true }));

  // Reflect the live state while this view is on the page.
  el.unmount = sweep.subscribe(reflect);
  const reflectLater = () => reflect(sweep.state());
  envSel.addEventListener("change", reflectLater);

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("environment"),
      h("div", { class: "r-ann__actions" }, envSel, h("button", { type: "button", class: "r-btn r-btn--small", onClick: refreshEnvs }, "refresh")),
      h("p", { class: "r-secondary" }, "Instances you enabled from the toolbar popup. A tab on the instance has to be open for a search to run."),
    ),
  );
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("queries"),
      h("div", { class: "r-ann__actions" }, indexIn, windowSel, skipFreshLabel),
      h("p", { class: "r-secondary" }, "Inventory sourcetypes runs ", h("code", null, "| tstats count, min(_time), max(_time) where index=… by index, sourcetype"), ": cheap on any deployment; the index filter narrows it if you want. Full discovery runs that again, then every row's profile, structure and decodes, one sourcetype at a time: the same searches the row buttons run, listed before they start, cancellable between them."),
      status,
      h("div", { class: "r-ann__actions" }, progress, resumeBtn),
    ),
  );

  const discoveredHead = headingNode("discovered-sourcetypes", 0);
  el.appendChild(h("section", { class: "r-section" }, discoveredHead, results));

  el.afterMount = async () => {
    await refreshEnvs();
    reflect(sweep.state());
  };
  return el;
}

export default { render };
