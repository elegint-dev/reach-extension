// Discover on Sentinel: #/discover?env=<workspace resource id>
// The recipe (docs/SENTINEL.md §5): Reach writes the queries, the user runs
// them in the portal and brings the one result cell back. Each step is a
// link that opens the Logs blade with the query already run; the paste box
// below reads what comes back, works out which step it was from the
// envelope, and writes the discovered layer. Reach never touches the
// network from here. The user is the transport.
//
// "Copy all recipe queries" is the Sentinel side of Splunk's full
// discovery: every step's wrapped query in one text, so one Logs session
// runs them all (the editor runs the block the cursor is in) and the
// results come back one paste at a time. Reach still runs nothing.
//
//   copyAllText(steps, env, { label })  -> the text, exported for the test

import { titleBlock } from "../components/titleBlock.js";
import { headingNode, heading } from "../lib/headings.js";
import { stLink } from "../components/links.js";
import { h } from "../components/h.js";
import { callout } from "../components/callout.js";
import { table } from "../components/table.js";
import { chip } from "../components/chip.js";
import { healthChips, deltaLine } from "../components/health.js";
import * as recipe from "../lib/recipe.js";
import * as intake from "../lib/intake.js";
import * as packs from "../lib/packs.js";
import { TERMS } from "../lib/platform.js";
import { sourceChips } from "./catalogue.js";
import { copy } from "../lib/copy.js";
import { when } from "../lib/when.js";
import { copyText } from "../lib/runtime.js";
import * as searches from "../lib/searches.js";

export function statusChip(step) {
  if (step.status === "imported") return chip({ kind: "trust", value: "confirmed", text: copy("discover.imported", { when: when(step.imported_at) || "-", rows: step.rows }), title: `imported ${when(step.imported_at) || "-"}${step.imported_q ? `\n${step.imported_q}` : ""}` });
  if (step.status === "stale") return chip({ kind: "trust", value: "asserted", text: copy("discover.stale"), title: "stale: the query changed since this was imported" });
  return chip({ kind: "trust", value: "inferred", text: "pending" });
}

// One block per step: a numbered comment header, the step id the envelope
// carries, then the same wrapped query the row's copy button gives.
export function copyAllText(steps, env, { label } = {}) {
  return steps
    .map((s, i) => `// ${i + 1}. ${s.label}\n// reach step: ${s.id}\n${recipe.queryFor(s, env, { label }).kql}`)
    .join("\n\n");
}

export function render(ctx) {
  const { catalogue } = ctx;
  const el = h("div", { class: "r-view r-view--discover" });

  // The action row: the first step's portal link and the whole batch as
  // one copy; both are bound once the recipe for the chosen workspace is
  // drawn, and read what draw() left in `batch` at click time.
  const envLine = h("span", { class: "r-discover__env" }, `no ${TERMS.env} known yet`);
  const openFirst = h("a", { class: "r-btn r-btn--primary", href: "#", target: "_blank", rel: "noopener", title: "Opens the Logs blade on this workspace with step 1 already run" }, "Open step 1 ↗");
  openFirst.addEventListener("click", (e) => {
    if (openFirst.getAttribute("href") === "#") e.preventDefault();
  });
  let batch = [];
  const copyAll = h("button", { type: "button", class: "r-btn", disabled: true, title: "Every query, one block each, to run in one Logs session", onClick: (e) => { const text = copyAllText(batch, env, { label: (env && env.label) || (meta && meta.name) }); copyText(text, e.currentTarget, "copied ✓"); searches.record({ text, platform: "sentinel", source: "copy", origin: "discovery", name: "every recipe query" }).catch(() => {}); } }, "Copy all queries");
  el.appendChild(
    titleBlock({
      kind: "page",
      h1: "Discover",
      scope: [envLine, "you run each KQL and paste the cell back"],
      actions: [openFirst, copyAll],
    }),
  );
  el.appendChild(
    h(
      "p",
      { class: "r-secondary" },
      `Ask your own ${TERMS.env} what it carries, by hand. Each step below is one KQL query Reach has written. Open it in the portal (it runs on arrival), right-click the single result cell → Copy value, and paste it here. Reach reads which step it was off the result itself. Facts from here fill the catalogue; they never overwrite a description.`,
    ),
  );

  const status = h("p", { class: "r-secondary", "aria-live": "polite" });
  const envSel = h("select", { class: "r-input", style: { maxWidth: "420px" } });
  const addIn = h("input", { class: "r-input", type: "text", placeholder: copy("discover.resourceId"), style: { maxWidth: "520px" } });
  const addBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, "add workspace");
  const stepsBox = h("div");
  const tablesBox = h("div");
  const proposalsBox = h("div");

  let envs = [];
  let key = ctx.params.env || null;
  let env = null; // the discovered-layer record for `key` (may be null)
  let meta = null; // the environments() entry

  const packTables = () => packs.list().flatMap((p) => p.sourcetypes);
  // Tables the packs bind every column the fleet baseline query reads on;
  // the baseline step itself is not shown here (it lives on the sourcetype
  // page), but a pasted result still has to resolve against a known step id.
  const falconTables = () => packTables().filter((t) => {
    const cols = catalogue.fieldsOn(t);
    return recipe.ORG_CORPUS_COLUMNS_NEEDED.every((c) => cols.includes(c));
  });

  async function refreshEnvs() {
    try {
      envs = await recipe.environments();
    } catch (err) {
      status.textContent = `Could not read the workspace list: ${err.message}`;
      envs = [];
    }
    if (!key && envs.length) key = envs[0].key;
    if (key && !envs.some((e) => e.key === key)) key = envs.length ? envs[0].key : null;
    envSel.replaceChildren(
      ...(envs.length
        ? envs.map((e) => h("option", { value: e.key, selected: e.key === key }, `${e.name}${e.label && e.label !== e.name ? ` (${e.label})` : ""}: ${e.tables} ${e.tables === 1 ? TERMS.sourcetype : TERMS.sourcetypes}${e.seen_at ? ", seen in the portal" : ""}`))
        : [h("option", { value: "" }, `no ${TERMS.env} known yet`)]),
    );
    if (key) envSel.value = key;
    const chosen = envs.find((e) => e.key === key);
    envLine.textContent = chosen ? chosen.name : `no ${TERMS.env} known yet`;
    await draw();
  }

  envSel.addEventListener("change", async () => {
    key = envSel.value || null;
    ctx.setUrl("discover", { ...ctx.params, env: key || undefined });
    await draw();
  });

  addBtn.addEventListener("click", async () => {
    const rid = addIn.value.trim();
    if (!rid) return;
    try {
      const added = await recipe.addEnvironment(rid);
      addIn.value = "";
      key = added.key;
      status.textContent = `Added ${added.label}.`;
      await refreshEnvs();
    } catch (err) {
      status.textContent = err.message;
    }
  });

  function stepRow(step) {
    const actions = h("span", { class: "r-stlist__src" });
    const open = h("a", { class: "r-btn r-btn--small", href: "#", target: "_blank", rel: "noopener", title: meta && meta.resourceId ? "Opens the Logs blade on this workspace with the query already run" : "Add the workspace's resource id above to get a link" }, copy("discover.openPortal"));
    const copyBtn = h("button", { type: "button", class: "r-btn r-btn--small", title: "The wrapped query, to paste into the editor yourself" }, copy("discover.copyKql"));
    const show = h("button", { type: "button", class: "r-btn r-btn--small" }, "show");
    const pre = h("pre", { class: "r-pre", hidden: true, style: { whiteSpace: "pre-wrap", fontSize: "11.5px", marginTop: "6px" } });
    recipe
      .linkFor(step, env, { resourceId: meta && meta.resourceId, label: (env && env.label) || (meta && meta.name) })
      .then((link) => {
        pre.textContent = link.kql;
        const note = (source) => searches.record({ text: link.kql, platform: "sentinel", source, origin: "discovery", name: step.label }).catch(() => {});
        if (link.url) {
          open.href = link.url;
          open.addEventListener("click", () => note("open"));
        } else {
          open.style.opacity = "0.5";
          open.addEventListener("click", (e) => e.preventDefault());
        }
        copyBtn.addEventListener("click", (e) => {
          copyText(link.kql, e.currentTarget, "copied ✓");
          note("copy");
        });
      })
      .catch((err) => {
        pre.textContent = err.message;
      });
    show.addEventListener("click", () => {
      pre.hidden = !pre.hidden;
      show.textContent = pre.hidden ? "show" : "hide";
    });
    actions.append(open, copyBtn, show);
    return h(
      "div",
      { class: "r-stlist__row" },
      h("div", { class: "r-stlist__name" }, h("span", null, step.label), h("p", { class: "r-secondary" }, h("code", null, step.id), " · ", statusChip(step)), pre),
      h("div", { class: "r-stlist__meta" }),
      actions,
    );
  }

  async function draw() {
    try {
      await drawInner();
    } catch (err) {
      status.textContent = `Could not draw the recipe: ${err.message}`;
      console.error(err);
    }
  }

  async function drawInner() {
    stepsBox.replaceChildren();
    tablesBox.replaceChildren();
    proposalsBox.replaceChildren();
    tablesHead.textContent = heading("discovered-sourcetypes", 0);
    batch = [];
    copyAll.disabled = true;
    openFirst.setAttribute("href", "#");
    if (!key) {
      stepsBox.appendChild(
        callout({
          kind: "note",
          label: `No ${TERMS.env} yet`,
          body: "Open the Logs blade on a workspace in the Azure portal with Reach enabled (the workspace is remembered here), or paste its resource id above.",
        }),
      );
      return;
    }
    env = await recipe.environment(key);
    meta = envs.find((e) => e.key === key) || null;
    const inventoried = env && Object.values(env.sourcetypes || {}).some((r) => r.inventoried_at);
    const steps = recipe.steps(env, { packTables: inventoried ? [] : packTables() });
    stepsBox.appendChild(h("div", { class: "r-stlist" }, steps.map(stepRow)));
    batch = steps.slice(); // the per-table steps join below, once the tables are known
    copyAll.disabled = !steps.length;
    if (steps.length) recipe.linkFor(steps[0], env, { resourceId: meta && meta.resourceId, label: (env && env.label) || (meta && meta.name) }).then((link) => { if (link.url) openFirst.href = link.url; }).catch(() => {});
    stepsBox.appendChild(h("p", { class: "r-secondary" }, "Copy all queries, above, takes every query here and every table's profile and record types as one block each: paste the lot into one Logs editor; it runs the block the cursor is in. Bring each result back below, in any order."));
    if (!inventoried) stepsBox.appendChild(h("p", { class: "r-muted" }, `Until the inventory is imported, the schema step names the ${TERMS.sourcetypes} the loaded packs know. A ${TERMS.sourcetype} that does not exist in this ${TERMS.env} makes that query fail in the portal. Import the inventory first, or remove it from the batch by hand.`));

    // Tables: inventoried, profiled, or pack-known.
    const names = recipe.knownTables(env, { packTables: packTables() });
    tablesHead.textContent = heading("discovered-sourcetypes", names.length);
    if (!names.length) {
      tablesBox.appendChild(h("p", { class: "r-muted" }, `Nothing known about this ${TERMS.env} yet. Import the inventory.`));
    } else {
      const rows = names.map((name) => {
        const rec = (env && env.sourcetypes && env.sourcetypes[name]) || null;
        const cat = catalogue.sourcetype(name);
        const disc = (rec && rec.discriminator) || (cat && cat.discriminator) || (rec && rec.proposed_discriminator) || null;
        const tsteps = recipe.tableSteps(env, name, { discriminator: disc });
        batch.push(...tsteps);
        const per = h("div", { class: "r-stlist__src" });
        for (const s of tsteps) {
          const a = h("a", { class: "r-btn r-btn--small", href: "#", target: "_blank", rel: "noopener", title: `${s.label}\n${s.status === "imported" ? `imported ${when(s.imported_at) || "-"}` : s.status}` }, `${s.step === "profile" ? "profile" : copy("discover.recordTypesBy", { column: s.params.column })} ↗${s.status === "imported" ? " ✓" : ""}`);
          recipe.linkFor(s, env, { resourceId: meta && meta.resourceId, label: (env && env.label) || (meta && meta.name) }).then((link) => {
            if (link.url) a.href = link.url;
            else { a.style.opacity = "0.5"; a.addEventListener("click", (e) => e.preventDefault()); }
          }).catch(() => {});
          per.appendChild(a);
        }
        const profiled = rec && rec.profiled_at ? `${Object.values(rec.fields || {}).filter((f) => f.profile).length} ${TERMS.fields} · sample ${rec.sample}` : "-";
        // The delta between the two profiles pasted last, as on Splunk between runs.
        const moved = rec && rec.profile_delta && (rec.profile_delta.added.length || rec.profile_delta.gone.length || rec.profile_delta.fill.length) ? deltaLine(rec.profile_delta) : null;
        const declared = rec && rec.schema_at ? `${Object.values(rec.fields || {}).filter((f) => f.declared).length} declared` : "-";
        const discCell = rec && rec.record_types
          ? h("span", null, h("code", null, rec.discriminator), ` · ${rec.record_types.length} values`)
          : disc
            ? h("span", { class: "r-muted" }, h("code", null, disc), rec && rec.proposed_discriminator === disc && !(cat && cat.discriminator) ? " (proposed)" : "")
            : h("span", { class: "r-muted" }, "-");
        return {
          table: h("span", null, stLink(name), " ", cat ? sourceChips(cat.sources) : null),
          volume: { text: rec && rec.mb !== undefined ? `${rec.mb} MB` : rec && rec.count ? `${rec.count.toLocaleString()} rows` : "-", align: "right", muted: !rec },
          seen: h("span", null, h("span", { class: "r-muted" }, rec && rec.last_seen ? `${when(rec.first_seen) || "-"} → ${when(rec.last_seen) || "-"}` : "-"), " ", ...healthChips(rec ? { lastSeen: rec.last_seen, missingSince: rec.missing_since } : null)),
          schema: { text: declared, muted: !(rec && rec.schema_at) },
          profile: h("span", null, h("span", { class: rec && rec.profiled_at ? "" : "r-muted" }, profiled), moved ? h("span", null, " · ", moved) : null),
          types: discCell,
          action: per,
        };
      });
      tablesBox.appendChild(
        table({
          caption: `${TERMS.Sourcetypes} on ${meta ? meta.name : key}`,
          columns: [
            { key: "table", label: TERMS.sourcetype },
            { key: "volume", label: "volume", align: "right" },
            { key: "seen", label: "first → last seen" },
            { key: "schema", label: "schema" },
            { key: "profile", label: "profile" },
            { key: "types", label: "record types" },
            { key: "action", label: "" },
          ],
          rows,
        }),
      );
    }

    const proposals = env ? recipe.proposeEdges(env) : [];
    if (proposals.length) {
      proposalsBox.appendChild(headingNode("join-leads"));
      proposalsBox.appendChild(h("p", { class: "r-secondary" }, `Two ${TERMS.sourcetypes} sharing a ${TERMS.field} name, the same runtime type and overlapping top values. Proposed by discovery, not confirmed: a lead for a pack edge, not one.`));
      proposalsBox.appendChild(
        table({
          columns: [{ key: "a", label: "from" }, { key: "b", label: "to" }, { key: "type", label: "type" }, { key: "overlap", label: "shared top values", align: "right" }],
          rows: proposals.slice(0, 40).map((p) => ({
            a: h("span", null, stLink(p.src.sourcetype), ".", h("code", null, p.src.field)),
            b: h("span", null, stLink(p.dst.sourcetype), ".", h("code", null, p.dst.field)),
            type: { mono: p.type },
            overlap: { text: String(p.overlap), align: "right" },
          })),
        }),
      );
    }

    tablesBox.appendChild(
      h(
        "p",
        { class: "r-muted" },
        `Last import ${when(env && env.discovered_at) || "-"}. `,
        h(
          "button",
          {
            type: "button",
            class: "r-btn r-btn--small",
            onClick: async () => {
              if (!window.confirm(`Forget everything discovered on ${meta ? meta.name : key}? Your notes are not affected.`)) return;
              await recipe.forget(key);
              key = null;
              await refreshEnvs();
            },
          },
          `forget this ${TERMS.env}`,
        ),
      ),
    );
  }

  // --- intake -------------------------------------------------------------------
  const pasteIn = h("textarea", { class: "r-input", rows: 6, placeholder: "Paste the result cell (Copy value), or the exported CSV, or drop the file here.", style: { fontFamily: "ui-monospace, Menlo, monospace", fontSize: "11.5px" } });
  const fileIn = h("input", { type: "file", accept: ".csv,.json,.txt,text/csv,application/json,text/plain", class: "r-input", style: { maxWidth: "320px" } });
  const importBtn = h("button", { type: "button", class: "r-btn r-btn--primary" }, "Import");
  const stepSel = h("select", { class: "r-input", style: { maxWidth: "260px" } }, h("option", { value: "" }, "step (only for a plain export)"), recipe.STEPS.map((s) => h("option", { value: s }, s)));
  const tableIn = h("input", { class: "r-input", type: "text", placeholder: `${TERMS.sourcetype} (profile / record types)`, style: { maxWidth: "260px" } });
  const columnIn = h("input", { class: "r-input", type: "text", placeholder: `${TERMS.field} (record types)`, style: { maxWidth: "220px" } });
  const intakeStatus = h("p", { class: "r-secondary", "aria-live": "polite" });

  async function readFile(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result || ""));
      r.onerror = () => reject(r.error || new Error("could not read the file"));
      r.readAsText(file);
    });
  }

  pasteIn.addEventListener("dragover", (e) => { e.preventDefault(); });
  pasteIn.addEventListener("drop", async (e) => {
    e.preventDefault();
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) pasteIn.value = await readFile(f);
  });
  fileIn.addEventListener("change", async () => {
    const f = fileIn.files && fileIn.files[0];
    if (f) pasteIn.value = await readFile(f);
  });

  importBtn.addEventListener("click", async () => {
    if (!key) {
      intakeStatus.textContent = `Pick a ${TERMS.env} first.`;
      return;
    }
    const text = pasteIn.value;
    if (!text.trim()) {
      intakeStatus.textContent = "Nothing to import.";
      return;
    }
    importBtn.disabled = true;
    try {
      const parsed = intake.parse(text);
      let expect = null;
      let opts = {};
      if (parsed.kind === "envelope") {
        // The fleet baseline step is not drawn here (it lives on the sourcetype
        // page); a pasted result still has to resolve against its step id.
        const all = [...recipe.steps(env, { packTables: packTables() }), ...recipe.orgCorpusSteps(env, { falconTables: falconTables() })];
        const t = parsed.params && parsed.params.table;
        if (t) all.push(...recipe.tableSteps(env, String(t), { discriminator: parsed.params.column || null }));
        expect = all.find((s) => s.id === recipe.stepId(parsed.step, parsed.params)) || null;
      } else {
        const step = stepSel.value;
        if (!step) throw new Error("A plain export carries no step identity. Pick the step it came from.");
        const params = {};
        if (tableIn.value.trim()) params.table = tableIn.value.trim();
        if (columnIn.value.trim()) params.column = columnIn.value.trim();
        opts = { step, params };
      }
      const r = await recipe.apply(key, parsed, { ...opts, expect });
      const w = r.written || {};
      const summary = Object.entries(w).map(([k, v]) => `${k} ${v}`).join(", ");
      intakeStatus.replaceChildren(`Imported ${r.step}${summary ? ` (${summary})` : ""}.${r.verdicts.length ? " " + r.verdicts.join("; ") + "." : ""}${r.notice ? ` ${r.notice}` : ""}`, ...(r.step === "profile" ? [" ", h("a", { href: `#/coverage?env=${encodeURIComponent(key)}${r.table ? `&st=${encodeURIComponent(r.table)}` : ""}` }, "Coverage")] : []));
      pasteIn.value = "";
      await draw();
    } catch (err) {
      intakeStatus.textContent = `Import failed: ${err.message}`;
    } finally {
      importBtn.disabled = false;
    }
  });

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("environment"),
      h("div", { class: "r-ann__actions" }, envSel, h("button", { type: "button", class: "r-btn r-btn--small", onClick: refreshEnvs }, "refresh")),
      h("p", { class: "r-secondary" }, "Workspaces Reach has seen the Logs blade open on, with the extension enabled in the portal. Or add one by its resource id:"),
      h("div", { class: "r-ann__actions" }, addIn, addBtn),
      status,
    ),
  );
  el.appendChild(h("section", { class: "r-section" }, headingNode("queries"), stepsBox));
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("pasted-results"),
      h("p", { class: "r-secondary" }, "Right-click the one result cell in the portal → Copy value, and paste. Or Export → CSV (all columns) and drop the file. A plain export of some other query works too, if you say which step it stands in for."),
      pasteIn,
      h("div", { class: "r-ann__actions" }, fileIn, stepSel, tableIn, columnIn, importBtn),
      intakeStatus,
    ),
  );
  const tablesHead = headingNode("discovered-sourcetypes", 0);
  el.appendChild(h("section", { class: "r-section" }, tablesHead, tablesBox));
  el.appendChild(h("section", { class: "r-section" }, proposalsBox));

  el.afterMount = refreshEnvs;
  return el;
}

export default { render, copyAllText, statusChip };
