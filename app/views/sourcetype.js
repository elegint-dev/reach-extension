// Sourcetype page: #/st/<name>?role=<role>&q=<filter>
// What a sourcetype is, which record types it carries, and every field on
// it with whether anyone has described it yet. The unit of the catalogue.
//
// Title block: the name, the source and health chips, the scope line
// (fields, described, the record-type field, the index), then the action
// row. Sections in the entity master order: Meaning, Field changes (N),
// Workflows (Splunk), Record types (N), Fields (N).

import { h, spinner } from "../components/h.js";
import { fieldLink, eventLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { sourcetypeAnnotation } from "../components/annotation.js";
import { TERMS, isSentinel } from "../lib/platform.js";
import { isStacked } from "../lib/surface.js";
import { sourceChips } from "./catalogue.js";
import { fillBadge } from "../components/profile.js";
import { provenanceLine } from "../components/provenance.js";
import { healthChips, deltaBlock } from "../components/health.js";
import { ageLabel } from "../lib/discovery.js";
import * as discovery from "../lib/discovery.js";
import * as recipe from "../lib/recipe.js";
import { splunkOrigins, pickOrigin } from "./discover-splunk.js";
import { statusChip as sentinelStatusChip } from "./discover-sentinel.js";
import * as workflows from "../lib/workflows.js";
import * as modules from "../lib/modules.js";
import { oneLiner } from "../lib/values.js";
import { referenceLine } from "../components/dictionary.js";
import { copy } from "../lib/copy.js";
import { copyText } from "../lib/runtime.js";
import { when } from "../lib/when.js";

const FOLD_OPEN_MAX = 40;
const WINDOW_OPTIONS = ["-24h", "-7d", "-30d", "0"];

// Whether this sourcetype (Splunk) or table (Sentinel) is the one the
// fleet baseline measures: the FDR sourcetype by name on Splunk; on
// Sentinel, a real KQL table (not the pack's colon-bearing container
// name) whose known fields cover the columns the baseline query reads.
export function isFleetBaselineTable(name, { catalogue, sentinel = isSentinel() } = {}) {
  if (!name) return false;
  if (!sentinel) return name === discovery.ORG_CORPUS_SOURCETYPE;
  const cols = catalogue && catalogue.fieldsOn ? catalogue.fieldsOn(name) : [];
  if (!recipe.ORG_CORPUS_COLUMNS_NEEDED.every((c) => cols.includes(c))) return false;
  return recipe.orgCorpusTables({ sourcetypes: {} }, { falconTables: [name] }).includes(name);
}

function windowLabel(w) {
  return w === "0" ? "all time" : `last ${w.slice(1)}`;
}

// What the Discover page used to print once a fleet baseline existed, now
// read back beside the control that runs it: one line per environment
// that has measured one.
function baselineSummary(catalogue) {
  const corpora = catalogue && catalogue.orgCorpora ? catalogue.orgCorpora() : [];
  if (!corpora.length) return h("p", { class: "r-muted" }, "No fleet baseline yet.");
  return h(
    "div",
    null,
    corpora.map((c) => {
      const doc = c.doc;
      const scope = doc.index ? `index ${doc.index}` : doc.table ? `table ${doc.table}` : "";
      const win = doc.window === "0" ? "all time" : doc.window ? `the last ${String(doc.window).replace(/^-/, "")}` : "-";
      return h(
        "p",
        { class: "r-secondary" },
        `${doc.kept.toLocaleString()} process binaries (hash, path, signing id) across your mac and windows hosts, measured ${when(doc.at) || "-"} over ${win}${scope ? ` of ${scope}` : ""}${doc.pruned ? `; ${doc.pruned.toLocaleString()} less widespread rows cut to the byte budget` : ""}.`,
      );
    }),
  );
}

// Splunk: the same one-click search Discover used to run, moved here; the
// index prefills from what this sourcetype is already known to live in.
function splunkBaselineControl(rec, catalogue) {
  const status = h("p", { class: "r-secondary", "aria-live": "polite" });
  const envSel = h("select", { class: "r-input", style: { maxWidth: "320px" } });
  const indexIn = h("input", { class: "r-input", type: "text", placeholder: copy("discover.indexPlaceholder"), value: rec && rec.indexes && rec.indexes.length ? rec.indexes.join(",") : "", style: { maxWidth: "200px" } });
  const windowSel = h("select", { class: "r-input", style: { maxWidth: "180px" } }, WINDOW_OPTIONS.map((w) => h("option", { value: w, selected: w === "-30d" }, windowLabel(w))));
  const runBtn = h("button", { type: "button", class: "r-btn r-btn--primary", disabled: true }, "Run");
  const summary = h("div", null, baselineSummary(catalogue));
  let origins = [];
  let origin = null;

  function drawSummary() {
    summary.replaceChildren(baselineSummary(catalogue));
  }

  async function refresh() {
    try {
      origins = splunkOrigins(await discovery.environments());
      status.textContent = origins.length ? "" : "No Splunk instance is enabled. Open a Splunk Web page, click the Reach toolbar icon and press “Enable on this Splunk instance”, then refresh here.";
    } catch (err) {
      status.textContent = `Could not reach the extension's background worker: ${err.message}`;
      origins = [];
    }
    origin = pickOrigin(origin, origins);
    envSel.replaceChildren(
      ...(origins.length
        ? origins.map((o) => h("option", { value: o.origin, selected: o.origin === origin }, `${o.origin}${o.tabs ? ` (${o.tabs} tab${o.tabs === 1 ? "" : "s"} open)` : " (no tab open)"}`))
        : [h("option", { value: "" }, "no Splunk instance enabled yet")]),
    );
    if (origin) envSel.value = origin;
    runBtn.disabled = !origin;
    drawSummary();
  }
  envSel.addEventListener("change", () => {
    origin = envSel.value || null;
    runBtn.disabled = !origin;
  });
  runBtn.addEventListener("click", async () => {
    runBtn.disabled = true;
    runBtn.replaceChildren(spinner(), "Running…");
    status.textContent = `Measuring the fleet's process binaries on ${origin}…`;
    try {
      const r = await discovery.orgCorpus(origin, { index: indexIn.value.trim() || "*", earliest: windowSel.value === "0" ? "0" : windowSel.value });
      status.textContent = `Fleet baseline: ${r.doc.kept.toLocaleString()} process binaries kept${r.doc.pruned ? `, ${r.doc.pruned.toLocaleString()} cut to the byte budget` : ""}, from ${r.rows.length.toLocaleString()} rows on ${origin}.${r.notice ? ` ${r.notice}` : ""}`;
      for (const m of r.messages || []) if (m.type === "ERROR" || m.type === "FATAL") status.textContent += ` Splunk said: ${m.text}`;
    } catch (err) {
      status.textContent = `Fleet baseline failed: ${err.message}`;
    }
    runBtn.disabled = !origin;
    runBtn.textContent = "Run";
    drawSummary();
  });

  const el = h(
    "div",
    null,
    h(
      "p",
      { class: "r-secondary" },
      `One search over the Falcon process events of your mac and windows hosts (${discovery.ORG_CORPUS_SOURCETYPE}, the index and window below): per hash, image path and signing id, how many hosts ran it and when it was first and last seen. Scans every process event in the window; the known-good verdict reads it back as "seen on N of your hosts".`,
    ),
    h("div", { class: "r-ann__actions" }, envSel, indexIn, windowSel, runBtn),
    status,
    summary,
  );
  return { el, refresh };
}

// Sentinel: the recipe step's own card (portal link, copy KQL), moved off
// Discover; the user still brings the one result cell back on Discover's
// own paste importer, which resolves it the same way (recipe.orgCorpusSteps).
function sentinelBaselineControl(name, catalogue) {
  const status = h("p", { class: "r-secondary", "aria-live": "polite" });
  const envSel = h("select", { class: "r-input", style: { maxWidth: "360px" } });
  const cardBox = h("div");
  const summary = h("div", null, baselineSummary(catalogue));
  let envs = [];
  let key = null;

  async function drawCard() {
    cardBox.replaceChildren();
    if (!key) {
      cardBox.appendChild(h("p", { class: "r-muted" }, `No ${TERMS.env} known yet. Open the Logs blade with Reach enabled, or add one on Discover.`));
      return;
    }
    const env = await recipe.environment(key);
    const meta = envs.find((e) => e.key === key) || null;
    const steps = recipe.orgCorpusSteps(env, { falconTables: [name] }).filter((s) => s.params.table === name);
    if (!steps.length) {
      cardBox.appendChild(h("p", { class: "r-muted" }, `${name} is not yet known as a real table on ${meta ? meta.name : key}. Import the schema on Discover, or bind this concept to the table that carries it.`));
      return;
    }
    const step = steps[0];
    const open = h("a", { class: "r-btn r-btn--small", href: "#", target: "_blank", rel: "noopener" }, copy("discover.openPortal"));
    const copyBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, copy("discover.copyKql"));
    const show = h("button", { type: "button", class: "r-btn r-btn--small" }, "show");
    const pre = h("pre", { class: "r-pre", hidden: true, style: { whiteSpace: "pre-wrap", fontSize: "11.5px", marginTop: "6px" } });
    recipe
      .linkFor(step, env, { resourceId: meta && meta.resourceId, label: (env && env.label) || (meta && meta.name) })
      .then((link) => {
        pre.textContent = link.kql;
        if (link.url) {
          open.href = link.url;
        } else {
          open.style.opacity = "0.5";
          open.addEventListener("click", (e) => e.preventDefault());
        }
        copyBtn.addEventListener("click", (e) => copyText(link.kql, e.currentTarget, "copied ✓"));
      })
      .catch((err) => {
        pre.textContent = err.message;
      });
    show.addEventListener("click", () => {
      pre.hidden = !pre.hidden;
      show.textContent = pre.hidden ? "show" : "hide";
    });
    cardBox.appendChild(
      h(
        "div",
        { class: "r-stlist__row" },
        h("div", { class: "r-stlist__name" }, h("span", null, step.label), h("p", { class: "r-secondary" }, h("code", null, step.id), " · ", sentinelStatusChip(step)), pre),
        h("span", { class: "r-stlist__src" }, open, copyBtn, show),
      ),
    );
    cardBox.appendChild(h("p", { class: "r-secondary" }, "Right-click the one result cell in the portal → Copy value, and paste it back on ", h("a", { href: `#/discover?env=${encodeURIComponent(key)}` }, "Discover"), "."));
  }

  async function refresh() {
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
        ? envs.map((e) => h("option", { value: e.key, selected: e.key === key }, `${e.name}${e.label && e.label !== e.name ? ` (${e.label})` : ""}`))
        : [h("option", { value: "" }, `no ${TERMS.env} known yet`)]),
    );
    if (key) envSel.value = key;
    summary.replaceChildren(baselineSummary(catalogue));
    await drawCard();
  }
  envSel.addEventListener("change", async () => {
    key = envSel.value || null;
    await drawCard();
  });

  const el = h(
    "div",
    null,
    h(
      "p",
      { class: "r-secondary" },
      "One KQL query over the Falcon process events of your mac and windows hosts, per hash, path and signing id: how many hosts ran it and when it was first and last seen. Open it in the portal, or copy it; paste the one result cell back on Discover.",
    ),
    h("div", { class: "r-ann__actions" }, envSel),
    status,
    cardBox,
    summary,
  );
  return { el, refresh };
}

// When discovery last measured this sourcetype, or that it never did: the
// silence between stopped and unmeasured is the chip's job to break.
export function measuredChip(rec, { discoverHref = null, now = Date.now() } = {}) {
  if (rec && rec.profiledAt) {
    const at = new Date(rec.profiledAt).getTime();
    const age = Number.isFinite(at) ? Math.max(0, Math.round((now - at) / 1000)) : null;
    return chip({ kind: "trust", value: "inferred", text: `measured ${age === null ? rec.profiledAt : ageLabel(age)}`, title: `profiled ${new Date(rec.profiledAt).toLocaleString()}` });
  }
  if (rec && (rec.lastSeen || rec.missingSince)) return null;
  const title = `Discovery has not measured this ${TERMS.sourcetype}: no health, no fill, no record-type counts.`;
  if (discoverHref) return h("a", { class: "r-chip r-chip--state r-chip--link", href: discoverHref, title }, "not measured");
  return h("span", { class: "r-chip r-chip--state", title }, "not measured");
}

// The record types on this sourcetype: what the pack knows, what discovery
// counted, or both, in one list. A pack event links to its page while the
// event route is mounted.
export function recordTypes(rec, events, { eventRoute = true } = {}) {
  const counts = new Map((rec.recordTypes || []).map((t) => [t.value, t.count]));
  const names = new Set([...events, ...counts.keys()]);
  const known = new Set(events);
  const all = Array.from(names).sort((a, b) => (counts.get(b) || 0) - (counts.get(a) || 0) || a.localeCompare(b));
  return {
    total: all.length,
    counted: counts.size > 0,
    rows: all.map((name) => ({ name, count: counts.has(name) ? counts.get(name) : null, link: known.has(name) && eventRoute })),
  };
}

export function render(ctx) {
  const { catalogue } = ctx;
  const name = ctx.params.name;
  const rec = catalogue.sourcetype(name);
  const el = h("div", { class: "r-view r-view--sourcetype" });
  const routes = new Set(ctx.modules ? ctx.modules.routes() : modules.routes());
  const stacked = isStacked();

  const editor = sourcetypeAnnotation({ record: rec || { name }, catalogue, onSaved: () => ctx.navigate("sourcetype", { name }) });
  const describe = h("button", { type: "button", class: "r-btn", onClick: () => editor.edit() }, "Describe");
  const discover = routes.has("discover") ? h("a", { class: "r-btn", href: "#/discover" }, "Discover") : null;

  if (!rec) {
    el.appendChild(
      titleBlock({
        kind: "sourcetype",
        h1: name,
        chips: [h("span", { class: "r-chip r-chip--state" }, "not in the catalogue")],
        scope: [`nothing in the catalogue knows this ${TERMS.sourcetype} yet`],
        actions: [describe, discover],
      }),
    );
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        headingNode("meaning"),
        h("p", { class: "r-secondary" }, "Describe it to start, or run ", h("a", { href: "#/discover" }, "discovery"), ` against your ${TERMS.env} to fill in its ${TERMS.fields}.`),
        editor,
      ),
    );
    return el;
  }

  const fields = catalogue.fieldsOn(name);
  const views = new Map(fields.map((f) => [f, catalogue.fieldOn(name, f)]));
  const described = fields.filter((f) => views.get(f) && views.get(f).meaning.description);
  const events = ctx.fields.sourcetypes().includes(name) ? ctx.fields.eventsOn(name) : [];
  const bindHref = `#/coverage?st=${encodeURIComponent(name)}`;
  const bind = routes.has("coverage") ? h("a", { class: "r-btn", href: bindHref }, `Bind ${TERMS.fields}`) : null;
  // The fleet baseline that feeds the known-good verdict: only on the one
  // sourcetype (Splunk) or table (Sentinel) it measures, and only while
  // the verdicts module is on.
  const isBaselineTable = modules.on("verdicts") && isFleetBaselineTable(name, { catalogue });
  const baseline = isBaselineTable
    ? h(
        "button",
        { type: "button", class: "r-btn", onClick: () => { const s = el.querySelector("#fleet-baseline"); if (s) s.scrollIntoView({ block: "start" }); } },
        "Baseline: what my fleet runs",
      )
    : null;

  el.appendChild(
    titleBlock({
      kind: "sourcetype",
      h1: name,
      chips: [sourceChips(rec.sources), ...healthChips(rec), measuredChip(rec, { discoverHref: routes.has("discover") ? "#/discover" : null })],
      // Two lines at 320: the record-type field beside the count, the
      // described count and the index on the second.
      scope: [
        `${fields.length.toLocaleString("en-US")} ${fields.length === 1 ? TERMS.field : TERMS.fields}`,
        rec.discriminator ? h("span", null, "record type ", h("code", null, rec.discriminator)) : null,
        h("span", { title: `${described.length} carry a description from a pack, a note of yours or discovery` }, `${described.length.toLocaleString("en-US")} described`),
        rec.indexes && rec.indexes.length ? h("span", null, `${TERMS.index} `, h("code", null, rec.indexes.join(", "))) : null,
      ],
      actions: [describe, discover, bind, baseline],
    }),
  );

  el.appendChild(h("section", { class: "r-section" }, headingNode("meaning"), editor, referenceLine({ sourcetype: name, packId: rec.packId, catalogue })));

  if (isBaselineTable) {
    const ctrl = isSentinel() ? sentinelBaselineControl(name, catalogue) : splunkBaselineControl(rec, catalogue);
    el.appendChild(h("section", { class: "r-section", id: "fleet-baseline" }, headingNode("fleet-baseline"), ctrl.el));
    // Fetches the environment list; deferred to mount so a bare render()
    // (a test, a served preview) draws the static summary without it.
    el.afterMount = ctrl.refresh;
  }

  const moved = deltaBlock(rec.profileDelta, name);
  if (moved) el.appendChild(moved);

  // Pivots start from a value held on this sourcetype; a hunt has no value
  // to start from and runs its searches on it, so it opens on the sourcetype.
  const ws = modules.on("workflows") ? workflows.forSourcetype(name) : [];
  const pivots = ws.filter((w) => !w.hunt);
  const hunts = ws.filter((w) => w.hunt);
  const workflowList = (rows, cls) => h("ul", { class: `r-list ${cls}` }, rows.map((w) => h("li", null, h("a", { href: workflows.href(w.id) }, w.title), h("span", { class: "r-muted" }, ` · ${w.kicker}`))));
  if (ws.length) {
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        headingNode("workflows"),
        pivots.length ? h("p", { class: "r-secondary" }, `Start from a value you are holding on this ${TERMS.sourcetype}; the popup in ${TERMS.host} offers the same on the ${TERMS.field} it begins from.`) : null,
        pivots.length ? workflowList(pivots, "r-workflows--pivots") : null,
        hunts.length ? h("p", { class: "r-secondary" }, `A hunt starts from no value: its searches run on this ${TERMS.sourcetype}, once here or on a schedule in the SIEM.`) : null,
        hunts.length ? workflowList(hunts, "r-workflows--hunts") : null,
      ),
    );
  }

  const types = recordTypes(rec, events, { eventRoute: routes.has("event") });
  if (types.total) {
    const list = h(
      "ul",
      { class: "r-typelist" },
      types.rows.map((t) => h("li", null, t.link ? eventLink(t.name) : h("code", null, t.name), t.count !== null ? h("span", { class: "r-muted r-typelist__n" }, ` ${t.count.toLocaleString()}`) : null)),
    );
    const source = events.length && types.counted ? "The pack's record types, with discovery's counts." : events.length ? "The record types the pack knows. Each has its own field set." : "Values discovery saw, with counts.";
    el.appendChild(
      h(
        "section",
        { class: "r-section" },
        h(
          "details",
          { class: "r-typelist__wrap", open: !stacked && types.total <= FOLD_OPEN_MAX },
          h("summary", null, headingNode("record-types", types.total, { class: "r-typelist__h" })),
          h("p", { class: "r-secondary" }, "Values of ", h("code", null, rec.discriminator || "the record-type field"), ". ", source),
          list,
        ),
      ),
    );
  }

  // ---- fields, grouped by role, filterable ---------------------------------
  const q = String(ctx.params.q || "").toLowerCase();
  const roleFilter = ctx.params.role || "";
  const byRole = new Map();
  for (const f of fields) {
    if (q && !f.toLowerCase().includes(q)) continue;
    const v = views.get(f);
    const role = (v && v.taxonomy.role) || "unclassified";
    if (roleFilter && role !== roleFilter) continue;
    if (!byRole.has(role)) byRole.set(role, []);
    byRole.get(role).push(f);
  }
  const roles = Array.from(byRole.keys()).sort();

  // A concept's description lands on every field bound to it (packs.js), so
  // an aliased column (signature, app, ...) carries the same text as the
  // column it aliases. Show that text once per description; an alias row
  // after the first gets its own binding note, or nothing.
  const shownDescriptions = new Set();

  const filter = h("input", {
    class: "r-input r-rolelist__filter",
    type: "search",
    placeholder: `filter ${TERMS.fields}`,
    "aria-label": `filter ${TERMS.fields}`,
    value: ctx.params.q || "",
    onInput: (e) => ctx.setUrl("sourcetype", { ...ctx.params, name, q: e.target.value || undefined }),
    onChange: (e) => ctx.navigate("sourcetype", { ...ctx.params, name, q: e.target.value || undefined }),
  });

  const allRoles = Array.from(new Set(fields.map((f) => ((views.get(f) || {}).taxonomy || {}).role || "unclassified"))).sort();
  const roleSel = h(
    "select",
    { class: "r-input r-rolelist__select", "aria-label": "role", onChange: (e) => ctx.navigate("sourcetype", { ...ctx.params, name, role: e.target.value || undefined }) },
    h("option", { value: "" }, "every role"),
    allRoles.map((r) => h("option", { value: r, selected: r === roleFilter }, r)),
  );

  // Every role group is a fold with its count in the title, closed on
  // stacked surfaces; the summary is data (the role), not a heading.
  const groups = roles.map((role) =>
    h(
      "details",
      { class: "r-rolelist__group", open: !stacked, dataset: { role } },
      h("summary", { class: "r-rolelist__role" }, role, h("span", { class: "r-muted" }, ` ${byRole.get(role).length}`)),
      h(
        "div",
        { class: "r-fieldgrid" },
        byRole.get(role).map((f) => {
          const v = views.get(f);
          const desc = v && v.meaning.description;
          const repeat = desc && shownDescriptions.has(desc);
          if (desc && !repeat) shownDescriptions.add(desc);
          const aliasOf = v && v.binding && v.binding.alias_of;
          const aliasNote = repeat ? (v.binding && v.binding.note) || (aliasOf ? `alias of ${aliasOf}` : null) : null;
          return h(
            "div",
            { class: "r-fieldgrid__row" },
            fieldLink(f, name),
            v ? fillBadge(v.profile) : null,
            v && v.user ? chip({ kind: "trust", value: "confirmed", text: "yours" }) : null,
            aliasNote
              ? h("span", { class: "r-fieldgrid__desc r-muted", title: aliasNote }, oneLiner(aliasNote))
              : repeat
                ? h("span", { class: "r-muted" }, "-")
                : desc
                  ? h("span", { class: "r-fieldgrid__desc", title: desc }, oneLiner(desc))
                  : v && v.provenance
                    ? h("span", { class: "r-fieldgrid__desc" }, provenanceLine(v.provenance))
                    : h("span", { class: "r-muted" }, "-"),
          );
        }),
      ),
    ),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("fields", fields.length),
      h("div", { class: "r-ann__actions r-rolelist__controls" }, filter, roleSel, routes.has("coverage") ? h("a", { class: "r-rolelist__bind", href: bindHref }, `Bind ${TERMS.fields}`) : null),
      groups.length ? h("div", { class: "r-rolelist" }, groups) : h("p", { class: "r-muted" }, fields.length ? `No ${TERMS.field} matches that filter.` : `No ${TERMS.fields} known yet. Run discovery, or describe one from a popup in ${TERMS.host}.`),
    ),
  );

  return el;
}

export default { render, measuredChip, recordTypes, isFleetBaselineTable };
