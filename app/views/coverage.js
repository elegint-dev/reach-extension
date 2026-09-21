// Coverage: #/coverage?env=<key>&st=<container>&feed=<packId>&sel=<rowId>
// Which concepts each feed carries on the user's own tables, what the
// proposer thinks the unbound columns mean, and the confirm flow that turns
// a proposal into a learned binding (learned.js). Two screens behind one
// wide route, every bit of state in the URL:
//
//   environment (no st)   each feed's concepts as pack / yours / proposed /
//                         several / gap, then every table with its feed,
//                         counts and the pivots still blocked on it
//   table (st set)        every column with fill, what its values look
//                         like, the meaning proposed and why, and the
//                         actions: Confirm, Choose, Not this, Dismiss;
//                         Unbind on a bound row; Reconsider under Skipped fields
//
// Everything the page shows is computed by the pure modules (propose.js
// for the feed election and the proposals, learned.coverage() for the
// roll-up and the blockers, shapes.js for "looks like"); the view only
// adapts the stored discovered layer into their input shapes, renders,
// and writes through catalogue.bindField / bindFields (Confirm all and
// the sibling offer, one write each) / dismissBinding / unbindField.
// It reads the layer once, on mount, through layer.readAll() (a store
// read, both platforms' environments, one key each) and never runs a
// query: proposals come from the column names and top values
// discovery already stored. After a write it redraws its own boxes and
// restores focus itself: app.js leaves this route off its re-render on a
// store change, as it does Discover.
//
// The adapters and the words live in app/lib/coverage-model.js and are
// re-exported here.

import { h } from "../components/h.js";
import { stLink, fieldLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { readAll as discovered } from "../lib/layer.js";
import * as learned from "../lib/learned.js";
import * as propose from "../lib/propose.js";
import * as concepts from "../lib/concepts.js";
import * as packs from "../lib/packs.js";
import { plan as intentPlan } from "../lib/intent.js";
import { PLATFORM, TERMS } from "../lib/platform.js";
import * as model from "../lib/coverage-model.js";
import { STATE_CHIP, plural, environmentsFor, partitionVanished, withoutVanished, vocabularyConcepts, setAsideRows, asideWords, onWord, proposalsFor, rowsFor, whyLine, resultLine, blockerLine, feedSentence, confirmAllReason, sureProposals, matchProposals, mergeProposals, siblingOffers, evidenceFor, chooseGroups, envStats, sweepWords } from "../lib/coverage-model.js";

export * from "../lib/coverage-model.js";

// ---------------------------------------------------------------------------
// The view

function stateChip(state) {
  const spec = STATE_CHIP[state];
  return spec ? chip({ kind: "trust", ...spec }) : null;
}

function fillCell(fill) {
  if (fill === null || fill === undefined) return h("span", { class: "r-muted" }, "-");
  return h("span", { class: "r-muted", title: "share of sampled events carrying it" }, `${Math.round(fill * 100)}%`);
}


function sweepLine(rec) {
  const words = sweepWords(rec);
  return words ? h("p", { class: "r-muted" }, words) : null;
}

export function render(ctx) {
  const { catalogue } = ctx;
  const el = h("div", { class: "r-view r-view--coverage" });
  const status = h("p", { class: "r-secondary r-cov__status", "aria-live": "polite" });
  const body = h("div", { class: "r-cov__body" });

  // The title block is the view's first child; draw() swaps it for the
  // screen's own (the environment's, the table's, or an empty state).
  let title = titleBlock({ kind: "page", h1: "Coverage", scope: ["reading the discovered layer"] });
  el.appendChild(title);
  el.appendChild(
    h(
      "p",
      { class: "r-secondary" },
      `Which concepts each feed carries on your own ${TERMS.sourcetypes}, and what the unbound ${TERMS.fields} probably mean. Proposals come from the ${TERMS.field} names and top values discovery already stored; nothing here runs a query. Confirm one and the ${TERMS.field} takes the concept's meaning, notes and pivots.`,
    ),
  );
  el.appendChild(status);
  el.appendChild(body);
  function setTitle(next) {
    title.before(next);
    title.remove();
    title = next;
  }

  let layer = null;
  let leadsAll = []; // propose.matches() over the whole layer, computed once when it lands
  let resultPanel = null; // the one live result: the latest confirm, its undo and its sibling offer
  let envKey = ctx.params.env || null;
  const st = ctx.params.st || null;
  let forcedFeed = ctx.params.feed || null;
  let showVanished = false;
  let sel = ctx.params.sel || null;

  const v2 = () => packs.list().filter((p) => p.version === 2);
  const labelOf = (key) => {
    const c = concepts.concept(key);
    return c ? c.label : String(key).split("/").pop().replace(/_/g, " ");
  };
  const feedLabelOf = (packId) => {
    const f = concepts.feed(packId);
    if (f) return f.label;
    const p = packs.pack(packId);
    return p ? p.name : packId;
  };

  function setUrl(patch) {
    const params = { env: envKey || undefined, st: st || undefined, feed: forcedFeed || undefined, sel: sel || undefined, ...patch };
    for (const k of Object.keys(params)) if (params[k] === undefined || params[k] === null || params[k] === "") delete params[k];
    ctx.setUrl("coverage", params);
  }

  // Everything the two screens read, recomputed from the layer in hand and
  // the live resolver after every write.
  function model() {
    const learnedRecords = catalogue.learnedBindings();
    const all = environmentsFor(layer, { resolve: concepts.resolve, learnedRecords });
    const vanished = new Map(all.map((e) => [e.key, partitionVanished(e.containers).vanished]));
    const environments = showVanished ? all : withoutVanished(all);
    const packIds = v2().map((p) => p.id);
    const vocabulary = propose.vocabulary({
      concepts: vocabularyConcepts({ packIds, conceptsOf: concepts.conceptsOf, bindingsOf: concepts.bindingsOf }),
      learned: learnedRecords.filter((b) => b.basis === "confirmed" && b.concept),
    });
    const feeds = new Map(); // "env key\u0000container" -> feed
    const proposals = [];
    for (const env of environments) {
      if (env.platform !== PLATFORM) continue; // the other platform's environments are read only
      for (const c of env.containers) {
        const forced = env.key === envKey && c.name === st ? forcedFeed : null;
        const r = proposalsFor(env, c, { vocabulary, learnedRecords, forcedFeed: forced });
        feeds.set(`${env.key}\u0000${c.name}`, r.feed);
        proposals.push(...r.proposals);
      }
    }
    // Rule 8: a match with one bound side proposes for the other.
    const feedOf = (key, name) => {
      const f = feeds.get(`${key}\u0000${name}`);
      return f ? f.packId : null;
    };
    const merged = mergeProposals(proposals, matchProposals(leadsAll, { platform: PLATFORM, feedOf, resolve: concepts.resolve, learnedRecords }));
    const rawPacks = packIds.map((id) => packs.pack(id)).filter(Boolean);
    const cov = learned.coverage({ environments, platform: PLATFORM, packs: rawPacks, learned: learnedRecords, proposals: merged, plan: intentPlan });
    return { learnedRecords, environments, vanished, vocabulary, feeds, feedOf, proposals: merged, coverage: cov, rawPacks };
  }

  function currentEnv(m) {
    return m.environments.find((e) => e.key === envKey) || null;
  }

  function coverageOf(m, key, name) {
    const env = m.coverage.environments.find((e) => e.key === key) || null;
    if (!env) return { env: null, container: null };
    return { env, container: name ? env.containers.find((c) => c.name === name) || null : null };
  }

  function restoreFocus() {
    if (!sel) return;
    const row = body.querySelector(`[data-row-id="${CSS.escape(String(sel))}"]`);
    if (row) row.focus();
  }

  function draw() {
    body.replaceChildren();
    // A vanished table asked for by name is still reviewable: show it.
    if (st && !showVanished) {
      for (const e of environmentsFor(layer)) if (e.containers.some((c) => c.name === st && c.vanished)) showVanished = true;
    }
    const m = model();
    if (!m.environments.length) {
      setTitle(emptyState());
      return;
    }
    if (!envKey || !m.environments.some((e) => e.key === envKey)) {
      const withSt = st ? m.environments.find((e) => e.platform === PLATFORM && e.containers.some((c) => c.name === st)) : null;
      const first = withSt || m.environments.find((e) => e.platform === PLATFORM) || m.environments[0];
      envKey = first.key;
      setUrl({});
    }
    const env = currentEnv(m);
    if (st) drawTable(m, env);
    else drawEnvironment(m, env);
    restoreFocus();
  }

  function emptyState() {
    return titleBlock({
      kind: "page",
      h1: st || "Coverage",
      chips: [h("span", { class: "r-chip r-chip--state" }, st ? "not profiled" : "nothing to propose")],
      scope: [st ? `run Discover on this ${TERMS.sourcetype} first` : `profile a ${TERMS.sourcetype} in Discover first: proposals come from the ${TERMS.field} names and values it reports`],
      actions: [h("a", { class: "r-btn r-btn--primary", href: "#/discover" }, "Discover"), st ? h("a", { class: "r-btn", href: "#/coverage" }, "All feeds") : null],
    });
  }

  function envSelect(m) {
    const mine = m.environments.filter((e) => e.platform === PLATFORM);
    const theirs = m.environments.filter((e) => e.platform !== PLATFORM);
    const sel_ = h(
      "select",
      { class: "r-input r-cov__env", "aria-label": TERMS.env },
      mine.map((e) => h("option", { value: e.key, selected: e.key === envKey }, `${e.label}: ${plural(e.containers.length, TERMS.sourcetype, TERMS.sourcetypes)}`)),
      theirs.length ? h("option", { disabled: true }, "the other platform, read only") : null,
      theirs.map((e) => h("option", { value: e.key, selected: e.key === envKey }, `${e.label}: ${plural(e.containers.length, e.platform === "sentinel" ? "table" : "sourcetype", e.platform === "sentinel" ? "tables" : "sourcetypes")}`)),
    );
    sel_.addEventListener("change", () => {
      envKey = sel_.value || null;
      ctx.navigate("coverage", { env: envKey });
    });
    return sel_;
  }

  // ---- screen 1: the environment -----------------------------------------

  // "show N vanished": the sourcetypes the latest inventory did not return.
  function vanishedToggle(m, env) {
    const gone = m.vanished.get(env.key) || [];
    if (!gone.length) return null;
    const words = env.platform === "sentinel" ? (gone.length === 1 ? "table" : "tables") : gone.length === 1 ? "sourcetype" : "sourcetypes";
    const btn = h("button", { type: "button", class: "r-btn r-btn--small", "aria-pressed": showVanished ? "true" : "false" }, `${showVanished ? "hide" : "show"} ${gone.length} vanished`);
    btn.title = `${gone.length} ${words} the latest inventory did not return. ${showVanished ? "Counted above while shown." : "Left out of the counts above."}`;
    btn.addEventListener("click", () => {
      showVanished = !showVanished;
      draw();
    });
    return h("span", { class: "r-stat" }, btn);
  }

  function vanishedChip(env, name) {
    const c = env.containers.find((x) => x.name === name);
    if (!c || !c.vanished) return null;
    const since = c.missingSince ? new Date(c.missingSince).toLocaleDateString() : "";
    return chip({ kind: "trust", value: "inferred", text: since ? `vanished since ${since}` : "vanished", title: "Not returned by the latest inventory over its indexes; kept so the feed can be seen to have stopped." });
  }

  function drawEnvironment(m, env) {
    const { env: cov } = coverageOf(m, env.key);
    const stats = envStats(cov);
    const readOnly = env.platform !== PLATFORM;
    const stWords = readOnly ? (env.platform === "sentinel" ? ["table", "tables"] : ["sourcetype", "sourcetypes"]) : [TERMS.sourcetype, TERMS.sourcetypes];
    setTitle(
      titleBlock({
        kind: "page",
        h1: "Coverage",
        chips: [readOnly ? h("span", { class: "r-chip r-chip--state" }, "other platform, read only") : null],
        scope: [env.label, `${stats.carried} of ${stats.concepts} concepts carried`, `${stats.proposed} proposed`, `${stats.gaps} gaps`, plural(stats.tables, stWords[0], stWords[1])],
        actions: [envSelect(m), vanishedToggle(m, env)],
      }),
    );
    body.appendChild(
      h(
        "section",
        { class: "r-section" },
        readOnly ? h("p", { class: "r-muted" }, "This environment is on the other platform. Its bindings count for notes; confirm columns there from that platform's page.") : null,
        sweepLine(layer && layer[env.key]),
      ),
    );

    const feedBands = [];
    for (const feed of cov.feeds) {
      const rows = feed.concepts.map((c) =>
        h(
          "tr",
          null,
          h("td", null, c.label, c.known ? null : h("span", { class: "r-muted" }, " (waiting for that pack)")),
          h("td", { class: "r-muted" }, c.type || ""),
          h("td", null, c.status === "gap" ? h("span", { class: "r-muted" }, "gap") : stateChip(c.status)),
          h(
            "td",
            null,
            c.on.length
              ? c.on.slice(0, 4).flatMap((o, i) => [i ? " " : null, h("span", { class: "r-cov__on" }, stLink(o.container), ".", h("code", null, o.column), onWord(o, c.status) ? h("span", { class: "r-muted" }, ` (${onWord(o, c.status)})`) : null)])
              : h("span", { class: "r-muted" }, "-"),
            c.on.length > 4 ? h("span", { class: "r-muted" }, ` +${c.on.length - 4} more`) : null,
          ),
        ),
      );
      // One band per feed, folded unless it is the only one.
      feedBands.push(
        h(
          "details",
          { class: "r-cov__feed", open: cov.feeds.length === 1 },
          h("summary", { class: "r-cov__feedsum" }, h("h3", { class: "r-cov__feedname" }, feed.label), h("span", { class: "r-muted r-cov__h2meta" }, ` ${feed.carried} carried, ${feed.proposed} proposed, ${feed.gaps} gaps`)),
          h(
            "div",
            { class: "r-table-wrap" },
            h(
              "table",
              { class: "r-table r-cov__table" },
              h("thead", null, h("tr", null, h("th", null, "concept"), h("th", null, "type"), h("th", null, "status"), h("th", null, "carried on"))),
              h("tbody", null, rows),
            ),
          ),
        ),
      );
    }
    if (feedBands.length) body.appendChild(h("section", { class: "r-section r-cov__feeds" }, headingNode("feeds", feedBands.length), feedBands));

    const tableRows = cov.containers.map((c) => {
      const feed = m.feeds.get(`${env.key}\u0000${c.name}`) || { packId: c.feedPackId, basis: c.feedPackId ? "bindings" : null, votes: {} };
      const gaps = learned.intentGaps(c);
      const counts = `${plural(c.columns, TERMS.field, TERMS.fields)} · ${c.counts.bound} bound${c.counts.yours ? ` (${c.counts.yours} by you)` : ""} · ${c.counts.proposed} proposed · ${c.counts.unbound} unbound`;
      return h(
        "div",
        { class: "r-stlist__row", dataset: { rowId: c.name }, tabindex: "0" },
        h("div", { class: "r-stlist__name" }, stLink(c.name), vanishedChip(env, c.name), h("p", { class: "r-secondary" }, feedSentence(feed, feedLabelOf)), gaps ? h("p", { class: "r-secondary r-muted" }, gaps) : null),
        h("div", { class: "r-stlist__meta" }, counts),
        h("span", { class: "r-stlist__src" }, readOnly ? null : h("a", { class: "r-btn r-btn--small", href: `#/coverage?env=${encodeURIComponent(env.key)}&st=${encodeURIComponent(c.name)}` }, "Review")),
      );
    });
    body.appendChild(
      h(
        "section",
        { class: "r-section" },
        headingNode("sourcetypes", tableRows.length),
        tableRows.length ? h("div", { class: "r-stlist" }, tableRows) : h("p", { class: "r-muted" }, `Nothing discovered on ${env.label} yet. `, h("a", { href: `#/discover?env=${encodeURIComponent(env.key)}` }, "Discover"), "."),
      ),
    );
  }

  // ---- screen 2: the table -------------------------------------------------

  function drawTable(m, env) {
    const container = env.containers.find((c) => c.name === st) || null;
    const readOnly = env.platform !== PLATFORM;
    const allFeeds = h("a", { class: "r-btn", href: `#/coverage?env=${encodeURIComponent(env.key)}` }, "All feeds");
    if (!container) {
      setTitle(
        titleBlock({
          kind: "sourcetype",
          h1: st,
          chips: [h("span", { class: "r-chip r-chip--state" }, "not profiled")],
          scope: [env.label, `run Discover on this ${TERMS.sourcetype} first`],
          actions: [h("a", { class: "r-btn r-btn--primary", href: `#/discover?env=${encodeURIComponent(env.key)}` }, "Discover"), allFeeds],
        }),
      );
      return;
    }
    const { container: cov } = coverageOf(m, env.key, st);
    const feed = m.feeds.get(`${env.key}\u0000${st}`) || { packId: null, basis: null, votes: {} };
    const proposals = m.proposals.filter((p) => p.platform === env.platform && p.container === st);
    const rows = rowsFor(env, container, { proposals, learnedRecords: m.learnedRecords, labelOf, blockers: cov ? cov.blockers : [] });
    const conceptType = (key) => {
      const c = concepts.concept(key);
      return c ? c.type : null;
    };
    const feedInfos = m.rawPacks.map((p) => ({ id: p.id, label: feedLabelOf(p.id), concepts: concepts.conceptsOf(p.id).map((c) => ({ key: c.key, label: c.label })) }));

    // Header: feed sentence and select, counts, blockers, Confirm all.
    const feedSel = h(
      "select",
      { class: "r-input r-cov__feedsel", "aria-label": "feed" },
      h("option", { value: "", selected: !feed.packId }, "not recognised"),
      m.rawPacks.map((p) => h("option", { value: p.id, selected: p.id === feed.packId }, feedLabelOf(p.id))),
    );
    feedSel.addEventListener("change", () => {
      forcedFeed = feedSel.value || null;
      setUrl({ feed: forcedFeed });
      draw();
    });
    const sure = proposals.filter((p) => p.tier === "high");
    const reason = confirmAllReason(feed, proposals);
    const reasonEl = h("span", { class: "r-muted r-cov__reason", id: "r-cov-reason" }, reason || "");
    const confirmAll = h(
      "button",
      {
        type: "button",
        class: "r-btn r-btn--primary",
        disabled: readOnly || reason !== null,
        title: reason,
        "aria-describedby": reason ? "r-cov-reason" : null,
      },
      `Confirm all (${sure.length})`,
    );
    confirmAll.addEventListener("click", async () => {
      confirmAll.disabled = true;
      // The live list, not the one drawn: a row confirmed in place since is
      // bound by now and stays out; one write for the rest.
      const live = model();
      const list = sureProposals(live.proposals, { platform: env.platform, container: st, resolve: concepts.resolve, learnedRecords: live.learnedRecords });
      let done = 0;
      let errors = [];
      try {
        const r = await catalogue.bindFields(list.map((p) => ({ sourcetype: st, name: p.column, concept: p.concept, alias_of: p.alias_of || null, evidence: p.evidence || null, via: "coverage" })));
        done = r.records.length;
        errors = r.errors;
      } catch (err) {
        errors = [err && err.message ? err.message : String(err)];
      }
      status.textContent = `Bound ${plural(done, TERMS.field, TERMS.fields)} on ${st}.${errors.length ? " " + errors.join(" ") : ""}`;
      draw();
    });
    const gaps = cov ? learned.intentGaps(cov) : null;
    setTitle(
      titleBlock({
        kind: "sourcetype",
        h1: st,
        chips: [h("span", { class: "r-chip r-chip--state" }, "coverage"), readOnly ? h("span", { class: "r-chip r-chip--state" }, "read only") : null],
        scope: cov ? [feed.packId ? feedLabelOf(feed.packId) : "feed not recognised", `${cov.counts.bound} bound${cov.counts.yours ? ` (${cov.counts.yours} by you)` : ""}`, `${cov.counts.proposed} proposed`, `${cov.counts.unbound} unbound`] : [env.label],
        actions: [readOnly ? null : confirmAll, allFeeds],
      }),
    );
    body.appendChild(
      h(
        "section",
        { class: "r-section r-cov__head" },
        h("label", { class: "r-cov__feedrow" }, h("span", null, `This ${TERMS.sourcetype} carries: `), feedSel),
        h("p", { class: "r-secondary" }, feedSentence(feed, feedLabelOf)),
        h("p", { class: "r-secondary r-cov__gaps" }, gaps || ""),
        feed.packId ? null : h("p", { class: "r-muted" }, `Not recognised as one feed, so nothing is proposed on its own. Pick the feed above to see what would fit.`),
        readOnly ? null : h("p", { class: "r-secondary" }, reasonEl),
      ),
    );

    // The one result panel: filled by the latest confirm, emptied by any
    // other write. It lives outside the table so its words never resize a
    // column, and there is only ever one undo on the page.
    resultPanel = h("div", { class: "r-cov__result", "aria-live": "polite" });
    body.appendChild(resultPanel);

    // Fields (N): the column table, with the set-aside columns (left
    // alone, or every sure candidate refused) folded under it. Every
    // refused concept is named; a column still in the table with a
    // proposal is not listed twice.
    const tbody = h("tbody");
    for (const row of rows) tbody.appendChild(rowEl(row, { env, feed, feedInfos, conceptType, readOnly }));
    const aside = setAsideRows(m.learnedRecords, env.platform, st, m.proposals);
    body.appendChild(
      h(
        "section",
        { class: "r-section r-cov__fields" },
        headingNode("fields", rows.length),
        h(
          "div",
          { class: "r-table-wrap" },
          h(
            "table",
            { class: "r-table r-cov__table" },
            h("thead", null, h("tr", null, h("th", null, TERMS.field), h("th", null, "fill"), h("th", null, "looks like"), h("th", null, "meaning"), h("th", null, ""))),
            tbody,
          ),
        ),
        aside.length
          ? h(
              "details",
              { class: "r-cov__aside" },
              headingNode("skipped-fields", aside.length),
              h(
                "div",
                { class: "r-stlist" },
                aside.map((b) =>
                  h(
                    "div",
                    { class: "r-stlist__row" },
                    h("div", { class: "r-stlist__name" }, h("code", null, b.column)),
                    h("div", { class: "r-stlist__meta" }, asideWords(b, labelOf)),
                    h("span", { class: "r-stlist__src" }, readOnly ? null : h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => write(() => catalogue.unbindField(st, b.column), b.column, `Reconsidering ${b.column}.`) }, "Reconsider")),
                  ),
                ),
              ),
            )
          : null,
      ),
    );

    // Same values elsewhere: join leads with neither side bound. The pairs
    // were computed once on mount; a confirm can only take a pair out, so
    // the cached list is filtered against the live resolver here.
    const unbound = (side) => !concepts.resolve(side.platform, side.container, side.column);
    const leads = leadsAll.filter((x) => ((x.a.env === env.key && x.a.container === st) || (x.b.env === env.key && x.b.container === st)) && unbound(x.a) && unbound(x.b));
    if (leads.length) {
      body.appendChild(
        h(
          "section",
          { class: "r-section" },
          headingNode("join-leads"),
          h("p", { class: "r-secondary" }, `A ${TERMS.field} here that shares its name and top values with one on another ${TERMS.sourcetype}. A lead for a join, not a binding.`),
          h(
            "div",
            { class: "r-table-wrap" },
            h(
              "table",
              { class: "r-table r-cov__table" },
              h("thead", null, h("tr", null, h("th", null, "here"), h("th", null, "there"), h("th", { class: "r-table__right" }, "shared values"))),
              h(
                "tbody",
                null,
                leads.slice(0, 40).map((x) => {
                  const here = x.a.env === env.key && x.a.container === st ? x.a : x.b;
                  const there = here === x.a ? x.b : x.a;
                  return h("tr", null, h("td", null, h("code", null, here.column)), h("td", null, h("code", null, there.container), ".", h("code", null, there.column), there.env !== env.key ? h("span", { class: "r-muted" }, ` on ${there.env}`) : null), h("td", { class: "r-table__right" }, String(x.overlap)));
                }),
              ),
            ),
          ),
        ),
      );
    }
  }

  // One write, then a full redraw with focus back on the row. The words
  // say what happened; the result panel (a confirm's) is gone with the
  // redraw, so the latest action is the only one on the page.
  async function write(fn, rowId, words = "") {
    try {
      await fn();
      status.textContent = words;
    } catch (err) {
      status.textContent = err && err.message ? err.message : String(err);
    }
    sel = rowId || sel;
    setUrl({});
    draw();
  }

  function meaningCell(row) {
    const cell = h("td", { class: "r-cov__meaning" });
    // A refusal still on the row ("not this" with a sure survivor) is named
    // after the why-line, so the walk the user is on stays visible.
    const why = (p) => {
      const nots = (p && p.refused ? p.refused : []).map((k) => `not ${labelOf(k)}`).join(", ");
      return whyLine(p, { unblocks: row.unblocks }) + (nots ? `; ${nots}` : "");
    };
    if (row.state === "pack" || row.state === "yours") cell.append(h("span", null, row.label), " ", stateChip(row.state));
    else if (row.state === "proposed") cell.append(h("span", null, row.label), " ", stateChip("proposed"), h("p", { class: "r-cov__why r-muted" }, why(row.proposal)));
    else if (row.state === "several") {
      const alts = [row.proposal.concept, ...row.proposal.alternatives.map((a) => a.concept)].slice(0, 3).map((k) => labelOf(k));
      cell.append(h("span", { class: "r-muted" }, alts.join(" or ")), " ", stateChip("several"), h("p", { class: "r-cov__why r-muted" }, why(row.proposal)));
    } else if (row.state === "medium") cell.append(h("span", { class: "r-muted" }, `maybe ${row.label}`), " ", stateChip("medium"), h("p", { class: "r-cov__why r-muted" }, why(row.proposal)));
    else if (row.state === "dismissed") {
      const refused = row.record ? Array.from(new Set([...(row.record.dismissed || []), ...(row.record.concept ? [row.record.concept] : [])])) : [];
      cell.append(stateChip("dismissed"), refused.length ? h("p", { class: "r-cov__why r-muted" }, refused.map((k) => `not ${labelOf(k)}`).join(", ")) : null);
    }
    else if (row.state === "inert") cell.append(h("span", null, row.concept), " ", stateChip("inert"), h("p", { class: "r-cov__why r-muted" }, `waiting for the ${row.packId} pack: this browser does not have it, so the concept's meaning and pivots cannot show yet`));
    else cell.append(h("span", { class: "r-muted" }, "-"));
    return cell;
  }

  function rowEl(row, opts) {
    const tr = h("tr", { dataset: { rowId: row.id }, tabindex: "0", class: `r-cov__row r-cov__row--${row.state}` });
    tr.append(h("td", null, fieldLink(row.column, st)), h("td", null, fillCell(row.fill)), h("td", { class: "r-muted" }, row.looksLike || ""), meaningCell(row), actionCell(row, tr, opts));
    return tr;
  }

  function actionCell(row, tr, opts) {
    const cell = h("td", { class: "r-cov__actions" });
    if (opts.readOnly) return cell;
    const btn = (text, onClick, primary) => h("button", { type: "button", class: ["r-btn", "r-btn--small", primary && "r-btn--primary"], onClick }, text);
    const choose = () => chooseIn(cell, row, tr, opts);
    const notThis = () => write(() => catalogue.dismissBinding(st, row.column, row.proposal.concept), row.id, `${row.column}: not ${labelOf(row.proposal.concept)}.`);
    const dismiss = () => write(() => catalogue.dismissBinding(st, row.column, null), row.id, `${row.column} set aside.`);
    if (row.state === "proposed") {
      cell.append(btn("Confirm", () => confirm(row, tr, opts, row.proposal.concept, row.proposal), true), btn("Choose", choose), btn("Not this", notThis), btn("Dismiss", dismiss));
    } else if (row.state === "several" || row.state === "medium") {
      cell.append(btn("Choose", choose, true), btn("Not this", notThis), btn("Dismiss", dismiss));
    } else if (row.state === "yours" || row.state === "inert") {
      cell.append(btn("Unbind", () => write(() => catalogue.unbindField(st, row.column), row.id, `Unbound ${row.column}.`)));
    } else if (row.state === "dismissed") {
      // Reconsider forgets the refusals; Choose keeps them and binds now.
      cell.append(btn("Reconsider", () => write(() => catalogue.unbindField(st, row.column), row.id, `Reconsidering ${row.column}.`)), btn("Choose", choose));
    } else if (row.state === "unbound") {
      cell.append(btn("Choose", choose), btn("Dismiss", dismiss));
    }
    return cell;
  }

  // Choose: the action cell becomes a select of the alternatives with Save
  // and Cancel, the annotation editor's pattern.
  function chooseIn(cell, row, tr, opts) {
    const groups = chooseGroups({ feedPackId: opts.feed.packId, proposal: row.proposal, feeds: opts.feedInfos });
    const select = h(
      "select",
      { class: "r-input", "aria-label": `concept for ${row.column}` },
      groups.map((g) => h("optgroup", { label: g.label }, g.options.map((o) => h("option", { value: o.key, selected: row.proposal && o.key === row.proposal.concept }, o.score !== null ? `${o.label} (${Math.round(o.score * 100)}%)` : o.label)))),
    );
    const save = h("button", { type: "button", class: "r-btn r-btn--small r-btn--primary" }, "Save");
    const cancel = h("button", { type: "button", class: "r-btn r-btn--small" }, "Cancel");
    save.addEventListener("click", () => {
      const key = select.value;
      if (!key) return;
      confirm(row, tr, opts, key, row.proposal);
    });
    cancel.addEventListener("click", () => {
      const fresh = actionCell(row, tr, opts);
      cell.replaceWith(fresh);
    });
    cell.replaceChildren(h("div", { class: "r-cov__choose" }, select, save, cancel));
    select.focus();
  }

  // Confirm: write, then the result panel (the one on the page) shows the
  // result line, the blocker sentence, an undo and the sibling offer; the
  // row redraws as yours in place, the other rows stay where they are, and
  // the header counts follow.
  async function confirm(row, tr, opts, conceptKey, proposal) {
    sel = row.id;
    setUrl({});
    try {
      await catalogue.bindField(st, row.column, conceptKey, { alias_of: proposal && proposal.concept === conceptKey ? proposal.alias_of || null : null, evidence: evidenceFor(proposal, conceptKey), via: "coverage" });
    } catch (err) {
      status.textContent = err && err.message ? err.message : String(err);
      return;
    }
    status.textContent = "";
    const m = model();
    const env = currentEnv(m);
    const { container: cov } = coverageOf(m, env.key, st);
    const label = labelOf(conceptKey);
    const undo = h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => write(() => catalogue.unbindField(st, row.column), row.id, `Unbound ${row.column}.`) }, "undo");
    const done = h("div", { class: "r-cov__done" }, h("span", null, resultLine(row.column, label), " ", blockerLine(cov)), " ", undo);
    const container = env.containers.find((c) => c.name === st);
    const offers = siblingOffers(env, st, row.column, conceptKey, { learnedRecords: m.learnedRecords, conceptType: opts.conceptType(conceptKey), feedOf: (name) => m.feedOf(env.key, name) });
    if (offers.length) done.appendChild(siblingBox(offers, conceptKey, label, row.id));
    if (resultPanel) resultPanel.replaceChildren(done);
    const proposals = m.proposals.filter((p) => p.platform === env.platform && p.container === st);
    const fresh = rowsFor(env, container, { proposals, learnedRecords: m.learnedRecords, labelOf, blockers: cov ? cov.blockers : [] }).find((r) => r.id === row.id);
    if (fresh) {
      const next = rowEl(fresh, opts);
      tr.replaceWith(next);
      next.focus();
    }
    refreshHeader(m, env, container);
  }

  function siblingBox(offers, conceptKey, label, rowId) {
    const boxes = offers.map((o) => {
      const cb = h("input", { type: "checkbox", checked: o.checked });
      return { o, cb, el: h("label", { class: "r-cov__sib" }, cb, " ", h("code", null, o.container), ".", h("code", null, o.column), h("span", { class: "r-muted" }, o.profiled ? (o.agrees ? " values agree" : " values disagree") : " not profiled")) };
    });
    const save = h("button", { type: "button", class: "r-btn r-btn--small r-btn--primary" }, `Bind these to ${label}`);
    const skip = h("button", { type: "button", class: "r-btn r-btn--small" }, "Skip");
    const box = h("div", { class: "r-cov__siblings" }, h("p", { class: "r-secondary" }, `The same ${TERMS.field} on other ${TERMS.sourcetypes} here, unbound:`), boxes.map((b) => b.el), h("div", { class: "r-ann__actions" }, save, skip));
    save.addEventListener("click", async () => {
      save.disabled = true;
      const checked = boxes.filter((b) => b.cb.checked);
      let n = 0;
      let errors = [];
      try {
        const r = await catalogue.bindFields(checked.map((b) => ({ sourcetype: b.o.container, name: b.o.column, concept: conceptKey, evidence: { from: "sibling", score: null, via: `${st}.${rowId}`, shape: null, matched: null, total: null }, via: "coverage" })));
        n = r.records.length;
        errors = r.errors;
      } catch (err) {
        errors = [err && err.message ? err.message : String(err)];
      }
      status.textContent = `Bound ${n} more to ${label}.${errors.length ? " " + errors.join(" ") : ""}`;
      sel = rowId;
      setUrl({});
      draw();
    });
    skip.addEventListener("click", () => box.remove());
    return box;
  }

  // After a confirm the counts and the blocker sentence in the header move;
  // the rows stay where they are.
  function refreshHeader(m, env, container) {
    const { container: cov } = coverageOf(m, env.key, st);
    if (!cov) return;
    const feed = m.feeds.get(`${env.key}\u0000${st}`) || { packId: cov.feedPackId, basis: null, votes: {} };
    const proposals = m.proposals.filter((p) => p.platform === env.platform && p.container === st);
    const scope = title.querySelector(".r-scope");
    if (scope) scope.replaceChildren(...[feed.packId ? feedLabelOf(feed.packId) : "feed not recognised", `${cov.counts.bound} bound${cov.counts.yours ? ` (${cov.counts.yours} by you)` : ""}`, `${cov.counts.proposed} proposed`, `${cov.counts.unbound} unbound`].flatMap((t, i) => (i ? [h("span", { class: "r-scope__sep", "aria-hidden": "true" }, " · "), t] : [t])));
    const gapsEl = body.querySelector(".r-cov__gaps");
    if (gapsEl) gapsEl.textContent = learned.intentGaps(cov) || "";
    const sure = proposals.filter((p) => p.tier === "high").length;
    const btn = title.querySelector(".r-btn--primary");
    const reason = confirmAllReason(feed, proposals);
    if (btn) {
      btn.textContent = `Confirm all (${sure})`;
      btn.disabled = reason !== null;
      if (reason) btn.setAttribute("title", reason);
      else btn.removeAttribute("title");
    }
    const reasonEl = body.querySelector(".r-cov__reason");
    if (reasonEl) reasonEl.textContent = reason || "";
  }

  el.afterMount = async () => {
    try {
      layer = (await discovered()) || {};
    } catch (err) {
      status.textContent = `Could not read the discovered layer: ${err && err.message ? err.message : err}`;
      layer = {};
    }
    try {
      // With the resolver: a pair with one bound side is a proposal (rule 8),
      // read back against the live resolver by matchProposals() on every draw.
      leadsAll = propose.matches({ environments: environmentsFor(layer, { resolve: concepts.resolve, learnedRecords: catalogue.learnedBindings() }) });
    } catch {
      leadsAll = [];
    }
    draw();
  };
  return el;
}

export default { render, ...model };
