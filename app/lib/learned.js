// The learned layer: bindings the user confirmed, kept in the user layer
// and projected into the resolver as one synthetic pack.
//
// A pack binds a column to a concept for the tables a feed documents. A
// custom table (acme:cloudtrail, a copied CloudTrail_CL) carries the same
// concepts under its own column names, and nothing bundled knows that. The
// user says so once, and the record lands in user.bindings, one per
// (platform, container, column):
//
//   { platform: "splunk" | "sentinel", container, column,
//     concept: "<pack>/<id>" | null,    null with basis "dismissed": leave this column alone
//     basis: "confirmed" | "dismissed", dismissed with a concept: not this one
//     alias_of: column | null, confirmed_at: ISO | null, via: string | null,
//     imported_at: ISO | null, evidence: object | null }
//
// The confirmed records whose concept exists here become a bindings-only v2
// pack (id "learned", no concepts of its own) that packs.replace() indexes
// beside the bundled packs: resolve(), notes, compiled pivots and export
// then work with no new code path. It owns no concept, so a pack that
// binds the same triple wins by concepts.best(); the learned layer only
// fills gaps. A record whose concept no loaded pack defines is inert: it
// stays in the layer and waits for that pack. catalogue.js is the only
// writer; this module holds the pure shapes.
//
//   LEARNED_ID                                     "learned"
//   normaliseBindings(list)                        → [record]  drops malformed records and unsafe keys; one per triple, newest wins
//   learnedPack(bindings, { platform?, conceptExists })  → v2 pack of the confirmed records whose concept exists
//                                                    platform, when given, keeps that platform's records only (default: both)
//   mergeBindings(mine, theirs, { now? })          → { list, added, updated, kept }  per triple, newer confirmed_at wins; theirs get imported_at
//   isInert(record, conceptExists)                 → true for a confirmed record whose concept is not loaded ("waiting for the X pack")
//   shadowingPack(record, resolve)                 → the pack id that binds this triple ahead of the learned pack, or null
//                                                    (resolve is concepts.resolve; a shadowed record stays in the layer, out of the pack)
//   decidedAt(record)                              → confirmed_at, the one clock decisions compare on ("" when absent)
//   packOf(record)                                 → the pack id a record's concept names, or null
//   tripleKey(record)                              → "platform container column"
//
// Coverage: a per-environment checklist, computed only from data the
// caller already holds. Nothing here resolves a column against the live
// concepts.js registry, runs an intent through intent.js, or reads the
// store; that is what lets tests/coverage.test.js build a whole
// environment by hand with no catalogue.load(), and lets the coverage
// view redraw after a write with no extra read of its own.
//
//   coverage({ environments, platform, packs, learned, proposals, plan }) -> Coverage
//     environments: [ { key, platform, label?, containers: [ { name,
//                     columns: [ { column, profile?, concept } ] } ] } ]
//                   the same shape propose.matches() takes, so one adapter
//                   builds both: the caller turns the stored layer ({
//                   [envKey]: { sourcetypes: { [st]: { fields: { [f]: {
//                   profile } } } } }, catalogue.discoveredRaw()'s shape)
//                   into this one container at a time, resolving each
//                   column's concept itself (concepts.resolve, or the
//                   learned binding when there is one) - coverage() reads
//                   `concept` as given and never resolves one itself.
//     platform:     this build's own platform ("splunk" | "sentinel", from
//                   platform.js); only decides EnvCoverage.thisPlatform
//     packs:        [ rawPack ] the loaded v2 packs, packs.pack(id)'s own
//                   shape ({ id, name, feed: { label, discriminator },
//                   concepts: { [id]: { label, type } }, edges: [ { id,
//                   label, intent } ] }): the full concept roster (so a
//                   concept nobody has touched still shows as a gap) and
//                   the edges a blocker checks come from here, never from
//                   a live registry
//     learned:      [ record ] this module's own shape (run through
//                   normaliseBindings again, so raw user.bindings works
//                   unchanged): which triples are "confirmed" (yours, not
//                   the pack's) or "dismissed" with no concept (set aside,
//                   never a gap)
//     proposals:    [ { platform, container, column, concept, tier,
//                   score?, evidence? } ] flat across every environment
//                   and container - propose.proposeBindings()'s per-
//                   container rows, plus (there is no matchProposals()
//                   export) a row the caller builds from a propose.matches()
//                   entry whose `proposal` is set: { platform, container:
//                   proposal.for === "a" ? a.container : b.container,
//                   column: ..., concept: proposal.concept, tier:
//                   proposal.tier }. Tagged with platform and container by
//                   the caller, best first when a triple has more than
//                   one. A column with no concept and no proposal is a gap.
//     plan:         intent.js's own `plan(intent, { pack, platform,
//                   container }) -> { unresolved }`, injected rather than
//                   imported (see "No DOM" below): a blocker is a filter
//                   or record-type concept `plan()` could not resolve on
//                   the container, which only the live concepts.js
//                   registry can answer correctly (a container's full set
//                   of bindings, not merely the columns `environments`
//                   happened to list - a partial column list must never
//                   invent a false blocker). Omit it and blockers are all
//                   empty, never guessed.
//
//   Coverage: { environments: [ EnvCoverage ] }
//   EnvCoverage: { key, platform, thisPlatform: boolean | null,
//                  feeds: [FeedCoverage], containers: [ContainerCoverage] }
//   FeedCoverage: { packId, label, concepts: [ConceptCoverage],
//                   carried, proposed, gaps }   concept counts: pack+yours,
//                   proposed+several, gap
//   ConceptCoverage: { key, id, label, type, known: boolean, status:
//                      "pack" | "yours" | "proposed" | "several" | "gap",
//                      on: [ { container, column, status } ] }
//     known is false for a concept named by a binding or proposal whose
//     pack is not in `packs` (an inert record, surfaced here rather than
//     silently dropped); status is the concept's best landing anywhere in
//     the environment (pack beats yours beats proposed beats several).
//   ContainerCoverage: { name, feedPackId, feedLabel, columns: number,
//                        counts: { bound, yours, proposed, unbound },
//                        blockers: [ { edgeId, label, missing: [ { concept,
//                        label, proposal: { column, tier } | null } ] } ] }
//     feedPackId is the majority owner of the container's resolved
//     columns, or (nothing resolved yet) of its proposals; null when
//     neither exists ("not recognised"). bound counts every resolved
//     column, pack or learned; yours is the learned subset of bound;
//     bound + proposed + unbound === columns (a column the user dismissed
//     entirely counts as unbound: set aside, not a lead). A blocker is one
//     of the feed's own edges whose intent has a filter or record-type
//     concept this container does not resolve yet; `missing` names each
//     such concept once, with the best proposal for it here, if any.
//
//   intentGaps(container, { limit = 3 }) -> string | null   a ContainerCoverage's
//     blockers, read back as the sentence a table row shows: "<feed>
//     pivots here still need <concept> (proposal: <column>, sure),
//     <concept> (pick a column) and 4 more."; the sure proposals first,
//     `limit` named (0: all); null when there are no blockers.
//
// No DOM. No store. No import of concepts.js, intent.js, propose.js or
// packs.js: every fact coverage() needs, including whether a filter
// concept resolves, is a plain value the caller already computed or a
// function (`plan`) it hands in, which is what lets tests/coverage.test.js
// build a whole environment and a fake `plan` by hand, no catalogue.load()
// needed for the synthetic cases (a real one is used too, to prove the
// hand-built cases agree with intent.js).

export const LEARNED_ID = "learned";
const PLATFORMS = ["splunk", "sentinel"];
const BASES = ["confirmed", "dismissed"];
const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
const QUALIFIED_RE = /^[a-z0-9][a-z0-9-]*\/[a-z][a-z0-9_]*$/;

function safeName(v) {
  return typeof v === "string" && v !== "" && !UNSAFE.has(v);
}

function stringOrNull(v) {
  return typeof v === "string" && v !== "" ? v : null;
}

function plainObject(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const out = {};
  for (const [k, val] of Object.entries(v)) if (!UNSAFE.has(k)) out[k] = val;
  return out;
}

export function tripleKey(rec) {
  return `${rec.platform} ${rec.container} ${rec.column}`;
}

// When the record was decided. Only confirmed_at counts: an import stamp
// says when a file was read, not when anyone decided, so a record without
// confirmed_at never beats one that has it. imported_at breaks ties only
// (two hand-made records with the same or no confirmed_at), so a list
// still orders the same way every time.
export function decidedAt(rec) {
  return String((rec && rec.confirmed_at) || "");
}

// > 0 when a was decided after b, < 0 when before, 0 when neither can tell.
function compareDecision(a, b) {
  const da = decidedAt(a);
  const db = decidedAt(b);
  if (da !== db) return da > db ? 1 : -1;
  const ia = String((a && a.imported_at) || "");
  const ib = String((b && b.imported_at) || "");
  return ia === ib ? 0 : ia > ib ? 1 : -1;
}

function normaliseOne(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (!PLATFORMS.includes(raw.platform) || !safeName(raw.container) || !safeName(raw.column)) return null;
  if (!BASES.includes(raw.basis)) return null;
  const concept = raw.concept === null || raw.concept === undefined ? null : raw.concept;
  if (concept !== null && (typeof concept !== "string" || !QUALIFIED_RE.test(concept))) return null;
  if (raw.basis === "confirmed" && concept === null) return null;
  return {
    platform: raw.platform,
    container: raw.container,
    column: raw.column,
    concept,
    basis: raw.basis,
    alias_of: safeName(raw.alias_of) ? raw.alias_of : null,
    confirmed_at: stringOrNull(raw.confirmed_at),
    via: stringOrNull(raw.via),
    imported_at: stringOrNull(raw.imported_at),
    evidence: plainObject(raw.evidence),
    // Every concept the user said "not this" to on this pair, so a second
    // "not this" does not forget the first and the two candidates cannot
    // take turns forever. `concept` stays the latest of them (or null for
    // "leave this column alone").
    dismissed: Array.isArray(raw.dismissed) ? Array.from(new Set(raw.dismissed.filter((c) => typeof c === "string" && QUALIFIED_RE.test(c)))) : concept && raw.basis === "dismissed" ? [concept] : [],
  };
}

export function normaliseBindings(list) {
  if (!Array.isArray(list)) return [];
  const byTriple = new Map();
  for (const raw of list) {
    const rec = normaliseOne(raw);
    if (!rec) continue;
    const k = tripleKey(rec);
    const cur = byTriple.get(k);
    if (!cur) { byTriple.set(k, rec); continue; }
    // Two dismissals of one pair merge their "not this" lists; otherwise the newer decision stands.
    const next = compareDecision(rec, cur) >= 0 ? rec : cur;
    if (rec.basis === "dismissed" && cur.basis === "dismissed") next.dismissed = Array.from(new Set([...cur.dismissed, ...rec.dismissed]));
    byTriple.set(k, next);
  }
  return Array.from(byTriple.values());
}

export function packOf(rec) {
  return rec && typeof rec.concept === "string" && rec.concept.includes("/") ? rec.concept.split("/")[0] : null;
}

export function isInert(rec, conceptExists) {
  return Boolean(rec && rec.basis === "confirmed" && rec.concept && !conceptExists(rec.concept));
}

// The pack that binds this record's triple ahead of the learned pack, or
// null. packs.js indexes the learned pack last, so whatever resolve()
// returns for the triple that is not the learned pack is a feed pack's
// binding, owner or referrer; such a record is shadowed: bindField refuses
// to write one, and syncLearned keeps one that arrived by import or from
// another context out of the projection, so no pivot, concept column list
// or note slot ever sees it. It stays in the layer for the coverage view
// ("now bound by the X pack") and for export.
export function shadowingPack(rec, resolve) {
  if (!rec || typeof resolve !== "function") return null;
  const r = resolve(rec.platform, rec.container, rec.column);
  return r && r.binding && r.binding.packId !== LEARNED_ID ? r.binding.packId : null;
}

// The v2 pack the resolver takes. Only records that will pass packs.validate:
// confirmed, one per triple, a qualified concept key some loaded pack defines.
export function learnedPack(bindings, { platform, conceptExists = () => true } = {}) {
  const out = [];
  for (const rec of normaliseBindings(bindings)) {
    if (rec.basis !== "confirmed" || !rec.concept) continue;
    if (platform && rec.platform !== platform) continue;
    if (!conceptExists(rec.concept)) continue;
    const via = rec.evidence && stringOrNull(rec.evidence.via);
    const b = {
      platform: rec.platform,
      container: rec.container,
      column: rec.column,
      concept: rec.concept,
      basis: "confirmed",
      basis_ref: "confirmed by the user",
    };
    if (rec.alias_of) b.alias_of = rec.alias_of;
    if (via) b.note = `Looks like ${via}`;
    out.push(b);
  }
  return {
    format: "reach-pack",
    version: 2,
    id: LEARNED_ID,
    name: "Learned bindings",
    description: "Columns you bound to a concept yourself.",
    feed: { id: LEARNED_ID, label: "Learned bindings" },
    concepts: {},
    containers: {},
    bindings: out,
  };
}

// Merge for import. Per triple: a record only one side has is kept, and
// on both sides the newer decision wins by confirmed_at (mine on a tie,
// and mine whenever theirs carries no confirmed_at at all). Records taken
// from theirs are stamped imported_at.
export function mergeBindings(mine, theirs, { now } = {}) {
  const stamp = now || new Date().toISOString();
  const byTriple = new Map();
  for (const rec of normaliseBindings(mine)) byTriple.set(tripleKey(rec), rec);
  let added = 0;
  let updated = 0;
  let kept = 0;
  for (const rec of normaliseBindings(theirs)) {
    const k = tripleKey(rec);
    const cur = byTriple.get(k);
    if (!cur) {
      byTriple.set(k, { ...rec, imported_at: stamp });
      added++;
    } else if (compareDecision(rec, cur) > 0) {
      byTriple.set(k, { ...rec, imported_at: stamp });
      updated++;
    } else {
      kept++;
    }
  }
  return { list: Array.from(byTriple.values()), added, updated, kept };
}

// ---------------------------------------------------------------------------
// Coverage

const STATUS_RANK = { gap: 0, unbound: 0, several: 1, proposed: 2, yours: 3, pack: 4 };

function betterStatus(a, b) {
  return (STATUS_RANK[a] ?? -1) >= (STATUS_RANK[b] ?? -1) ? a : b;
}

function tierRank(tier) {
  return tier === "high" ? 2 : tier === "several" || tier === "medium" ? 1 : 0;
}

// column -> [proposal, ...] and (platform,container,concept) -> the single
// best proposal for that concept there (for a blocker's "missing" entry).
// A caller may already sort a triple's proposals best first (proposeBindings
// does); this only re-picks when it cannot tell, so it never disagrees with
// the caller's own ordering.
function indexProposals(proposals) {
  const byTriple = new Map();
  const byConceptContainer = new Map();
  for (const p of proposals || []) {
    if (!p || !p.platform || !p.container || !p.column || !p.concept) continue;
    const tk = `${p.platform} ${p.container} ${p.column}`;
    if (!byTriple.has(tk)) byTriple.set(tk, []);
    byTriple.get(tk).push(p);
    const ck = `${p.platform} ${p.container} ${p.concept}`;
    const cur = byConceptContainer.get(ck);
    if (!cur || tierRank(p.tier) > tierRank(cur.tier) || (tierRank(p.tier) === tierRank(cur.tier) && (p.score || 0) > (cur.score || 0))) byConceptContainer.set(ck, p);
  }
  return { byTriple, byConceptContainer };
}

function packIndex(packs) {
  const byId = new Map();
  const roster = new Map(); // packId -> [{key,id,label,type}]
  for (const p of packs || []) {
    if (!p || !p.id) continue;
    byId.set(p.id, p);
    const list = [];
    for (const [id, rec] of Object.entries(p.concepts || {})) list.push({ key: `${p.id}/${id}`, id, label: (rec && rec.label) || id.replace(/_/g, " "), type: (rec && rec.type) || null });
    roster.set(p.id, list);
  }
  return { byId, roster };
}

function conceptLabel(roster, key) {
  const pid = key.split("/")[0];
  const hit = (roster.get(pid) || []).find((c) => c.key === key);
  return hit ? hit.label : key.split("/").pop().replace(/_/g, " ");
}

// The pack the container's own resolved columns mostly carry; falling back
// to the pack its proposals mostly carry when nothing is resolved yet.
// null ("not recognised") when neither exists.
function electedFeedOf(env, container, propByTriple) {
  const tally = new Map();
  for (const col of container.columns || []) {
    const pid = packOf({ concept: col.concept });
    if (pid) tally.set(pid, (tally.get(pid) || 0) + 1);
  }
  if (!tally.size) {
    for (const col of container.columns || []) {
      for (const p of propByTriple.get(`${env.platform} ${container.name} ${col.column}`) || []) {
        const pid = p.concept && p.concept.includes("/") ? p.concept.split("/")[0] : null;
        if (pid) tally.set(pid, (tally.get(pid) || 0) + 1);
      }
    }
  }
  if (!tally.size) return null;
  return Array.from(tally.entries()).sort((a, b) => b[1] - a[1])[0][0];
}

// The bare or qualified concept refs an edge's intent filters on, plus (when
// the intent also filters on record_types) the feed's discriminator. These
// are the only refs `plan().unresolved` is allowed to block on here (the
// task's own rule): an unresolved shape concept (a project, a by, a
// measure, an order) is dropped by the compilers instead of failing, so it
// is never a blocker, however plan() lists it.
function blockingRefs(intent, pack) {
  const refs = [];
  for (const f of intent.filter || []) {
    if (!f) continue;
    if (Array.isArray(f.any)) {
      for (const c of f.any) if (c && c.concept) refs.push(c.concept);
    } else if (f.concept) {
      refs.push(f.concept);
    }
  }
  if (intent.record_types && intent.record_types.length) {
    const disc = pack.feed && pack.feed.discriminator;
    if (disc) refs.push(disc);
  }
  return refs;
}

// One edge's missing concepts on this container, from the real plan: every
// ref plan() could not resolve there, kept only when it is also one of
// this edge's blocking refs (a filter or the record-type discriminator),
// named once, with the best proposal for it here, if any. `planFn` is
// intent.js's own `plan`, injected by the caller (never imported here: see
// the header) - without one, blockers cannot be told from a column list
// coverage() cannot trust to be complete, so none are reported.
function edgeMissing(edge, pack, env, container, propByConceptContainer, roster, planFn) {
  if (typeof planFn !== "function") return [];
  const allowed = new Set(blockingRefs(edge.intent, pack).map((ref) => (ref.includes("/") ? ref : `${pack.id}/${ref}`)));
  if (!allowed.size) return [];
  let planned;
  try {
    planned = planFn(edge.intent, { pack, platform: env.platform, container: container.name });
  } catch (err) {
    if (!(edge.intent.scope === "type" && err && err.code === "no_containers")) return [];
    planned = { scope: "type", union: [] };
  }
  // A scope "type" plan unions the containers that carry its filter
  // concepts; one it left out lacks them here, whatever the union resolved
  // elsewhere.
  const unresolved = planned && planned.scope === "type"
    ? (planned.union || []).some((u) => u && u.container === container.name) ? [] : Array.from(allowed)
    : (planned && planned.unresolved) || [];
  const out = [];
  const seen = new Set();
  for (const ref of unresolved) {
    if (typeof ref !== "string") continue;
    const key = ref.includes("/") ? ref : `${pack.id}/${ref}`;
    if (!allowed.has(key) || seen.has(key)) continue;
    seen.add(key);
    const proposal = propByConceptContainer.get(`${env.platform} ${container.name} ${key}`) || null;
    out.push({ concept: key, label: conceptLabel(roster, key), proposal: proposal ? { column: proposal.column, tier: proposal.tier } : null });
  }
  return out;
}

export function coverage({ environments = [], platform = null, packs = [], learned = [], proposals = [], plan = null } = {}) {
  const { byId: packsById, roster } = packIndex(packs);
  const learnedByTriple = new Map();
  for (const rec of normaliseBindings(learned)) learnedByTriple.set(tripleKey(rec), rec);
  const { byTriple: propByTriple, byConceptContainer: propByConceptContainer } = indexProposals(proposals);

  const envOut = [];
  for (const env of environments || []) {
    // packId -> Map(conceptKey -> ConceptCoverage)
    const feedConcepts = new Map();
    const conceptRow = (packId, key) => {
      if (!feedConcepts.has(packId)) {
        const m = new Map();
        for (const c of roster.get(packId) || []) m.set(c.key, { key: c.key, id: c.id, label: c.label, type: c.type, known: true, status: "gap", on: [] });
        feedConcepts.set(packId, m);
      }
      const m = feedConcepts.get(packId);
      if (!m.has(key)) m.set(key, { key, id: key.split("/").pop(), label: conceptLabel(roster, key), type: null, known: roster.has(packId), status: "gap", on: [] });
      return m.get(key);
    };

    const containers = [];
    for (const container of env.containers || []) {
      const cols = container.columns || [];
      const feedPackId = electedFeedOf(env, container, propByTriple);
      const feedPack = feedPackId ? packsById.get(feedPackId) : null;
      const feedLabel = feedPack ? (feedPack.feed && feedPack.feed.label) || feedPack.name : null;

      let bound = 0;
      let yours = 0;
      let proposedCount = 0;
      let unbound = 0;
      for (const col of cols) {
        const tk = tripleKey({ platform: env.platform, container: container.name, column: col.column });
        const learnedRec = learnedByTriple.get(tk);
        let status;
        let conceptKey = col.concept || null;
        if (conceptKey) {
          const isYours = Boolean(learnedRec && learnedRec.basis === "confirmed" && learnedRec.concept === conceptKey);
          status = isYours ? "yours" : "pack";
          if (isYours) yours++;
          bound++;
        } else if (learnedRec && learnedRec.basis === "dismissed" && !learnedRec.concept) {
          status = "unbound"; // set aside entirely: still unbound, never a lead
          unbound++;
        } else {
          const best = (propByTriple.get(`${env.platform} ${container.name} ${col.column}`) || [])[0];
          if (best) {
            conceptKey = best.concept;
            status = best.tier === "high" ? "proposed" : "several";
            proposedCount++;
          } else {
            status = "unbound";
            unbound++;
          }
        }
        if (conceptKey) {
          const pid = conceptKey.includes("/") ? conceptKey.split("/")[0] : null;
          if (pid) {
            const row = conceptRow(pid, conceptKey);
            row.status = betterStatus(row.status, status);
            row.on.push({ container: container.name, column: col.column, status });
          }
        }
      }

      const blockers = [];
      let ready = 0; // intent edges with nothing missing here: they compile now
      if (feedPack) {
        for (const edge of feedPack.edges || []) {
          if (!edge || !edge.intent) continue;
          const missing = edgeMissing(edge, feedPack, env, container, propByConceptContainer, roster, plan);
          if (missing.length) blockers.push({ edgeId: edge.id, label: edge.label || edge.id, missing });
          else ready++;
        }
      }

      containers.push({ name: container.name, feedPackId, feedLabel, columns: cols.length, counts: { bound, yours, proposed: proposedCount, unbound }, blockers, pivots: { ready, blocked: blockers.length } });
    }

    const feeds = [];
    for (const [packId, m] of feedConcepts) {
      const list = Array.from(m.values());
      const pack = packsById.get(packId);
      feeds.push({
        packId,
        label: (pack && ((pack.feed && pack.feed.label) || pack.name)) || packId,
        concepts: list,
        carried: list.filter((c) => c.status === "pack" || c.status === "yours").length,
        proposed: list.filter((c) => c.status === "proposed" || c.status === "several").length,
        gaps: list.filter((c) => c.status === "gap").length,
      });
    }
    feeds.sort((a, b) => a.label.localeCompare(b.label));

    envOut.push({ key: env.key, platform: env.platform, thisPlatform: platform ? env.platform === platform : null, feeds, containers });
  }
  return { environments: envOut };
}

// A ContainerCoverage's blockers, in one sentence. Every missing concept
// across every blocking edge, named once (a container can miss the same
// concept for several pivots at once), a proposal noted when there is one.
// The sentence stays short: the concepts with a sure proposal first (one
// click away), then the maybes, then the ones with nothing to point at,
// and after `limit` of them "and N more". limit 0 or null names them all.
const GAP_RANK = { high: 0, several: 1, medium: 1 };

export function intentGaps(container, { limit = 3 } = {}) {
  if (!container || !Array.isArray(container.blockers) || !container.blockers.length) return null;
  const byKey = new Map();
  for (const b of container.blockers) for (const m of b.missing || []) if (!byKey.has(m.concept)) byKey.set(m.concept, m);
  const rank = (m) => (m.proposal ? GAP_RANK[m.proposal.tier] ?? 1 : 2);
  const all = Array.from(byKey.values()).sort((a, b) => rank(a) - rank(b));
  const shown = limit && all.length > limit ? all.slice(0, limit) : all;
  const parts = shown.map((m) => {
    const suffix = m.proposal ? (m.proposal.tier === "high" ? `(proposal: ${m.proposal.column}, sure)` : `(maybe ${m.proposal.column})`) : "(pick a column)";
    return `${m.label} ${suffix}`;
  });
  const more = all.length - shown.length;
  if (more) parts.push(`${more} more`);
  const list = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0];
  const feed = container.feedLabel ? `${container.feedLabel} pivots` : "Pivots";
  return `${feed} here still need ${list}.`;
}

export default { LEARNED_ID, normaliseBindings, learnedPack, mergeBindings, isInert, shadowingPack, decidedAt, packOf, tripleKey, coverage, intentGaps };
