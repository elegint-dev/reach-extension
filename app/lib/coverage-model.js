// coverage-model: what the Coverage page computes, apart from how it is drawn.
//
// The pure model behind app/views/coverage.js: the adapters and the words,
// no DOM. tests/coverage-view.test.js holds them:
//
//   envPlatform(key, env)                  -> "splunk" | "sentinel"   an ARM resource id is a workspace
//   envLabel(key, env)                     -> the words for the environment select
//   columnsOf(rec, extra?)                 -> [ { column, profile, provenance, declared } ] fields plus decode keys plus extra
//   environmentsFor(layer, { resolve, learnedRecords }) -> [ { key, platform, label, containers: [ { name, rec, columns, vanished, missingSince } ] } ]
//                                             learned.coverage()'s and propose.matches()'s input; concept via resolve()
//   partitionVanished(containers)           -> { live, vanished }   a container the latest inventory did not return is vanished
//   withoutVanished(environments)           -> the same list with the vanished containers dropped: what the counts are computed over by default
//   vocabularyConcepts({ packIds, conceptsOf, bindingsOf }) -> propose.vocabulary()'s concepts input, learned pack left out
//   dismissedOn(learnedRecords, platform, container) -> [ { column, concept } ]
//   setAsideRows(learnedRecords, platform, container, proposals) -> [ { column, record, refused: [concept], leftAlone } ]
//                                             the Skipped fields fold: a column left alone, or one whose every sure candidate was refused
//   asideWords(entry, labelOf)              -> "not CIM user ARN, not CIM user, not Principal ARN" | "left alone"
//   onWord(entry, rowStatus)                -> "proposed" | "" : a carried-on entry's own status when it differs from the roll-up's
//   proposalsFor(env, container, { vocabulary, learnedRecords, forcedFeed }) -> { feed: { packId, basis, votes, forced }, proposals }
//   rowsFor(env, container, { proposals, learnedRecords, labelOf, blockers }) -> [Row]
//     Row: { id, column, fill, looksLike, state, concept, label, packId, proposal, record, unblocks }
//     state: "pack" | "yours" | "proposed" | "several" | "medium" | "dismissed" | "unbound"
//            dismissed: set aside outright, or every sure candidate refused (no proposal left)
//   looksLike(profile)                      -> "ARN" | "IP" | ... | null
//   whyLine(proposal, { unblocks })         -> "name matches UserIdentityArn; 3 of 3 top values look like ARNs; unblocks 2 pivots"
//   resultLine(column, label)               -> "Bound PrincipalArn to Principal ARN."
//   blockerLine(containerCoverage)          -> "No pivot yet: <intentGaps sentence>" | "Notes on this column now show on every SIEM."
//   feedSentence(feed, labelOf)             -> "CloudTrail, from 31 matching names" | "not recognised"
//   confirmAllDisabled(feed, proposals)     -> true on a feed elected by names, or with no sure match
//   confirmAllReason(feed, proposals)       -> why it is disabled, in a sentence, or null
//   sureProposals(proposals, { platform, container, resolve, learnedRecords }) -> what Confirm all writes: the sure rows not bound by now
//   matchProposals(leads, { platform, feedOf, resolve, learnedRecords }) -> rule 8: a match with one bound side, as a proposal row for the other
//   mergeProposals(nameRows, matchRows) -> one row per triple: the name row, unless only the match is sure of a different concept
//   siblingOffers(env, container, column, concept, { learnedRecords, conceptType, feedOf }) -> [ { container, column, profiled, agrees, checked } ]
//                                             feedOf(container) -> packId: only a table elected to the concept's pack is offered
//   evidenceFor(proposal, conceptKey)      -> the evidence a confirm stores: the proposal's own, an alternative's score, or manual
//   chooseGroups({ feedPackId, proposal, feeds }) -> [ { label, options: [ { key, label, score } ] } ]
//   envStats(envCoverage)                   -> { concepts, carried, proposed, gaps, tables }
//   sweepWords(rec)                         -> "Computed over a full discovery sweep at T (n of N sourcetypes)." | ""
//   STATE_CHIP                              the chip per row state

import * as learned from "./learned.js";
import * as propose from "./propose.js";
import { classify, shapeVeto, numericVeto } from "./shapes.js";
import { isResourceId, workspaceNameOf } from "./kql.js";
// ---------------------------------------------------------------------------
// Words

const SHAPE_WORDS = {
  arn: "ARN",
  aws_access_key: "access key",
  aws_principal_id: "principal id",
  bool: "yes/no",
  domain: "domain",
  email: "email",
  epoch: "epoch time",
  guid: "GUID",
  hash: "hash",
  hex32: "32-hex id",
  integer: "number",
  ip: "IP",
  iso_time: "time",
  json: "JSON",
  sid: "SID",
  upn: "UPN",
  url: "URL",
};

const SHAPE_PLURAL = { arn: "ARNs", ip: "IPs", guid: "GUIDs", sid: "SIDs", upn: "UPNs", url: "URLs", email: "emails", domain: "domains", hash: "hashes", json: "JSON", bool: "yes/no", integer: "numbers", iso_time: "times", epoch: "epoch times", hex32: "32-hex ids", aws_access_key: "access keys", aws_principal_id: "principal ids" };

export const STATE_CHIP = {
  pack: { value: "confirmed", text: "pack" },
  yours: { value: "confirmed", text: "yours" },
  proposed: { value: "suggested", text: "proposed", confidence: "high" },
  several: { value: "suggested", text: "several fit", confidence: "medium" },
  medium: { value: "suggested", text: "maybe", confidence: "low" },
  dismissed: { value: "inferred", text: "set aside" },
  inert: { value: "confirmed", text: "yours" },
  gap: { value: "inferred", text: "gap" },
};

const FEED_BASIS_WORDS = { bindings: "from its bindings", literals: "from its values", names: "from matching names" };

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

// ---------------------------------------------------------------------------
// Adapters: the stored layer into the pure modules' input shapes

export function envPlatform(key, env) {
  if (isResourceId(key)) return "sentinel";
  if (/^https?:\/\//.test(String(key || ""))) return "splunk";
  return env && (env.resourceId || env.tenantId) ? "sentinel" : "splunk";
}

export function envLabel(key, env) {
  if (envPlatform(key, env) === "sentinel") return (env && env.label) || workspaceNameOf(key) || String(key);
  return String(key);
}

export function columnsOf(rec, extra = []) {
  const fields = (rec && rec.fields) || {};
  const names = new Set(Object.keys(fields));
  for (const d of Object.keys((rec && rec.decodes) || {})) names.add(d);
  for (const e of extra || []) if (e) names.add(e);
  return Array.from(names)
    .sort()
    .map((column) => {
      const f = fields[column] || {};
      return { column, profile: f.profile || null, provenance: f.provenance || null, declared: f.declared || null };
    });
}

// The layer ({ [envKey]: { sourcetypes: { [st]: rec } } }) into the shape
// learned.coverage() and propose.matches() take. Each column's concept is
// whatever `resolve(platform, container, column)` answers (concepts.resolve
// in the app: pack or learned binding alike); a learned record's column is
// listed even when the last profile did not report it, so it can be unbound.
export function environmentsFor(layer, { resolve = () => null, learnedRecords = [] } = {}) {
  const out = [];
  for (const [key, env] of Object.entries(layer || {})) {
    const platform = envPlatform(key, env);
    const containers = [];
    for (const [name, rec] of Object.entries((env && env.sourcetypes) || {})) {
      const extra = learnedRecords.filter((b) => b.platform === platform && b.container === name).map((b) => b.column);
      const columns = columnsOf(rec, extra).map((c) => {
        const r = resolve(platform, name, c.column);
        return { ...c, concept: r ? r.key : null };
      });
      containers.push({ name, rec, columns, vanished: Boolean(rec && rec.missing_since), missingSince: (rec && rec.missing_since) || null });
    }
    containers.sort((a, b) => a.name.localeCompare(b.name));
    out.push({ key, platform, label: envLabel(key, env), containers });
  }
  return out;
}

// A sourcetype the latest inventory over its indexes did not return
// (discovery.js marks it missing_since) is kept in the layer, so a feed
// that stopped can be seen to have stopped, but it is not what the
// environment carries now. The counts leave it out unless asked.
export function partitionVanished(containers) {
  const live = [];
  const vanished = [];
  for (const c of containers || []) (c.vanished ? vanished : live).push(c);
  return { live, vanished };
}

export function withoutVanished(environments) {
  return (environments || []).map((e) => ({ ...e, containers: partitionVanished(e.containers).live }));
}

// propose.vocabulary()'s concepts input from the live resolver: every
// concept of the listed packs with every pack binding pointing at it, on
// either platform. The learned pack's bindings are left out here (they go
// in as `learned`, uncapped), and a concept is listed under the pack that
// owns it, so a sample pack's qualified bindings land on the owner.
export function vocabularyConcepts({ packIds = [], conceptsOf, bindingsOf } = {}) {
  const out = [];
  for (const packId of packIds) {
    for (const c of conceptsOf(packId) || []) {
      const bindings = (bindingsOf(c.key) || [])
        .filter((b) => b.packId !== learned.LEARNED_ID)
        .map((b) => ({ platform: b.platform, container: b.container, column: b.column, alias_of: b.alias_of || null, cim: b.cim || null }));
      out.push({ key: c.key, id: c.id, label: c.label, type: c.type || null, decode: c.decode || null, cim: c.cim || null, bindings });
    }
  }
  return out;
}

export function dismissedOn(learnedRecords, platform, container) {
  const out = [];
  for (const b of learnedRecords || []) {
    if (b.basis !== "dismissed" || b.platform !== platform || b.container !== container) continue;
    if (!b.concept && !(b.dismissed || []).length) { out.push({ column: b.column, concept: null }); continue; } // set aside outright
    for (const c of new Set([...(b.dismissed || []), ...(b.concept ? [b.concept] : [])])) out.push({ column: b.column, concept: c });
    if (!b.concept) out.push({ column: b.column, concept: null });
  }
  return out;
}

// The Skipped fields fold, one entry per column: a column dismissed outright
// (concept null), or one whose refusals left no proposal (proposeBindings
// offers only a sure survivor once a concept was refused; none left, and
// the column is set aside). A column with a refusal that still has a
// proposal stays in the table, with the refusal named on its row, and is
// not listed here: once is enough.
export function setAsideRows(learnedRecords, platform, container, proposals = []) {
  const proposed = new Set((proposals || []).filter((p) => p.platform === platform && p.container === container).map((p) => p.column));
  const out = [];
  for (const b of learnedRecords || []) {
    if (b.basis !== "dismissed" || b.platform !== platform || b.container !== container) continue;
    if (b.concept && proposed.has(b.column)) continue;
    const refused = Array.from(new Set([...(b.dismissed || []), ...(b.concept ? [b.concept] : [])]));
    out.push({ column: b.column, record: b, refused, leftAlone: !b.concept });
  }
  return out;
}

export function asideWords(entry, labelOf = (k) => k) {
  const nots = (entry.refused || []).map((k) => `not ${labelOf(k)}`).join(", ");
  if (!nots) return "left alone";
  return entry.leftAlone ? `left alone; ${nots}` : nots;
}

// The roll-up row carries the concept's best status anywhere; each entry
// under "carried on" says its own when it differs, so a concept the pack
// covers on one table and a proposal covers on another does not read as
// covered on both.
export function onWord(entry, rowStatus) {
  if (!entry || !entry.status || entry.status === rowStatus) return "";
  return entry.status === "several" ? "several fit" : entry.status;
}

function confirmedRecord(learnedRecords, platform, container, column) {
  return (learnedRecords || []).find((b) => b.platform === platform && b.container === container && b.column === column) || null;
}

// Elect the container's feed and propose for its unbound columns. Every
// resolved column (pack or learned) goes in as packBound so nothing is ever
// proposed over a binding and the alias route can find its source. A feed
// from the URL (?feed=) overrides the election: the escape hatch for a
// table the vote did not recognise.
export function proposalsFor(env, container, { vocabulary, learnedRecords = [], forcedFeed = null } = {}) {
  const rec = container.rec || {};
  const columns = container.columns.map((c) => ({ column: c.column, profile: c.profile, provenance: c.provenance }));
  const packBound = container.columns.filter((c) => c.concept).map((c) => ({ column: c.column, concept: c.concept }));
  const recordTypes = rec.discriminator && Array.isArray(rec.record_types) && rec.record_types.length ? { column: rec.discriminator, values: rec.record_types } : null;
  const elect = vocabulary ? propose.electFeed(container.name, columns, { vocabulary, decodes: rec.decodes || {}, recordTypes, existingBindings: packBound.map((b) => ({ concept: b.concept })) }) : { feedPackId: null, basis: null, votes: {} };
  const feedPackId = forcedFeed || elect.feedPackId;
  const feed = { packId: feedPackId, basis: forcedFeed && forcedFeed !== elect.feedPackId ? "forced" : elect.basis, votes: elect.votes || {}, forced: Boolean(forcedFeed) };
  let proposals = [];
  if (feedPackId && vocabulary) {
    const dismissed = dismissedOn(learnedRecords, env.platform, container.name);
    proposals = propose.proposeBindings({ container: container.name, columns, vocabulary, feed: feedPackId, dismissed, packBound }).map((p) => ({ ...p, platform: env.platform, container: container.name }));
  }
  return { feed, proposals };
}

// ---------------------------------------------------------------------------
// Rows and words

export function looksLike(profile) {
  if (!profile || !Array.isArray(profile.top) || !profile.top.length) return null;
  const c = classify(profile.top);
  if (!c.shape || c.share < 0.5) return null;
  return SHAPE_WORDS[c.shape] || c.shape;
}

function tierState(tier) {
  return tier === "high" ? "proposed" : tier === "several" ? "several" : tier === "medium" ? "medium" : "unbound";
}

// Which of the container's blocked pivots a concept would unblock.
function unblocksOf(blockers, conceptKey) {
  const out = [];
  for (const b of blockers || []) if ((b.missing || []).some((m) => m.concept === conceptKey)) out.push(b.edgeId);
  return out;
}

export function rowsFor(env, container, { proposals = [], learnedRecords = [], labelOf = (k) => k, blockers = [] } = {}) {
  const byColumn = new Map();
  for (const p of proposals) if (p.container === container.name && !byColumn.has(p.column)) byColumn.set(p.column, p);
  return container.columns.map((c) => {
    const record = confirmedRecord(learnedRecords, env.platform, container.name, c.column);
    let proposal = byColumn.get(c.column) || null;
    let state = "unbound";
    let concept = c.concept || null;
    if (concept) state = record && record.basis === "confirmed" && record.concept === concept ? "yours" : "pack";
    else if (record && record.basis === "confirmed" && record.concept) {
      // Confirmed to a concept no loaded pack defines (a teammate's export
      // for a pack this browser lacks): still the analyst's decision. Shown
      // as theirs, waiting for that pack; never proposed over.
      state = "inert";
      concept = record.concept;
      proposal = null;
    } else if (record && record.basis === "dismissed" && (!record.concept || !proposal)) state = "dismissed"; // left alone, or every sure candidate refused
    else if (proposal) {
      state = tierState(proposal.tier);
      concept = proposal.concept;
    }
    const pid = concept && concept.includes("/") ? concept.split("/")[0] : null;
    return {
      id: c.column,
      column: c.column,
      fill: c.profile && c.profile.fill !== null && c.profile.fill !== undefined ? c.profile.fill : null,
      looksLike: looksLike(c.profile),
      state,
      concept,
      label: concept ? labelOf(concept) : null,
      packId: pid,
      proposal,
      record,
      unblocks: proposal ? unblocksOf(blockers, proposal.concept) : [],
    };
  });
}

export function whyLine(proposal, { unblocks = [] } = {}) {
  if (!proposal) return "";
  const ev = proposal.evidence || {};
  const parts = [];
  // evidence.from says "shape" whenever the values confirmed the name; only
  // a via of "shape:<x>" means the values carried it on their own.
  const viaShape = typeof ev.via === "string" && ev.via.startsWith("shape:");
  if (ev.from === "alias") parts.push(ev.via || `alias of ${proposal.alias_of}`);
  else if (ev.from === "calculated") parts.push(ev.via || `calculated from ${proposal.alias_of}`);
  else if (ev.from === "match") parts.push(ev.matched ? `${plural(ev.matched, "value", "values")} shared with ${ev.via}` : `same name and shape as ${ev.via}`);
  else if (viaShape) parts.push("the values decide it");
  else if (ev.via) parts.push(`name matches ${ev.via}`);
  else parts.push("name matches");
  // Distinct top values, the list a reader can check, not the event-weighted
  // sum classify() scores on (that read "27 of 27" beside "3 distinct").
  if (ev.shape && ev.hits !== null && ev.hits !== undefined && ev.values) parts.push(`${ev.hits} of ${ev.values} top values look like ${SHAPE_PLURAL[ev.shape] || ev.shape}`);
  else if (ev.shape && ev.matched !== null && ev.matched !== undefined && ev.total) parts.push(`the top values look like ${SHAPE_PLURAL[ev.shape] || ev.shape}`);
  if (unblocks.length) parts.push(`unblocks ${plural(unblocks.length, "pivot", "pivots")}`);
  return parts.join("; ");
}

export function resultLine(column, label) {
  return `Bound ${column} to ${label}.`;
}

// After a confirm: what compiles here now, and what is still waiting. The
// line never says "no pivot yet" while some of the feed's pivots compile.
export function blockerLine(containerCoverage) {
  const gaps = learned.intentGaps(containerCoverage);
  const ready = containerCoverage && containerCoverage.pivots ? containerCoverage.pivots.ready : 0;
  if (!gaps) return `${ready ? `${plural(ready, "pivot compiles", "pivots compile")} here now. ` : ""}Notes on this column now show on every SIEM.`;
  if (ready) return `${plural(ready, "pivot compiles", "pivots compile")} here now. ${gaps}`;
  return `No pivot yet: ${gaps}`;
}

export function feedSentence(feed, labelOf = (k) => k) {
  if (!feed || !feed.packId) return "not recognised";
  const label = labelOf(feed.packId);
  if (feed.basis === "forced") return `${label}, your pick`;
  if (feed.basis === "names") {
    const n = feed.votes && feed.votes[feed.packId];
    return n ? `${label}, from ${plural(n, "matching name", "matching names")}` : `${label}, ${FEED_BASIS_WORDS.names}`;
  }
  return FEED_BASIS_WORDS[feed.basis] ? `${label}, ${FEED_BASIS_WORDS[feed.basis]}` : label;
}

export function confirmAllDisabled(feed, proposals = []) {
  return confirmAllReason(feed, proposals) !== null;
}

export function confirmAllReason(feed, proposals = []) {
  if (!feed || !feed.packId) return "Not recognised as one feed, so nothing is sure.";
  if (feed.basis === "names") return "This feed was recognised from names alone; confirm its columns one by one.";
  if (!proposals.some((p) => p.tier === "high")) return "No sure match left to confirm.";
  return null;
}

// What Confirm all writes: the sure (high) proposals on this container,
// less any column that is bound by now (resolves, or holds a confirmed
// record). Computed inside the click handler from a fresh model, never
// from the list the page was drawn with, so a row confirmed in place is
// not bound twice and the count reported is the count written.
export function sureProposals(proposals, { platform, container, resolve = () => null, learnedRecords = [] } = {}) {
  const out = [];
  const seen = new Set();
  for (const p of proposals || []) {
    if (p.tier !== "high" || p.platform !== platform || p.container !== container || seen.has(p.column)) continue;
    seen.add(p.column);
    if (resolve(platform, container, p.column)) continue;
    const rec = confirmedRecord(learnedRecords, platform, container, p.column);
    if (rec && rec.basis === "confirmed") continue;
    out.push(p);
  }
  return out;
}

// Rule 8 on the page: propose.matches() pairs found on mount, read against
// the live resolver. A pair with exactly one bound side proposes that
// side's concept for the other, as a proposal row shaped like
// proposeBindings()'s (evidence.from "match", via the bound column), on
// this platform only, and only where the target table's elected feed
// (`feedOf(envKey, name)`) is the concept's pack: the feed rule matches()
// leaves to its caller. A dismissed pair is skipped; one row per triple,
// the strongest overlap first since matches() sorts that way. The caller
// folds these into proposeBindings()'s rows with mergeProposals().
export function matchProposals(leads, { platform, feedOf = () => null, resolve = () => null, learnedRecords = [] } = {}) {
  const out = [];
  const seen = new Set();
  for (const x of leads || []) {
    if (!x || !x.a || !x.b) continue;
    const ra = resolve(x.a.platform, x.a.container, x.a.column);
    const rb = resolve(x.b.platform, x.b.container, x.b.column);
    if (Boolean(ra) === Boolean(rb)) continue;
    const bound = ra ? x.a : x.b;
    const target = ra ? x.b : x.a;
    const concept = (ra || rb).key;
    if (!concept || target.platform !== platform) continue;
    const tk = `${target.container}\0${target.column}`;
    if (seen.has(tk)) continue;
    if (feedOf(target.env, target.container) !== learned.packOf({ concept })) continue;
    if (dismissedOn(learnedRecords, platform, target.container).some((d) => d.column === target.column && (d.concept === null || d.concept === concept))) continue;
    seen.add(tk);
    out.push({
      platform,
      container: target.container,
      column: target.column,
      concept,
      tier: propose.matchTier(x),
      score: null,
      runnerUp: null,
      evidence: { from: "match", score: null, via: `${bound.container}.${bound.column}`, shape: x.shape || null, matched: x.overlap, total: null },
      alias_of: null,
      alternatives: [],
    });
  }
  return out;
}

// The name route's rows and the match rows as one list, one row per
// triple. A column only one route proposes takes that row. On a column
// both propose: the same concept keeps the name row (its evidence is the
// fuller story); a different concept goes to the sure side, the match row
// when it is high and the name row is not (two shared values outweigh a
// close call between spellings), else the name row.
export function mergeProposals(nameRows, matchRows) {
  const keyOf = (p) => `${p.platform}\0${p.container}\0${p.column}`;
  const out = [];
  const at = new Map();
  for (const p of nameRows || []) {
    at.set(keyOf(p), out.length);
    out.push(p);
  }
  for (const m of matchRows || []) {
    const k = keyOf(m);
    if (!at.has(k)) {
      at.set(k, out.length);
      out.push(m);
      continue;
    }
    const cur = out[at.get(k)];
    if (cur.concept !== m.concept && m.tier === "high" && cur.tier !== "high") out[at.get(k)] = m;
  }
  return out;
}

// Nothing in the column's values says the concept is wrong: no dominant
// shape the type vetoes, and not an all-numeric column for a type whose
// values are never numbers. null when the column has no profile at all.
function shapeAgrees(profile, conceptType) {
  if (!profile || !Array.isArray(profile.top) || !profile.top.length) return null;
  if (profile.numeric && numericVeto(conceptType)) return false;
  const c = classify(profile.top);
  if (c.shape && c.total >= 3 && c.share >= 0.5 && shapeVeto(c.shape, conceptType)) return false;
  return true;
}

// The same column (by normalised name) on the environment's other tables
// where nothing binds it yet: offered after a confirm, pre-checked when the
// table was profiled and its values do not disagree with the concept. The
// feed gate is the one the primary confirm passed: a sibling is offered
// only on a table whose elected feed (`feedOf(name)`, the election the
// page already ran) is the concept's own pack, so "Bind these" can never
// write onto a table the election did not recognise. No feedOf, no offers.
export function siblingOffers(env, container, column, conceptKey, { learnedRecords = [], conceptType = null, feedOf = () => null } = {}) {
  const key = propose.tokens(column).slice().sort().join(",");
  if (!key) return [];
  const packId = learned.packOf({ concept: conceptKey });
  if (!packId) return [];
  const out = [];
  for (const other of env.containers || []) {
    if (other.name === container) continue;
    if (feedOf(other.name) !== packId) continue;
    for (const c of other.columns || []) {
      if (c.concept) continue;
      if (propose.tokens(c.column).slice().sort().join(",") !== key) continue;
      const rec = confirmedRecord(learnedRecords, env.platform, other.name, c.column);
      if (rec && rec.basis === "dismissed" && (!rec.concept || rec.concept === conceptKey)) continue;
      const profiled = Boolean(c.profile && Array.isArray(c.profile.top) && c.profile.top.length);
      const agrees = shapeAgrees(c.profile, conceptType);
      out.push({ container: other.name, column: c.column, profiled, agrees, checked: profiled && agrees === true });
    }
  }
  return out;
}

// The Choose select: the feed's concepts first (the proposal's alternatives
// at the top, best first), then every other feed under its own heading.
// The evidence a confirm stores for a concept picked from the proposal's
// alternatives: the name route's story with that alternative's own score.
// A pick outside the alternatives is manual.
export function evidenceFor(proposal, conceptKey) {
  const blank = { from: "manual", score: null, via: null, shape: null, matched: null, total: null };
  if (!proposal) return blank;
  const ev = proposal.evidence || {};
  if (proposal.concept === conceptKey) return { ...blank, ...ev, from: ev.from || "manual" };
  const alt = (proposal.alternatives || []).find((a) => a.concept === conceptKey);
  if (!alt) return blank;
  return { from: ev.from || "name", score: alt.score, via: ev.via || null, shape: null, matched: null, total: null };
}

export function chooseGroups({ feedPackId = null, proposal = null, feeds = [] } = {}) {
  const alts = new Map();
  for (const a of (proposal && proposal.alternatives) || []) alts.set(a.concept, a.score);
  if (proposal && proposal.concept) alts.set(proposal.concept, proposal.score);
  const groups = [];
  const ordered = [...feeds.filter((f) => f.id === feedPackId), ...feeds.filter((f) => f.id !== feedPackId)];
  for (const f of ordered) {
    const own = (f.concepts || []).map((c) => ({ key: c.key, label: c.label, score: alts.has(c.key) ? alts.get(c.key) : null }));
    if (f.id === feedPackId) own.sort((a, b) => (b.score === null ? -1 : b.score) - (a.score === null ? -1 : a.score) || a.label.localeCompare(b.label));
    else own.sort((a, b) => a.label.localeCompare(b.label));
    if (own.length) groups.push({ label: f.label, options: own });
  }
  return groups;
}

export function envStats(envCoverage) {
  let conceptsN = 0;
  let carried = 0;
  let proposed = 0;
  let gaps = 0;
  for (const f of (envCoverage && envCoverage.feeds) || []) {
    conceptsN += f.concepts.length;
    carried += f.carried;
    proposed += f.proposed;
    gaps += f.gaps;
  }
  return { concepts: conceptsN, carried, proposed, gaps, tables: ((envCoverage && envCoverage.containers) || []).length };
}

// A discovered record stamped by a full discovery sweep (discovery-sweep.js)
// says so: the picture below is over every sourcetype, not a few rows.
export function sweepWords(rec) {
  const sw = rec && rec.sweep;
  if (!sw || !sw.at) return "";
  const when = new Date(sw.at);
  return `Computed over a full discovery sweep at ${Number.isNaN(when.getTime()) ? String(sw.at) : when.toLocaleString()}${sw.total ? ` (${sw.done} of ${sw.total} sourcetypes)` : ""}.`;
}
