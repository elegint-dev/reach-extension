// The name-first proposer: what a column probably means, from its name,
// the vocabulary of every column already bound to a concept, and (where
// given) its top values. Nothing here queries or stores; every input is
// passed in by the caller (the learned layer, or a dev tool), which is how
// the leave-one-container-out check in tools/dev/check-bindings.mjs works.
// Reach never runs a query on Sentinel and never touches the network from
// here: this module reads what discovery already wrote, nothing more.
//
//   tokens(name)                          -> [token]     camel/Pascal/snake/dot/brace split, folded, singularised
//   nameScore(tokensA, tokensB)           -> 0..1         column tokens vs one spelling's tokens
//   vocabulary({ platform, concepts, learned }) -> Vocabulary
//     concepts: [ { key, id, label, type, decode, cim, bindings: [{platform,container,column,alias_of,cim}] } ]
//                  cim: { from: [...] } on a computed CIM field caps its spellings (never vote, never reach
//                  high); { targets: [...] } on a raw field does not, that is the canonical spelling
//     learned:  [ { platform, container, column, concept } ]   confirmed user bindings, folded in uncapped
//     Every bound spelling carries weight 1 / (distinct concepts of its own pack it is bound to): a
//     spelling that means different things on different containers of one feed (Location, userName)
//     weighs its name score down. A spelling bound in more than one feed (Category, TimeGenerated)
//     identifies none of them on its own (distinct: false): it votes only in the election's
//     second reading, for every feed it is bound in.
//   electFeed(container, columns, { vocabulary, decodes, recordTypes, existingBindings })
//     -> { feedPackId, basis: "bindings" | "literals" | "names" | null, votes, anchors?, shared? }
//     shared: true when the names reading needed spellings a sibling pack also binds
//   proposeBindings({ platform, container, columns, vocabulary, feed, dismissed, packBound })
//     columns: [ { column, profile: { top, distinct, numeric, type } | null, provenance } ]
//     dismissed: [ { column, concept | null } ]   "not this" pairs and columns set aside outright
//     -> [ { column, concept, tier: "high" | "several" | "medium", score, runnerUp,
//            evidence: { from, score, via, shape, matched, total, values, hits }, alias_of, alternatives, refused } ]
//     matched/total weigh the top values by event count; hits/values count them (3 of 3 top values look like ARNs)
//     A refused concept is never the proposal and never an alternative, but it
//     stays in the field the tier is read against: refusing the best candidate
//     cannot promote the runner-up to high by elimination. Once a column has a
//     refusal, only a candidate that is sure on its own (a name at 0.9, or a
//     positive shape that favours it) is offered at all; with none left, the
//     column has no proposal and the page sets it aside.
//   matches({ environments }) -> [Match]   generalises recipe.proposeEdges across environments and platforms
//     Match: { a, b, name, overlap, shape, basis: "proposed", proposal: { for: "a" | "b", concept, tier } | null }
//   matchTier(match)                      -> "high" | "medium"   the tier a bound side's concept carries to the other
//   LOW_INFO, SYNONYMS, PLATFORM_DEFAULT_COLUMNS, COMMON_COLUMNS   exported for tests and the dev tool
//
// No DOM.

import { classify, shapeOf, shapeSupports, shapeVeto, numericVeto, POSITIVE_SHAPES, VETO_ONLY_SHAPES } from "./shapes.js";
import { systemFields } from "./layer.js";

// ---------------------------------------------------------------------------
// Tokens

export const LOW_INFO = new Set(["id", "name", "type", "time", "data", "address", "value", "info", "details", "string", "text", "date", "desc", "description"]);

export const SYNONYMS = {
  src: "source",
  dst: "destination",
  dest: "destination",
  usr: "user",
  acct: "account",
  ts: "timestamp",
  addr: "address",
  identifier: "id",
  ipaddress: "ip",
  ipaddr: "ip",
};

const SENTINEL_SUFFIX_RE = /_(CL|s|d|g|b|t)$/;

// Splunk's default fields, which fieldsummary reports on every sourcetype.
// They are not in layer.SYSTEM_FIELDS (discovery keeps them so the
// sourcetype page can show them), so the proposer holds its own: "host"
// must never propose a hostname concept, nor "source" a source-ip one.
export const PLATFORM_DEFAULT_COLUMNS = new Set(["host", "source", "sourcetype", "index"]);

const SYSTEM_ON_EITHER = systemFields();

function systemColumn(name) {
  return SYSTEM_ON_EITHER.has(name) || PLATFORM_DEFAULT_COLUMNS.has(name);
}

// Columns a platform puts on every table, so their presence says nothing
// about which feed a table is: the Azure Monitor resource-log common
// schema (every diagnostic table carries OperationName, CorrelationId,
// CallerIpAddress, ResultType, DurationMs...) and the fields Splunk's CIM
// and the AWS add-on stamp on every sourcetype they touch. A pack may
// bind them (SigninLogs.OperationName is a real binding) and they still
// score on an elected table; they never elect one. The list is load
// bearing: without it AuditLogs (7 votes), AzureActivity (3) and a
// flattened GuardDuty finding (3) elect a feed in
// tools/dev/check-bindings.mjs, because the packs bind these names on
// two or three containers of one feed and nothing else in the pack JSON
// says they recur on every table of the platform. Compared by lowercase.
export const COMMON_COLUMNS = new Set([
  // Azure Monitor resource logs, top-level common schema
  "timegenerated", "tenantid", "sourcesystem", "type", "resourceid", "_resourceid", "resource", "resourcegroup", "resourceprovider", "resourcetype", "subscriptionid",
  "operationname", "operationnamevalue", "operationversion", "category", "categoryvalue", "resulttype", "resultsignature", "resultdescription", "durationms",
  "callerippaddress", "calleripaddress", "correlationid", "identity", "level", "location", "properties", "properties_d", "caller", "eventdataid", "activitystatus", "activitystatusvalue",
  // Splunk CIM and add-on common fields
  "user", "src", "dest", "src_ip", "dest_ip", "src_port", "dest_port", "action", "app", "status", "signature", "signature_id", "dvc", "vendor", "product", "vendor_product", "vendor_account", "vendor_region", "aws_account_id", "aws_region", "region", "account_id", "accountid", "eventtype",
]);

function singularise(t) {
  if (t.length > 3 && t.endsWith("s") && !t.endsWith("ss") && !t.endsWith("us") && !t.endsWith("is")) return t.slice(0, -1);
  return t;
}

// Splits on ".", "_", "-", ":", "/", space and camel boundaries; the Splunk
// multivalue marker "{}" and a Sentinel custom-log suffix ("_CL", "_s"...)
// are stripped first so they never surface as tokens.
export function tokens(name) {
  let s = String(name == null ? "" : name).replace(/\{\}/g, "");
  s = s.replace(SENTINEL_SUFFIX_RE, "");
  s = s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");
  const parts = s.split(/[.\s_\-:/]+/).filter(Boolean);
  const out = [];
  for (const p of parts) {
    let t = p.toLowerCase();
    if (SYNONYMS[t]) t = SYNONYMS[t];
    t = singularise(t);
    if (t) out.push(t);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Name score: column tokens (A) against one spelling's tokens (B).

function isLowInfo(t) {
  return LOW_INFO.has(t);
}

function setOf(arr) {
  return new Set(arr);
}

function jaccardShare(a, b) {
  const union = new Set([...a, ...b]);
  if (!union.size) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return inter / union.size;
}

// Do the shared tokens appear in the same relative order on both sides?
// Undefined (treated as agreeing) below two shared tokens.
function orderAgrees(a, b, shared) {
  const seqA = a.filter((t) => shared.has(t));
  const seqB = b.filter((t) => shared.has(t));
  if (seqA.length < 2 || seqB.length < 2) return true;
  return seqA.join("\0") === seqB.join("\0");
}

export function nameScore(a, b) {
  const A = Array.isArray(a) ? a : tokens(a);
  const B = Array.isArray(b) ? b : tokens(b);
  const setA = setOf(A);
  const setB = setOf(B);
  if (!setA.size || !setB.size) return 0;
  if (A.length === B.length && A.every((t, i) => t === B[i])) return 1;
  if (setA.size === setB.size && [...setA].every((t) => setB.has(t))) return 1;

  const inter = new Set([...setA].filter((t) => setB.has(t)));
  if (!inter.size) return 0;
  const nonLowInfoShared = [...inter].some((t) => !isLowInfo(t));

  const bInsideA = [...setB].every((t) => setA.has(t)); // the spelling's tokens are all in the column: the column may be more specific
  const aInsideB = [...setA].every((t) => setB.has(t)); // the column's tokens are all in the spelling: the column is the shorter side

  // Containment in either direction: the longer side's extra tokens decide.
  // All low-info (UserIdentity vs UserIdentityId, IPAddress vs
  // IPAddressValue) is the same name with filler; a real extra token on
  // either side (ip vs CidrIp, method vs authentication_method,
  // UserIdentityPrincipalid vs UserIdentity) is a different, more specific
  // name and scores far below the match floor.
  if (nonLowInfoShared && (bInsideA || aInsideB)) {
    const longer = bInsideA && setA.size > setB.size ? setA : setB;
    const shorter = longer === setA ? setB : setA;
    const extra = [...longer].filter((t) => !shorter.has(t));
    const allLowInfo = extra.every(isLowInfo);
    const share = jaccardShare(setA, setB);
    const base = allLowInfo ? 0.8 + 0.2 * share : 0.2 + 0.7 * share;
    return orderAgrees(A, B, inter) ? base : base * 0.85;
  }
  // Weighted Jaccard: low-info tokens count for little.
  const weight = (t) => (isLowInfo(t) ? 0.25 : 1);
  const union = new Set([...setA, ...setB]);
  let interW = 0;
  let unionW = 0;
  for (const t of union) {
    const w = weight(t);
    unionW += w;
    if (inter.has(t)) interW += w;
  }
  return unionW ? 0.75 * (interW / unionW) : 0;
}

// ---------------------------------------------------------------------------
// Vocabulary

const GENERIC_VALUES = new Set(["true", "false", "0", "1", "yes", "no", "success", "failure", "unknown", "none", "null", "enabled", "disabled", ""]);

function decodeLiterals(decode) {
  if (!decode || !decode.values) return new Set();
  return new Set(Object.keys(decode.values).map((k) => String(k).toLowerCase()).filter((k) => !GENERIC_VALUES.has(k)));
}

// vocabulary({ platform, concepts, learned }) -> Map(conceptKey -> entry)
//   entry: { key, packId, id, label, type, decode, literals: Set,
//            spellings: [ { tokens, weight, capped, text, container, column, platform } ] }
export function vocabulary({ concepts = [], learned = [] } = {}) {
  // Pass 1: which distinct concepts each exact column spelling is bound
  // to, across every pack and every confirmed binding. A spelling that
  // recurs on many containers but always means the same concept
  // (userAgent, eventName) is the canonical vendor name and keeps full
  // weight. One that means different things on different containers of
  // the same feed (Location: country on SigninLogs, location_details on
  // azure:aad:signin) weighs 1 / that count, which keeps it out of the
  // high tier. One bound in more than one feed (Category, TimeGenerated,
  // userName) is not distinct: only the election, which scores one feed's
  // concepts, tells its meanings apart, so it never votes for a feed.
  const conceptsBySpelling = new Map();
  const bump = (col, key) => {
    const k = String(col || "").toLowerCase();
    if (!k || !key) return;
    if (!conceptsBySpelling.has(k)) conceptsBySpelling.set(k, new Set());
    conceptsBySpelling.get(k).add(key);
  };
  for (const c of concepts) for (const b of c.bindings || []) bump(b.column, c.key);
  for (const l of learned) bump(l.column, l.concept);
  const packOf = (key) => (key && key.includes("/") ? key.split("/")[0] : null);
  const weightOf = (col, key) => {
    const set = conceptsBySpelling.get(String(col || "").toLowerCase());
    if (!set || !set.size) return { weight: 1, distinct: true };
    const inFeed = [...set].filter((k) => packOf(k) === packOf(key)).length || 1;
    return { weight: 1 / inFeed, distinct: set.size === 1 };
  };

  const vocab = new Map();
  for (const c of concepts) {
    if (!c || !c.key) continue;
    const packId = c.key.includes("/") ? c.key.split("/")[0] : c.packId || null;
    const spellings = [];
    const add = (text, { weight = 1, distinct = true, capped = false, container = null, column = null, platform = null, kind = "column" } = {}) => {
      const tk = tokens(text);
      if (!tk.length) return;
      spellings.push({ tokens: tk, weight, distinct, capped, text, container, column, platform, kind });
    };
    // A concept's cim slot has two shapes (packs.js's comment on `cim`): a
    // computed CIM field carries `from` (the raw fields it derives from)
    // and reads as generic as any TA alias; a raw field instead carries
    // `targets` (the CIM fields it feeds) and is the canonical spelling,
    // not a generic one. Only the first caps.
    const conceptCapped = Boolean(c.cim && c.cim.from);
    add(c.id, { weight: 1, capped: conceptCapped, kind: "id" });
    if (c.label) add(c.label, { weight: 1, capped: conceptCapped, kind: "label" });
    for (const b of c.bindings || []) {
      const capped = conceptCapped || Boolean(b.alias_of) || Boolean(b.cim && b.cim.from);
      add(b.column, { ...weightOf(b.column, c.key), capped, container: b.container, column: b.column, platform: b.platform, kind: "column" });
    }
    vocab.set(c.key, {
      key: c.key,
      packId,
      id: c.id,
      label: c.label || c.id,
      type: c.type || null,
      decode: c.decode || null,
      literals: decodeLiterals(c.decode),
      spellings,
    });
  }
  for (const l of learned) {
    const key = l.concept;
    const entry = key && vocab.get(key);
    if (!entry) continue; // that pack is not loaded here; inert until it is
    const tk = tokens(l.column);
    if (tk.length) entry.spellings.push({ tokens: tk, ...weightOf(l.column, key), capped: false, text: l.column, container: l.container, column: l.column, platform: l.platform, kind: "learned" });
  }
  return vocab;
}

// Best (score, spelling) for one column's tokens against a concept's
// vocabulary entry. A bound spelling's score is scaled by its weight (an
// ambiguous spelling cannot carry a confident match); a concept's own id
// and label carry weight 1. The result is capped when the winning
// spelling is capped, or when the column's tokens are identical to a
// capped spelling's: a column literally named after a CIM alias (src_ip)
// is that alias whatever else its tokens happen to equal (source_ip), so
// the concept id must not open a back door to the high tier.
function bestSpelling(colTokens, entry) {
  let best = null;
  let identityCapped = false;
  for (const sp of entry.spellings) {
    const raw = nameScore(colTokens, sp.tokens);
    if (!raw) continue;
    const score = raw * sp.weight;
    if (!best || score > best.score || (score === best.score && best.spelling.capped && !sp.capped)) best = { score, spelling: sp };
    if (sp.capped && raw >= 1) identityCapped = true;
  }
  if (!best) return { score: 0, spelling: null, capped: false };
  return { score: best.score, spelling: best.spelling, capped: best.spelling.capped || identityCapped };
}

// ---------------------------------------------------------------------------
// Feed election

function feedsOf(vocab) {
  const feeds = new Map(); // packId -> [entry]
  for (const entry of vocab.values()) {
    if (!entry.packId) continue;
    if (!feeds.has(entry.packId)) feeds.set(entry.packId, []);
    feeds.get(entry.packId).push(entry);
  }
  return feeds;
}

// A vote needs a vendor-looking match, not a generic word plus filler:
// either the column equals a spelling of two or more tokens outright
// (EventName, ClientAppUsed, event_simpleName), or the two share at least
// two tokens that are not low-info (userIdentity.arn vs UserIdentityArn).
// "user" against "UserId", "resource.resourceType" against "Resources" and
// "Level" against "Level" all score 0.9 or more and identify no feed.
function distinctiveMatch(colTokens, spTokens, score) {
  const setB = new Set(spTokens);
  const shared = colTokens.filter((t) => setB.has(t) && !isLowInfo(t));
  if (new Set(shared).size >= 2) return true;
  return score >= 1 && setB.size >= 2;
}

// Concept types whose spelling identifies a feed on its own: the record
// type, the actor and the host or credential keys. A feed elected from
// names must have at least one vote from one of these, or from the feed's
// own discriminator; error_code, request_id, tls_version and event.type
// alone are what S3 access logs and Google Workspace logins share with
// CloudTrail, and were electing it (dev Splunk, 2026-09-18).
const ANCHOR_TYPES = new Set(["record_type", "principal", "host_id", "access_key", "user_id", "process_uid"]);
// A column present in almost none of the sampled rows says nothing about
// the table (o365:management:activity carried Graph sign-in columns in 14
// of 5000 events and was elected as Entra).
const VOTE_MIN_FILL = 0.05;
const ELECT_MIN_VOTES = 5;
const ELECT_LEAD = 3;

export function electFeed(container, columns, { vocabulary: vocab, decodes = {}, recordTypes = null, existingBindings = [] } = {}) {
  const fillOf = new Map();
  for (const c of columns || []) {
    if (c && typeof c === "object" && c.column && c.profile && c.profile.fill !== null && c.profile.fill !== undefined) fillOf.set(c.column, c.profile.fill);
  }
  const cols = (columns || []).map((c) => (typeof c === "string" ? c : c.column)).filter((c) => c && !systemColumn(c));

  // 1. Majority owner of bindings the container already carries.
  if (existingBindings && existingBindings.length) {
    const tally = new Map();
    for (const b of existingBindings) {
      const packId = b.concept && b.concept.includes("/") ? b.concept.split("/")[0] : null;
      if (!packId) continue;
      tally.set(packId, (tally.get(packId) || 0) + 1);
    }
    if (tally.size) {
      const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1]);
      return { feedPackId: ranked[0][0], basis: "bindings", votes: Object.fromEntries(tally) };
    }
  }

  const feeds = feedsOf(vocab);

  // 2. Literal hits: a column's observed values (decode table or a
  // record-type field's counted values) overlapping a feed's decode or
  // discriminator vocabulary, 3+ values with 2+ distinct hits.
  const literalTally = new Map();
  const literalSource = (col) => {
    const d = decodes && decodes[col];
    if (d && d.values) return Object.keys(d.values).map((v) => String(v).toLowerCase());
    if (recordTypes && recordTypes.column === col && Array.isArray(recordTypes.values)) return recordTypes.values.map((v) => String(v.value).toLowerCase());
    return null;
  };
  for (const col of cols) {
    const values = literalSource(col);
    if (!values || values.length < 3) continue;
    const clean = values.filter((v) => !GENERIC_VALUES.has(v));
    if (clean.length < 2) continue;
    for (const [packId, entries] of feeds) {
      let hits = 0;
      for (const v of clean) for (const entry of entries) if (entry.literals.has(v)) { hits++; break; }
      if (hits >= 2) literalTally.set(packId, (literalTally.get(packId) || 0) + 1);
    }
  }
  if (literalTally.size) {
    const ranked = [...literalTally.entries()].sort((a, b) => b[1] - a[1]);
    if (ranked[0][1] >= 1 && (ranked.length < 2 || ranked[0][1] > ranked[1][1])) {
      return { feedPackId: ranked[0][0], basis: "literals", votes: Object.fromEntries(literalTally) };
    }
  }

  // 3. Name vote: columns whose best score against a feed's distinctive
  // spellings reaches 0.9. Only a real observed vendor column counts, not a
  // concept's own id or label (generic taxonomy words like "event_id" or
  // "event_source" would otherwise vote for every feed that happens to
  // have a same-named concept). A column whose tokens are all low-info, a
  // platform common column, and a column literally named after an alias
  // or CIM spelling never vote. Elected with 5+ such columns, three times
  // the runner-up and an anchor.
  //
  // Two readings of the same tally. The first counts only spellings that
  // are distinct across the catalogue (bound to one concept anywhere):
  // "Category", "userName" or "TimeGenerated" mean different things on
  // different feeds and identify none of them. The second, tried only when
  // the first elects nothing, lets a spelling bound in several feeds vote
  // for each of them: on a large catalogue the same vendor schema recurs
  // across sibling packs (CloudTrail and CloudTrail Lake, the sensor and
  // the ITHR stream) and "eventName" then narrows the field to those
  // feeds rather than to none. In that reading a feed whose every voting
  // column also votes for the leader is a narrower account of the same
  // schema, not a rival, so it is left out of the runner-up; the leader
  // must still explain more columns than it (or spell them identically,
  // the tie-break between two packs that bind the same names), three
  // times any feed that explains a column the leader does not, and own
  // at least one of the voting names outright: a column set explained
  // only by spellings every sibling also binds (the CIM Change fields
  // object_attrs, change_type, object_path on a dozen packs) names the
  // family, not the feed.
  const tally = new Map(); // packId -> { distinct: Set(column), shared: Set(column), exact: Set(column), anchorDistinct, anchorShared }
  const tallyOf = (packId) => {
    if (!tally.has(packId)) tally.set(packId, { distinct: new Set(), shared: new Set(), exact: new Set(), anchorDistinct: 0, anchorShared: 0 });
    return tally.get(packId);
  };
  for (const col of cols) {
    const colTokens = tokens(col);
    if (!colTokens.length || colTokens.every(isLowInfo)) continue;
    if (COMMON_COLUMNS.has(String(col).toLowerCase())) continue;
    if (fillOf.has(col) && fillOf.get(col) < VOTE_MIN_FILL) continue; // a column the rows barely carry
    const colKey = String(col).toLowerCase();
    for (const [packId, entries] of feeds) {
      let votes = false;
      let votesDistinct = false;
      let anchor = false;
      let anchorDistinct = false;
      let exact = false;
      let aliasName = false;
      for (const entry of entries) {
        for (const sp of entry.spellings) {
          if (sp.kind === "id" || sp.kind === "label") continue;
          const score = nameScore(colTokens, sp.tokens);
          if (sp.capped) {
            if (score >= 1) aliasName = true; // the column is literally an alias/CIM name
            continue;
          }
          if (score < HIGH_SCORE || !distinctiveMatch(colTokens, sp.tokens, score)) continue;
          votes = true;
          if (sp.distinct) votesDistinct = true;
          if (String(sp.text).toLowerCase() === colKey) exact = true;
          if (ANCHOR_TYPES.has(entry.type) && score >= 1) {
            anchor = true;
            if (sp.distinct) anchorDistinct = true;
          }
        }
      }
      if (!votes || aliasName) continue;
      const t = tallyOf(packId);
      t.shared.add(col);
      if (exact) t.exact.add(col);
      if (anchor) t.anchorShared++;
      if (votesDistinct) {
        t.distinct.add(col);
        if (anchorDistinct) t.anchorDistinct++;
      }
    }
  }
  const voteTally = Object.fromEntries([...tally].filter(([, t]) => t.distinct.size).map(([id, t]) => [id, t.distinct.size]));
  if (tally.size) {
    const distinctRanked = [...tally.entries()].filter(([, t]) => t.distinct.size).sort((a, b) => b[1].distinct.size - a[1].distinct.size);
    if (distinctRanked.length) {
      const [leadId, lead] = distinctRanked[0];
      const runnerVotes = distinctRanked.length > 1 ? distinctRanked[1][1].distinct.size : 0;
      if (lead.distinct.size >= ELECT_MIN_VOTES && lead.distinct.size >= ELECT_LEAD * runnerVotes && lead.anchorDistinct >= 1) {
        return { feedPackId: leadId, basis: "names", votes: voteTally, anchors: lead.anchorDistinct };
      }
    }
    const sharedRanked = [...tally.entries()].sort((a, b) => b[1].shared.size - a[1].shared.size || b[1].exact.size - a[1].exact.size);
    const [leadId, lead] = sharedRanked[0];
    const narrower = (t) => [...t.shared].every((c) => lead.shared.has(c)) && (t.shared.size < lead.shared.size || t.exact.size < lead.exact.size);
    const rivals = sharedRanked.slice(1).filter(([, t]) => !narrower(t));
    const runnerVotes = rivals.length ? rivals[0][1].shared.size : 0;
    if (lead.shared.size >= ELECT_MIN_VOTES && lead.distinct.size >= 1 && lead.shared.size >= ELECT_LEAD * runnerVotes && lead.anchorShared >= 1) {
      const sharedTally = Object.fromEntries([...tally].map(([id, t]) => [id, t.shared.size]));
      return { feedPackId: leadId, basis: "names", votes: sharedTally, anchors: lead.anchorShared, shared: true };
    }
  }

  // Not recognised. The tally still comes back so a near miss is visible
  // (and so a caller can offer the best-voted feed as the first pick).
  return { feedPackId: null, basis: null, votes: voteTally };
}

// ---------------------------------------------------------------------------
// Tiering

const HIGH_SCORE = 0.9;
const FLOOR_SCORE = 0.75;
const GAP = 0.05;

// The tier reads two numbers: the full score (name plus shape evidence)
// decides the floor and the gap to the runner-up, but only the name score
// (or a positive shape, which sets it) can reach the high tier. A
// confirming shape breaks a tie; it never lifts a middling name to high.
function tierOf(score, nameOnly, runnerUpScore) {
  if (score < FLOOR_SCORE) return null;
  const gapOk = runnerUpScore === null || runnerUpScore === undefined || runnerUpScore <= score - GAP + 1e-9;
  if (nameOnly >= HIGH_SCORE && gapOk) return "high";
  if (!gapOk) return "several"; // a close call between two plausible concepts
  return "medium"; // a lone match short of high
}

function isDismissed(dismissed, column, concept) {
  for (const d of dismissed || []) {
    if (d.column !== column) continue;
    if (d.concept == null) return true; // leave this column alone entirely
    if (d.concept === concept) return true;
  }
  return false;
}

function columnDismissedEntirely(dismissed, column) {
  return (dismissed || []).some((d) => d.column === column && d.concept == null);
}

// ARN detail (user, assumed-role, role, sts_session) across the top values,
// for the principal-versus-session-issuer tie-break (step 5): a user,
// assumed-role or STS session ARN is the acting principal, a role ARN is
// what a session was issued from, so the two kinds of principal concept
// step apart by one gap and no resource concept competes with either.
function arnDetailOf(top) {
  const tally = new Map();
  for (const v of top) {
    const got = shapeOf(v.value);
    if (!got || got.shape !== "arn" || !got.detail) continue;
    const w = Number.isFinite(Number(v.count)) ? Number(v.count) : 1;
    tally.set(got.detail, (tally.get(got.detail) || 0) + w);
  }
  let best = null;
  for (const [d, w] of tally) if (!best || w > best.w) best = { d, w };
  return best ? best.d : null;
}

const ISSUER_TOKENS = new Set(["issuer", "role"]);

function issuerLike(entry) {
  return tokens(entry.id).some((t) => ISSUER_TOKENS.has(t));
}

// Is this concept the kind of principal the ARN detail names?
function arnFavours(detail, entry) {
  if (entry.type !== "principal") return false;
  if (detail === "role") return issuerLike(entry);
  return !issuerLike(entry); // user, assumed-role, sts_session: the acting principal
}

// One column's candidates against the elected feed's concepts, shape
// evidence applied, dismissed pairs skipped, capped spellings held to
// "several" at most.
function scoreColumn(colName, profile, vocab, feedPackId, dismissed, provenance, columnsByName) {
  const colTokens = tokens(colName);
  // The "3 values minimum" guard is about distinct values seen, not how
  // many events carried them: a single value repeated 1000 times must
  // never veto on the strength of a sample size of one.
  const shapeInfo = profile && profile.top && profile.top.length >= 3 ? classify(profile.top) : null;
  const hasShapeEvidence = Boolean(shapeInfo && shapeInfo.shape);
  const arnDetail = hasShapeEvidence && shapeInfo.shape === "arn" ? arnDetailOf(profile.top) : null;
  // Two more veto conditions the shape tables cannot see, because they are
  // about the column's declared/measured kind, not its top values: an
  // all-numeric column (Splunk numeric_count == count, a Sentinel
  // long/double/decimal) can never carry a concept whose values are
  // never numbers, and a Sentinel column whose runtime type is "dynamic"
  // (a nested object) can never carry anything but a raw_object.
  const numericColumn = Boolean(profile && profile.numeric);
  const dynamicColumn = profile && profile.type === "dynamic";

  const candidates = [];
  for (const entry of vocab.values()) {
    if (entry.packId !== feedPackId) continue;
    const refused = isDismissed(dismissed, colName, entry.key);
    const { score: nameOnly, spelling, capped } = bestSpelling(colTokens, entry);
    let score = nameOnly;
    let nameScoreForTier = nameOnly;
    // A meaningless (zero-score) name match carries no story to tell; leave
    // via unset so the shape route below can claim credit for itself. A
    // concept's label is a sentence, not a spelling: the why-line names the
    // concept id for a label hit, so every via reads as an identifier.
    let via = nameOnly > 0 && spelling ? (spelling.kind === "label" ? entry.id : spelling.text) : null;
    let vetoed = false;
    let evidenceShape = null;

    if (entry.type !== "raw_object" && dynamicColumn) vetoed = true;
    if (!vetoed && numericColumn && numericVeto(entry.type)) vetoed = true;

    if (!vetoed && hasShapeEvidence) {
      const supports = shapeSupports(shapeInfo.shape, entry.type);
      // json's veto threshold is deliberately lower than the general one
      // (step 5: "json share over half"): a nested object showing up in
      // even a third of the sample is already the wrong kind of thing for
      // a scalar concept.
      const vetoShare = shapeInfo.shape === "json" ? 0.5 : 0.8;
      const vetoesIt = shapeVeto(shapeInfo.shape, entry.type) && shapeInfo.share >= vetoShare;
      if (vetoesIt) {
        vetoed = true;
      } else if (supports && shapeInfo.share >= 0.8) {
        evidenceShape = shapeInfo.shape;
        if (POSITIVE_SHAPES.has(shapeInfo.shape)) {
          // A specific shape (an ARN, an AWS access key or principal id,
          // a SID) is strong evidence on its own, name match or not, for
          // the concepts it singles out. An ARN whose resource kind names
          // the acting principal lifts the principal concepts; for a
          // resource concept (bucket name, image id) it is a confirming
          // shape at most, so such a concept is never proposed for a user
          // ARN on the shape alone, nor "sure" by elimination.
          if (!arnDetail || arnFavours(arnDetail, entry)) {
            score = Math.max(score + 0.1, HIGH_SCORE);
            if (nameScoreForTier < HIGH_SCORE) via = `shape:${shapeInfo.shape}`;
            nameScoreForTier = Math.max(nameScoreForTier, HIGH_SCORE);
          } else {
            score += 0.1;
          }
        } else if (!VETO_ONLY_SHAPES.has(shapeInfo.shape)) {
          // A confirming shape adds to the score (it can break a tie);
          // a veto-only shape (ip, guid, hash) is recorded and adds
          // nothing: an address column is not evidence for which of two
          // address concepts it is.
          score += 0.1;
        }
        // The ARN detail tie-break: every arn-supported candidate that is
        // not the kind the detail names steps back by one gap.
        if (arnDetail && !arnFavours(arnDetail, entry)) score -= GAP;
      }
    }
    if (vetoed || score < FLOOR_SCORE) continue;
    candidates.push({ concept: entry.key, score, nameOnly: nameScoreForTier, via, capped, refused, shape: evidenceShape, matched: shapeInfo ? shapeInfo.matched : null, total: shapeInfo ? shapeInfo.total : null, values: shapeInfo ? shapeInfo.values : null, hits: shapeInfo ? shapeInfo.hits : null });
  }

  // Provenance route (Splunk): an alias of a bound column carries that
  // column's concept at high; a calculated field with exactly one bound
  // ref, at medium. This can add or reinforce a candidate.
  if (provenance && provenance.length) {
    for (const p of provenance) {
      if (p.kind === "alias" && p.from && columnsByName && columnsByName.has(p.from)) {
        const fromConcept = columnsByName.get(p.from);
        if (fromConcept && vocab.get(fromConcept) && vocab.get(fromConcept).packId === feedPackId && !isDismissed(dismissed, colName, fromConcept)) {
          candidates.push({ concept: fromConcept, score: 1.2, nameOnly: 1, via: `alias of ${p.from}`, aliasOf: p.from, capped: false, refused: false, forcedTier: "high", shape: null, matched: null, total: null, values: null, hits: null });
        }
      } else if (p.kind === "calculated" && Array.isArray(p.refs) && p.refs.length === 1 && columnsByName && columnsByName.has(p.refs[0])) {
        const refConcept = columnsByName.get(p.refs[0]);
        if (refConcept && vocab.get(refConcept) && vocab.get(refConcept).packId === feedPackId && !isDismissed(dismissed, colName, refConcept)) {
          candidates.push({ concept: refConcept, score: 0.8, nameOnly: 0.8, via: `calculated from ${p.refs[0]}`, aliasOf: p.refs[0], capped: false, refused: false, forcedTier: "medium", shape: null, matched: null, total: null, values: null, hits: null });
        }
      }
    }
  }

  candidates.sort((a, b) => b.score - a.score);
  return candidates;
}

// proposeBindings({ platform, container, columns, vocabulary, feed, dismissed, packBound })
export function proposeBindings({ container, columns = [], vocabulary: vocab, feed, dismissed = [], packBound = [] } = {}) {
  if (!vocab || !feed) return [];
  const boundSet = new Set((packBound || []).map((c) => (typeof c === "string" ? c : c.column)));
  // Resolves an already-bound column to its concept, for the alias/calculated
  // provenance route; the caller passes packBound as [{column, concept}] when
  // it knows the concept, or bare column names when it does not.
  const columnsByName = new Map();
  for (const c of packBound || []) {
    if (c && typeof c === "object" && c.column && c.concept) columnsByName.set(c.column, c.concept);
  }

  const out = [];
  for (const c of columns) {
    const colName = typeof c === "string" ? c : c.column;
    const profile = typeof c === "string" ? null : c.profile || null;
    const provenance = typeof c === "string" ? null : c.provenance || null;
    if (!colName || systemColumn(colName) || boundSet.has(colName)) continue;
    if (columnDismissedEntirely(dismissed, colName)) continue;

    const candidates = scoreColumn(colName, profile, vocab, feed, dismissed, provenance, columnsByName);
    // candidates is sorted by score, so a provenance-route alias candidate
    // (score above any name-and-shape total) is "best" whenever present.
    // A refused candidate is skipped for the proposal and the alternatives
    // but still stands as the runner-up: the gap is read against the whole
    // field, so "not this" never promotes the next one by elimination.
    const best = candidates.find((c2) => !c2.refused) || null;
    if (!best) continue;
    const refused = candidates.filter((c2) => c2.refused).map((c2) => c2.concept);
    const columnRefused = (dismissed || []).some((d) => d.column === colName && d.concept != null);
    // Once the user has refused a concept here, only a candidate sure on
    // its own is offered; the 0.85 pile an ARN shape leaves behind (every
    // resource concept the shape supports) is not a walk worth taking.
    if (columnRefused && !best.forcedTier && best.nameOnly < HIGH_SCORE) continue;
    const runnerUp = candidates.find((c2) => c2.concept !== best.concept) || null;
    let tier = best.forcedTier || tierOf(best.score, best.nameOnly, runnerUp ? runnerUp.score : null);
    if (!tier) continue;
    if (best.capped && tier === "high") tier = "several"; // alias/cim spellings never reach high

    // Scores are reported clamped to 1; the gap test above ran on the
    // unclamped totals so a confirming shape can separate two exact names.
    const clamp = (x) => Math.min(1, x);
    const alternatives = candidates
      .filter((c2) => c2.concept !== best.concept && !c2.refused)
      .slice(0, 6)
      .map((c2) => ({ concept: c2.concept, score: clamp(c2.score) }));

    out.push({
      column: colName,
      concept: best.concept,
      tier,
      score: clamp(best.score),
      runnerUp: runnerUp ? { concept: runnerUp.concept, score: clamp(runnerUp.score) } : null,
      evidence: { from: best.forcedTier ? (best.via && best.via.startsWith("alias") ? "alias" : "calculated") : best.shape ? "shape" : "name", score: clamp(best.score), via: best.via, shape: best.shape, matched: best.matched, total: best.total, values: best.values, hits: best.hits },
      alias_of: best.aliasOf || null,
      alternatives,
      refused,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Cross-environment matches: recipe.proposeEdges, generalised across every
// (env, platform, container). environments: [ { key, platform, containers:
// [ { name, columns: [ { column, profile, concept } ] } ] } ]. `concept`,
// when the caller resolved it, marks a side as bound; matches() itself
// never resolves anything. Two columns match when their names agree (the
// same token set, or one inside the other with only low-info filler) and
// they share a top value, or share the same detected shape on an exact
// name. A match with exactly one bound side carries `proposal` for the
// other side: high when 2+ values overlap or the name is exact and the
// shape agrees, else medium. The caller still applies the feed rule (a
// match cannot pull a concept of a feed the container is not elected to).

function bucketKey(col) {
  return tokens(col).slice().sort().join(",");
}

// High when two or more values overlap, or the names are exact and the
// shape agrees; else medium. Exported so a caller that resolves the sides
// later than matches() ran (the Coverage page, after a confirm) can tier a
// match the same way.
export function matchTier(m) {
  return m.overlap >= 2 || (m.name >= 1 && m.shape) ? "high" : "medium";
}

export function matches({ environments = [] } = {}) {
  const cells = [];
  for (const env of environments) {
    for (const container of env.containers || []) {
      for (const col of container.columns || []) {
        const profile = col.profile;
        if (!profile || !Array.isArray(profile.top) || !profile.top.length) continue;
        if ((profile.distinct || 0) < 2) continue;
        cells.push({ env: env.key, platform: env.platform, container: container.name, column: col.column, profile, concept: col.concept || null, key: bucketKey(col.column) });
      }
    }
  }
  const out = [];
  for (let i = 0; i < cells.length; i++) {
    for (let j = i + 1; j < cells.length; j++) {
      const a = cells[i];
      const b = cells[j];
      if (a.env === b.env && a.container === b.container) continue;
      const nameScoreAB = a.key === b.key ? 1 : nameScore(tokens(a.column), tokens(b.column));
      if (nameScoreAB < 0.9) continue;
      const va = new Set(a.profile.top.map((t) => t.value));
      const overlap = b.profile.top.filter((t) => va.has(t.value)).length;
      const shapeA = shapeOf(a.profile.top[0] && a.profile.top[0].value);
      const shapeB = shapeOf(b.profile.top[0] && b.profile.top[0].value);
      const sameShape = Boolean(shapeA && shapeB && shapeA.shape === shapeB.shape);
      if (!overlap && !(nameScoreAB >= 1 && sameShape)) continue;
      const match = {
        a: { env: a.env, platform: a.platform, container: a.container, column: a.column, concept: a.concept },
        b: { env: b.env, platform: b.platform, container: b.container, column: b.column, concept: b.concept },
        name: nameScoreAB,
        overlap,
        shape: sameShape ? shapeA.shape : null,
        basis: "proposed",
        proposal: null,
      };
      if (Boolean(a.concept) !== Boolean(b.concept)) {
        const bound = a.concept ? a : b;
        match.proposal = { for: a.concept ? "b" : "a", concept: bound.concept, tier: matchTier(match) };
      }
      out.push(match);
    }
  }
  return out.sort((x, y) => y.overlap - x.overlap);
}

export default { tokens, nameScore, vocabulary, electFeed, proposeBindings, matches, matchTier, LOW_INFO, SYNONYMS, PLATFORM_DEFAULT_COLUMNS, COMMON_COLUMNS };
