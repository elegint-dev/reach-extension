// The known-good verdict and the runbook head: the sibling fields each one
// reads off the clicked row, the pure models, and the rows drawn from them.
//
//   VERDICT_CSS                       the verdict row's stylesheet, for the app's value page (POPUP_CSS carries it too)
//   VERDICT_FIELDS, verdictFields(read) → { name: value }
//       the sibling fields a verdict reads, off the clicked row
//   ALERT_FIELDS, alertFields(read) → { name: value }
//       the alert-identity and entity fields a runbook reads, off the clicked row
//   runbookBlock({ ruleKey, row, platform, appUrl }) → Element | null
//       the runbook head for a row that carries a rule key (runbooks.js): the rule
//       name, the seed source, "N steps, M bound from this row" and a link to the
//       panel page, filled in when the bundle lands; null for a row without a key
//   platformBinaryOf(fields) → boolean | null   (pure)
//   verdictInput(fields, { field, value, conceptType }) → { platform, clicked, input } | null   (pure)
//       the known.js input gathered from a Falcon process event around a click
//       on a hash, a signing id or an image path; null off those, or off mac/linux
//   linuxReleaseOf(text) → { distro, release } | null   (pure)
//       the corpus key an OS version string names: the Ubuntu, RHEL and Amazon Linux forms
//   osBuildFor({ catalogue, fields }) → { build, basis } | null   (pure)
//       the host's OS build from the discovered crowdstrike:hosts profile, else the event
//   fleetLine(prevalence) → string | null   (pure)
//       the fourth line, from the organisation corpus (known.js prevalenceOf)
//   macosEntry(loaded, input) → entry | null   (pure)
//       the loaded macOS index's row for the event's signing id, else the one
//       platform signing id the corpus has at the event's path
//   verdictModel({ verdict, input, entry, buildBasis, prevalence }) → { tier, chip, headline, detail, hint, corpus, fleet }   (pure)
//       one line per tier: normal, consistent (Linux, path without a hash), impersonation (red), unknown (with the next step)
//   verdictBlock({ field, value, container, platform, event, catalogue, view, known, hold, onTier, titled, appUrl }) → Element | null
//       that line, drawn below the value row; the corpus projection is imported and
//       fetched only once a mac or linux event is in hand, and the row redraws when it lands.
//       `appUrl(hash)` maps a hash route to a URL, for the "no fleet baseline yet" link
//       to the Falcon sourcetype page; without it, the line carries no link.
//
// DOM module (uses h.js). Fetches nothing at import; the corpus loads on
// the first mac or linux event.

import { h } from "../../components/h.js";
import { PLATFORM } from "../platform.js";
import * as runbooks from "../runbooks.js";
import { when } from "../when.js";
import { attachButton } from "./hold-and-benign.js";

// The verdict row's own rules, written against the --rc-* palette only so the
// app's value page can carry them with a variable map instead of POPUP_CSS.
// A verdict is the first thing in the section (see verdictBlock): the
// banner is full width, its tier readable at a glance without opening
// anything, coloured by tier (normal/consistent green, impersonation red,
// unknown/pending neutral).
export const VERDICT_CSS = `
.reach-verdict{border:1px solid var(--rc-line2);border-radius:6px;padding:10px 12px;background:var(--rc-bg2)}
.reach-verdict[data-tier="normal"],.reach-verdict[data-tier="consistent"]{border-color:var(--rc-ok);background:var(--rc-ok-bg)}
.reach-verdict[data-tier="impersonation"]{border-color:var(--rc-err);background:var(--rc-err-bg)}
.reach-verdict__line{display:flex;align-items:baseline;flex-wrap:wrap;gap:0 6px;overflow-wrap:anywhere;min-width:0;font-size:14px;font-weight:600}
.reach-verdict__line .reach-chip{text-transform:capitalize;flex:0 0 auto}
.reach-verdict__text{min-width:0;overflow-wrap:anywhere}
.reach-verdict__detail,.reach-verdict__hint,.reach-verdict__fleet{font-size:12px;color:var(--rc-fg2);margin-top:2px;overflow-wrap:anywhere}
.reach-verdict__fleet{color:var(--rc-fg)}
`;
// ---------------------------------------------------------------------------
// The known-good verdict
//
// A clicked hash, signing id or image path on a Falcon process event,
// checked against the bundled corpus of platform-default executables
// (known.js). The event's sibling fields are the evidence: the popups read
// them off the row the click landed in (verdictFields), the panel gets them
// with the selection. Nothing is fetched until a mac or linux event is in
// hand; a Windows event, or one with no platform, draws nothing.

// The sibling fields a verdict reads, by their FDR names (Splunk) and the
// dev sample table's spellings (Sentinel). CodeSigningFlags_meaning is the
// Splunk TA's decode of the bitmask; CS_PLATFORM_BINARY a possible flag
// column on other ingests.
export const VERDICT_FIELDS = [
  "event_platform", "EventPlatform",
  "aid", "Aid", "aid_os_version", "AidOsVersion",
  "SHA256HashData", "SigningId", "TeamId", "ImageFileName",
  "CodeSigningFlags", "CodeSigningFlags_meaning", "CsValidationCategory", "CS_PLATFORM_BINARY",
  "event_simpleName", "EventSimpleName",
];

// The alert-identity fields a rule key is read from (Splunk: the ESCU
// detection id or the search name; Sentinel: AlertName) and the entity
// fields a runbook's pivots bind from, both platforms' spellings
// (runbooks.js owns the lists).
export const ALERT_FIELDS = runbooks.ALERT_FIELDS;

function readFields(names, read, max) {
  const out = {};
  for (const name of names) {
    let v;
    try { v = read(name); } catch { v = null; }
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (s) out[name] = s.slice(0, max);
  }
  return out;
}

// `read(name)` -> the row's value for that field, or null. Only fields with
// a value ride along, as short strings.
export function verdictFields(read) {
  return readFields(VERDICT_FIELDS, read, 512);
}

export function alertFields(read) {
  return readFields(ALERT_FIELDS, read, 2000); // Sentinel's Entities column is a JSON list
}

// ---------------------------------------------------------------------------
// The runbook head
//
// A row that carries a rule key gets the runbook band: the rule's name,
// which bundle seeded it, how many steps and how many of those bind a
// value off this row, and the panel page. The bundle is read on the first
// key (runbooks.load), so the line fills in when it lands.

export function runbookBlock({ ruleKey, row = {}, platform = PLATFORM, appUrl = null } = {}) {
  const rk = ruleKey || runbooks.ruleKeyFor(row, platform);
  if (!rk) return null;
  const hash = runbooks.href(rk, row);
  const link = appUrl && hash ? h("a", { class: "reach-link reach-runbook__open", href: appUrl(hash), target: "_blank", rel: "noopener" }, "Open the runbook →") : null;
  const name = h("span", { class: "reach-runbook__name" }, rk.name || rk.keys[0].value);
  const source = h("span", { class: "reach-chip reach-runbook__source", dataset: { basis: "pending" } }, "reading the bundle…");
  const count = h("div", { class: "reach-row__body reach-row__body--muted reach-runbook__count" }, "");
  const el = h("div", { class: "reach-row reach-runbook", dataset: { key: rk.key } }, h("div", { class: "reach-row__title" }, "Runbook"), h("div", { class: "reach-runbook__line" }, name, " ", source), count, link);
  // Resolves once the seed lookup has filled the row; tests await this
  // instead of a timer.
  el.ready = runbooks
    .seedFor(rk, { row, platform })
    .then((rb) => {
      name.textContent = rb.title || name.textContent;
      source.textContent = rb.seeded_from ? rb.seeded_from.label : "not in the bundled rules";
      source.dataset.basis = rb.seeded_from ? "confirmed" : "asserted";
      count.textContent = `${rb.steps.length} step${rb.steps.length === 1 ? "" : "s"}, ${rb.bound} bound from this row`;
    })
    .catch(() => {
      source.textContent = "bundle not readable";
      source.dataset.basis = "asserted";
    });
  return el;
}

const CS_PLATFORM_BINARY = 0x04000000; // cs_blobs.h
const BUILD_RE = /^\d{2}[A-Z]\d{1,4}[a-z]?$/; // a Darwin build: 25G83, 24F74, 23A344a
const SHA256_RE = /^[0-9a-f]{64}$/i;
const CLICK_KIND = { sha256hashdata: "sha256", signingid: "signing_id", imagefilename: "path" };
const TYPE_KIND = { file_hash: "sha256", signing_id: "signing_id", file_path: "path" };

function first(fields, ...names) {
  for (const n of names) if (fields[n]) return fields[n];
  return null;
}

// Whether the process is an Apple platform binary, from the event alone:
// the bitmask when the row carries it, else the TA's flag names, else a
// flag column; null when the event does not say. Only the bitmask can say
// "no": the flag names render one per value and a popup may read the first.
export function platformBinaryOf(fields) {
  const flags = fields.CodeSigningFlags;
  if (flags && /^\d+$/.test(flags)) return (Number(flags) & CS_PLATFORM_BINARY) !== 0;
  if (fields.CodeSigningFlags_meaning && /\bCS_PLATFORM_BINARY\b/.test(fields.CodeSigningFlags_meaning)) return true;
  const col = fields.CS_PLATFORM_BINARY;
  if (col) return /^(true|1|yes)$/i.test(col) ? true : /^(false|0|no)$/i.test(col) ? false : null;
  return null;
}

// The Linux corpus key an OS version string names: "Ubuntu 22.04" is ubuntu
// 22.04, "RHEL 9.4" is rhel 9 (the corpus is per major), "Amazon Linux 2023" is amazonlinux 2023.
export function linuxReleaseOf(text) {
  const s = String(text || "").trim();
  let m = /^ubuntu\s+(\d+\.\d+)/i.exec(s);
  if (m) return { distro: "ubuntu", release: m[1] };
  m = /^(?:rhel|red hat enterprise linux)\s+(\d+)/i.exec(s);
  if (m) return { distro: "rhel", release: m[1] };
  m = /^amazon linux\s+(\d+)/i.exec(s);
  if (m) return { distro: "amazonlinux", release: m[1] };
  return null;
}

// The verdict's input, gathered from the row's fields around a click on
// `field`. Null when the click is not on a hash, a signing id or an image
// path (by column name, or by the concept type the catalogue gives the
// column), or the event is not a mac or linux one.
//   -> { platform: "macos" | "linux", clicked: "sha256" | "signing_id" | "path", input }
export function verdictInput(fields, { field, value, conceptType } = {}) {
  const f = fields || {};
  const byName = field ? CLICK_KIND[String(field).toLowerCase()] : null;
  const byType = conceptType ? TYPE_KIND[conceptType] : null;
  const clicked = byName || byType;
  if (!clicked) return null;
  const literal = value === undefined || value === null ? "" : String(value).trim();
  if (clicked === "sha256" && byType && !byName && !SHA256_RE.test(literal)) return null; // an md5 or sha1 has no row in the corpus
  const plat = first(f, "event_platform", "EventPlatform");
  const platform = plat === "Mac" ? "macos" : plat === "Lin" ? "linux" : !plat && (f.SigningId || f.CodeSigningFlags) ? "macos" : null;
  if (!platform) return null;
  const sha = first(f, "SHA256HashData") || (clicked === "sha256" ? literal : null);
  const team = first(f, "TeamId");
  const build = first(f, "aid_os_version", "AidOsVersion");
  const linux = platform === "linux" ? linuxReleaseOf(build) : null;
  const input = {
    platform,
    sha256: sha && SHA256_RE.test(sha) ? sha.toLowerCase() : null,
    signing_id: first(f, "SigningId") || (clicked === "signing_id" ? literal : null),
    team_id: team && team !== "-" ? team : null,
    path: first(f, "ImageFileName") || (clicked === "path" ? literal : null),
    os_build: build && BUILD_RE.test(build) ? build : null,
    cs_platform_binary: platformBinaryOf(f),
    sign_flags: f.CodeSigningFlags && /^\d+$/.test(f.CodeSigningFlags) ? Number(f.CodeSigningFlags) : null,
    distro: linux ? linux.distro : null,
    release: linux ? linux.release : null,
  };
  return { platform, clicked, input };
}

// The host's OS build, which a process event does not carry: the discovered
// layer's crowdstrike:hosts profile when the inventory reports exactly one
// build (a fleet on several builds cannot be joined from a profile, and the
// verdict would name a build the host is not on), else a build-shaped
// aid_os_version on the event itself.
export function osBuildFor({ catalogue, fields }) {
  let view = null;
  try { view = catalogue && catalogue.fieldOn ? catalogue.fieldOn("crowdstrike:hosts", "os_build") : null; } catch { view = null; }
  const p = view && view.profile;
  if (p && p.distinct === 1 && Array.isArray(p.top) && p.top.length) {
    const v = String(p.top[0].value || "").trim();
    if (BUILD_RE.test(v)) return { build: v, basis: "the one build in your crowdstrike:hosts inventory" };
  }
  const own = fields ? first(fields, "aid_os_version", "AidOsVersion") : null;
  if (own && BUILD_RE.test(own)) return { build: own, basis: "aid_os_version on the event" };
  return null;
}

const TIER_CHIP = { normal: "confirmed", consistent: "validated", impersonation: "danger", unknown: "pack" };

function corpusText(corpus) {
  if (!corpus) return null;
  if (corpus.platform === "linux") return `${corpus.distro} ${corpus.release}`;
  if (Array.isArray(corpus.builds) && corpus.builds.length) return `macOS build${corpus.builds.length === 1 ? "" : "s"} ${corpus.builds.join(", ")}`;
  return `macOS${corpus.os_version ? ` ${corpus.os_version}` : ""} build ${corpus.build}`;
}

// The window a fleet baseline was measured over, as the line says it:
// Splunk's "-30d" and Sentinel's "30d" both read "the last 30d"; "0" is all time.
function windowText(w) {
  const s = String(w || "").trim();
  if (!s) return "";
  if (s === "0") return "all time";
  return `the last ${s.replace(/^-/, "")}`;
}

// The fourth line: what the analyst's own fleet says about the value
// (known.js prevalenceOf over the organisation corpus). Null without a
// corpus; a miss says whether the corpus was complete or cut to budget.
export function fleetLine(p) {
  if (!p || !p.key) return null;
  if (p.rows > 0) {
    const n = p.hosts.toLocaleString();
    const first = p.first_seen ? when(p.first_seen).slice(0, 10) : "";
    return `Seen on ${p.rows > 1 ? "at least " : ""}${n} of your hosts${first ? `, first ${first}` : ""}`;
  }
  if (!p.complete) return `Not among the ${p.kept.toLocaleString()} most widespread binaries in your fleet (corpus cut to budget)`;
  const w = windowText(p.window);
  return `Not seen elsewhere in your fleet${w ? ` (${w} of process events)` : ""}`;
}

// One line per tier, from the verdict and what the corpus holds for the
// identity it matched (entry: the signing id's row, on macOS), and the
// fleet line beneath.
//   -> { tier, chip, headline, detail, hint, corpus, fleet }
export function verdictModel({ verdict, input, entry = null, buildBasis = null, prevalence = null }) {
  const v = verdict || { tier: "unknown", evidence: [], corpus: null };
  const inp = input || {};
  const corpus = corpusText(v.corpus);
  const m = { tier: v.tier, chip: TIER_CHIP[v.tier] || "pack", headline: "", detail: null, hint: null, corpus, fleet: fleetLine(prevalence) };
  const apple = entry ? entry.platform_binary === true : inp.cs_platform_binary === true;
  if (v.tier === "normal") {
    if (v.corpus && v.corpus.platform === "linux") {
      m.headline = `In the known-good corpus for ${corpus}`;
      m.detail = v.evidence.join("; ");
      return m;
    }
    const who = apple ? "Apple platform binary" : entry && entry.team_id ? `Signed by team ${entry.team_id}` : "Known binary";
    const desc = entry && entry.description ? ` (${entry.description})` : "";
    const path = inp.path || (entry && entry.paths && entry.paths.size ? Array.from(entry.paths)[0] : null);
    const seen = builds(v, entry, inp.path);
    m.headline = `${who}${desc}${path ? ` at ${path}` : ""}${seen.length ? `, on macOS build${seen.length === 1 ? "" : "s"} ${seen.join(", ")}` : ""}`;
    if (!inp.signing_id && inp.path) m.detail = "Matched on the path alone: this event carries no signing id to compare.";
    if (buildBasis && inp.os_build) m.detail = `${m.detail ? `${m.detail} ` : ""}Build ${inp.os_build} from ${buildBasis}${seen.includes(inp.os_build) ? "" : ", not a build the corpus enumerated"}.`;
    return m;
  }
  if (v.tier === "consistent") {
    m.headline = `Path known to the ${corpus} corpus`;
    m.detail = v.evidence.join("; ");
    return m;
  }
  if (v.tier === "impersonation") {
    m.headline = `Disagrees with the corpus: ${v.evidence.join("; ")}`;
    return m;
  }
  m.headline = "Not in any known-good corpus";
  m.detail = v.evidence.length ? v.evidence.join("; ") : null;
  m.hint = inp.sha256 ? "Next: the VirusTotal row, or the hash across your hosts through the pivots below." : "Next: click the event's SHA256HashData for a hash check.";
  return m;
}

// The builds the matched pair was seen on: the signing id's row for the event's
// path, else every build the signing id was seen on, else the builds the corpus covers.
function builds(v, entry, path) {
  if (entry && path && entry.pathBuilds && entry.pathBuilds.has(path)) return entry.pathBuilds.get(path);
  if (entry && entry.builds && entry.builds.size) return Array.from(entry.builds);
  return v.corpus && Array.isArray(v.corpus.builds) ? v.corpus.builds : [];
}

// The macOS index row the verdict speaks about: the event's signing id when the
// corpus has it, else the one platform signing id the corpus has at the event's path.
export function macosEntry(loaded, input) {
  if (!loaded || !loaded.bySigningId) return null;
  const inp = input || {};
  if (inp.signing_id && loaded.bySigningId.has(inp.signing_id)) return loaded.bySigningId.get(inp.signing_id);
  if (inp.path && loaded.byPath) {
    const owners = (loaded.byPath.get(inp.path) || []).filter((id) => loaded.bySigningId.get(id).platform_binary);
    if (owners.length === 1) return loaded.bySigningId.get(owners[0]);
  }
  return null;
}

// The verdict row: drawn at once as "checking", then redrawn in place when
// the corpus answers. The projection is imported and fetched only here.
// `onTier(model)` hears the tier once the corpus answers (the title
// block's chip and the danger banner); `titled: false` leaves the corpus
// line to the caller's own heading.
export function verdictBlock({ field, value, container, platform = PLATFORM, event, catalogue = null, view = null, known = null, hold = null, onTier = null, titled = true, appUrl = null }) {
  const fields = event || {};
  const ask = verdictInput(fields, { field, value, conceptType: view && view.concept ? view.concept.type : null });
  if (!ask) return null;
  const root = h("div", { class: "reach-row reach-verdict", dataset: { tier: "pending" } });
  const sep = titled ? "· " : ""; // the separator follows the band title; alone, the corpus line stands on its own
  const feeds = h("span", { class: "reach-row__feeds" }, `${sep}checking the corpus…`);
  const body = h("div", { class: "reach-row__body reach-row__body--muted reach-verdict__body" }, "Checking the bundled known-good corpus…");
  root.append(titled ? h("div", { class: "reach-row__title" }, "Known-good ", feeds) : h("div", { class: "reach-verdict__corpus" }, feeds), body);
  const build = osBuildFor({ catalogue, fields });
  if (build) ask.input.os_build = build.build;
  (async () => {
    const mod = known || (await import("../known.js"));
    const verdict = await mod.verdict(ask.input);
    let entry = null;
    if (verdict.corpus && verdict.corpus.platform === "macos") {
      const loaded = await mod.loadMacos();
      entry = loaded ? macosEntry(loaded, ask.input) : null;
    }
    let prevalence = null;
    let noBaseline = false;
    try {
      const corpora = catalogue && catalogue.orgCorpora ? catalogue.orgCorpora() : [];
      noBaseline = corpora.length === 0;
      prevalence = noBaseline ? null : mod.prevalenceOf(ask.input, corpora.map((c) => c.doc));
    } catch {
      prevalence = null;
    }
    const m = verdictModel({ verdict, input: ask.input, entry, buildBasis: build && build.basis, prevalence });
    root.dataset.tier = m.tier;
    if (onTier) onTier(m);
    feeds.textContent = m.corpus ? `${sep}corpus: ${m.corpus}` : `${sep}no corpus for this event`;
    body.className = `reach-row__body reach-verdict__body${m.tier === "impersonation" ? " reach-row__body--danger" : ""}`;
    const baselineHref = appUrl ? appUrl(`#/st/${encodeURIComponent(mod.ORG_CORPUS_SOURCETYPE)}`) : null;
    const fleetNode = noBaseline
      ? h("span", null, "No fleet baseline yet · ", baselineHref ? h("a", { class: "reach-link", href: baselineHref, target: "_blank", rel: "noopener" }, "run it") : "run it")
      : m.fleet;
    body.replaceChildren(
      ...[
        h("div", { class: "reach-verdict__line" }, h("span", { class: "reach-chip", dataset: { basis: m.chip } }, m.tier), h("span", { class: "reach-verdict__text" }, m.headline)),
        m.detail ? h("div", { class: "reach-verdict__detail" }, m.detail) : null,
        m.hint ? h("div", { class: "reach-verdict__hint" }, m.hint) : null,
        fleetNode ? h("div", { class: "reach-verdict__fleet" }, fleetNode) : null,
        // The verdict as a notebook entry on the held value (hold: the pin fields the caller has).
        hold && m.tier !== "unknown" ? attachButton({ ...hold, field, value, container, platform, kind: "verdict", source: `known-good corpus${m.corpus ? ` (${m.corpus})` : ""}`, verdict: `${m.tier}: ${m.headline}` }) : null,
      ].filter(Boolean),
    );
  })().catch((err) => {
    root.dataset.tier = "error";
    feeds.textContent = `${sep}corpus unavailable`;
    body.className = "reach-row__body reach-row__body--muted reach-verdict__body";
    body.textContent = `Could not read the known-good corpus: ${err && err.message ? err.message : String(err)}`;
  });
  return root;
}
