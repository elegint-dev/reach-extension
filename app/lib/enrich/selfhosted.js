// A self-hosted enrichment relay as a fetch-mode source (app/lib/enrich.js):
// the user types the origin of their own MISP or IntelOwl instance in
// Reach's settings, and Reach becomes a client of it, the same reading
// docs/COMPLIANCE.md already uses for a Splunk origin ("a client for an
// internet protocol with user-specified servers" is outside the Limited Use
// section, Chrome's User Data FAQ Q15). No new named third-party recipient
// enters the privacy policy: the recipient is the org's own instance, under
// the org's own account, not a service Reach ships a relationship with. This
// is how the commercially restricted providers (AbuseIPDB, Censys, Hybrid
// Analysis) can still reach an analyst: through the org's own licensed
// instance and terms, via an IntelOwl analyzer, never through Reach itself.
//
// Off by default, gated the same way CIRCL and EPSS are (app/lib/enrich.js's
// gate() reads enabledIds; the caller populates it once Settings has an
// origin and, when the provider needs one, a token). Storage of the origin,
// token and provider, and the host permission request/revoke, live in
// app/components/moduleList.js and background.js: this module stays pure
// (no DOM, no chrome.*, no fetch of its own), like virustotal.js and
// circl.js. ctx.ask is the background relay; ctx.origin/ctx.token/ctx.provider
// are read from Settings by the caller and passed in, never stored here.
//
//   relay                  the background worker's descriptor (background.js lookup()
//                          and write()): the four keys, the typed origin as host
//                          pattern, the per-provider URL and authorization header,
//                          and the MISP write operations (writes, below)
//   classify(value, ctx)   { kind: "hash"|"ip"|"domain"|"url"|"cve", id } | null
//   mispTypeFor(kind, id)  the MISP attribute type a classified value is proposed as
//   originStatus(origin)   { ok, origin?, warn?, why? } https required;
//                           http accepted only for localhost or an RFC1918
//                           address, with a warning rather than a refusal
//   patternFor(origin)     "https://host:port/*" | null, the host permission
//                           pattern for an accepted origin (mirrors popup.js's
//                           own `${u.protocol}//${u.host}/*`)
//   deepLinkFor(provider, origin, value)   { href, label } | null
//   summarize(provider, json)              [line, ...] for one provider's response
//   call(value, ctx)       { status, lines, link, actions? } (the enrich.js registry
//                          contract); on MISP with writes on, a hit carries the
//                          "Record sighting" action and a miss the "Propose to MISP"
//                          action, each a click of its own through the relay
//   source                 the ready-to-register object
//
// Writes (MISP only, off by default behind the module's own toggle): a
// sighting on a matched attribute (POST /sightings/add/<attribute id>) and
// a proposed attribute on an event the analyst picks from the instance's
// recent ones (GET /events/index, then POST /attributes/add/<event id>,
// to_ids false, comment from the Hold reason). MISP's
// Security.check_sec_fetch_site_header guard (on by default) answers 405 to
// any POST whose Sec-Fetch-Site is not "same-origin", and an extension
// worker's fetch never is; GET /sightings/add and GET /attributes/add only
// return the API description (verified on 2.5.47), so the write paths are
// real POSTs that need the guard off on the analyst's instance. The toggle
// says so in its hint, and the 405 answer repeats it.

import { classify as vtClassify } from "../virustotal.js";
import { detectCve, detectUrl } from "../shapes.js";
import { KEYS } from "../storage-keys.js";

export const PROVIDERS = ["misp", "intelowl"];
export const PROVIDER_LABEL = { misp: "MISP", intelowl: "IntelOwl" };

const KINDS = ["hash", "ip", "domain", "url", "cve"];
const EVENTS_PAGE = 8;
const ID_RE = /^\d{1,12}$/;

export const WRITES_HINT = "Off, Reach only reads. On, \"Record sighting\" (a sighting on each attribute that matched the value) and \"Propose to MISP\" (one attribute on an event you pick) write on your click, under your own key. Needs Security.check_sec_fetch_site_header off on your MISP: with it on (the default) MISP answers 405 to any POST from a browser extension.";

// The attribute type a value is proposed as. A hash by digest length; an
// address as ip-dst (the more common direction for an indicator seen in
// telemetry); a CVE id as MISP's vulnerability type.
export function mispTypeFor(kind, id) {
  const s = String(id ?? "");
  if (kind === "hash") return s.length === 32 ? "md5" : s.length === 40 ? "sha1" : s.length === 64 ? "sha256" : null;
  return { ip: "ip-dst", domain: "domain", url: "url", cve: "vulnerability" }[kind] || null;
}

function str(v) {
  return typeof v === "string" ? v.trim() : "";
}

// MISP: /attributes/restSearch as a GET with the search terms in the
// query string, not the documented POST-with-JSON-body form. MISP's
// Security.check_sec_fetch_site_header guard (on by default) throws 405
// on any POST/PUT/AJAX whose Sec-Fetch-Site is not "same-origin", and an
// extension worker's fetch reads "none" there; the guard never inspects a
// plain GET, and restSearch accepts the same parameters as a query
// string. includeEventTags pulls the event's own tags onto each row,
// includeSightings the sightings the row shows a count of.
// IntelOwl: existing jobs for the observable only, never
// analyze_observable (a new analyzer run per click is too heavy).
function urlFor(id, cfg) {
  if (cfg.provider === "misp") {
    const qs = new URLSearchParams({ returnFormat: "json", value: id, includeEventTags: "1", includeSightings: "1" });
    return `${cfg.origin}/attributes/restSearch?${qs.toString()}`;
  }
  return `${cfg.origin}/api/jobs?observable_name=${encodeURIComponent(id)}`;
}

// A MISP write answer: the body's own message when it has one (a
// duplicate attribute answers 403 with errors.value), the guard's 405 with
// the setting to change, a 401 as the token.
function writeAnswer({ ok, status, body }, cfg) {
  const res = { ok, status, provider: cfg.provider, data: body };
  if (ok) return res;
  const said = body && typeof body === "object" ? [body.message, ...(body.errors && typeof body.errors === "object" ? Object.values(body.errors).flat() : [])].filter((x) => typeof x === "string" && x && x !== body.name).join(" ") : "";
  if (status === 401) res.error = `${cfg.origin} rejected the token.`;
  else if (status === 405) res.error = `${cfg.origin} refused the write (405): MISP's Security.check_sec_fetch_site_header guard is on there. Turn it off on your MISP, or leave writes off in Reach.`;
  else res.error = said ? `${cfg.origin} returned ${status}: ${said}` : `${cfg.origin} returned ${status}.`;
  return res;
}

// The write operations background.js write() runs, each a method, a URL
// and a JSON body from the message, after the same module, origin and
// permission checks a lookup passes and the writes toggle on top.
const writes = Object.freeze({
  events: {
    method: "GET",
    accepts: () => true,
    url: (msg, cfg) => `${cfg.origin}/events/index/limit:${EVENTS_PAGE}/sort:timestamp/direction:desc`,
    body: () => null,
    answer: writeAnswer,
  },
  sighting: {
    method: "POST",
    accepts: (msg) => ID_RE.test(String(msg.attributeId ?? "")),
    url: (msg, cfg) => `${cfg.origin}/sightings/add/${msg.attributeId}`,
    body: () => ({ source: "Reach" }),
    answer: writeAnswer,
  },
  attribute: {
    method: "POST",
    accepts: (msg) => ID_RE.test(String(msg.eventId ?? "")) && KINDS.includes(msg.kind) && typeof msg.id === "string" && msg.id.length > 0 && msg.id.length <= 2048 && Boolean(mispTypeFor(msg.kind, msg.id)),
    url: (msg, cfg) => `${cfg.origin}/attributes/add/${msg.eventId}`,
    body: (msg) => ({ type: mispTypeFor(msg.kind, msg.id), value: msg.id, comment: str(msg.comment).slice(0, 2000), to_ids: false }),
    answer: writeAnswer,
  },
});

export const relay = Object.freeze({
  id: "selfhosted",
  messages: { status: "reach:selfhosted:status", lookup: "reach:selfhosted:lookup", write: "reach:selfhosted:write" },
  keys: [KEYS.selfhostedOrigin, KEYS.selfhostedToken, KEYS.selfhostedProvider, KEYS.selfhostedWrites],
  config: (got) => ({
    origin: str(got[KEYS.selfhostedOrigin]),
    token: str(got[KEYS.selfhostedToken]),
    provider: PROVIDERS.includes(got[KEYS.selfhostedProvider]) ? got[KEYS.selfhostedProvider] : "misp",
    writes: got[KEYS.selfhostedWrites] === true,
  }),
  // The typed origin is the host permission: nothing here is a fixed
  // allowlist entry.
  hosts: (cfg) => [patternFor(cfg.origin)].filter(Boolean),
  configured: (cfg) => Boolean(cfg.origin && patternFor(cfg.origin)),
  status: (cfg, permitted) => ({ ok: true, configured: Boolean(cfg.origin && patternFor(cfg.origin)), permitted, provider: cfg.provider, origin: cfg.origin, writes: cfg.provider === "misp" && cfg.writes }),
  accepts: (kind, id) => KINDS.includes(kind) && id.length > 0 && id.length <= 2048,
  method: "GET",
  url: (kind, id, cfg) => urlFor(id, cfg),
  headers: (cfg) => ({ accept: "application/json", authorization: cfg.provider === "misp" ? cfg.token : `Token ${cfg.token}` }),
  answer: ({ ok, status, body }, cfg) => {
    const res = { ok, status, provider: cfg.provider, data: body };
    if (!ok) res.error = status === 401 ? `${cfg.origin} rejected the token.` : `${cfg.origin} returned ${status}.`;
    return res;
  },
  // An MV3 extension fetch with a host permission is not subject to CORS,
  // so a rejected fetch means the server is unreachable, not a CORS block.
  failure: (cfg, why) => ({ ok: false, status: 0, provider: cfg.provider, error: `Could not reach ${cfg.origin} (${why}).` }),
  // Writes: MISP only, and only with the module's writes toggle on.
  writable: (cfg) => cfg.provider === "misp" && cfg.writes === true,
  writes,
  errors: {
    unconfigured: "Self-hosted enrichment is not set up: add your server's origin in Reach's settings.",
    unpermitted: "Reach has no permission to contact this server yet. Save the origin again in Reach's settings to grant it.",
    refused: "Lookup refused: not a shape this source answers.",
    writesOff: "Writes to MISP are off: turn on \"Allow writes to MISP\" in Reach's settings (MISP only).",
    writeRefused: "Write refused: not a request this source makes.",
  },
});

export function classify(value, ctx = {}) {
  const cve = detectCve(value);
  if (cve) return { kind: "cve", id: cve.detail };
  const vt = vtClassify(value, { fieldName: ctx.fieldName });
  if (vt) return { kind: vt.kind, id: vt.id }; // ip | domain | hash, the same conservative rule VirusTotal uses
  const s = String(value ?? "").trim();
  if (s && s.length <= 2048 && detectUrl(s)) return { kind: "url", id: s };
  return null;
}

// RFC 1918, loopback and the common local hostnames: the only hosts http
// (rather than https) is accepted for, and only with a warning kept and
// shown, never silently dropped.
function isLocalOrPrivateHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h.endsWith(".localhost")) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const [a, b] = m.slice(1).map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

// A bare origin only: no path, query or fragment, so the value can never
// carry a credential or a routing trick into a fetch built from it later.
export function originStatus(origin) {
  const s = String(origin ?? "").trim().replace(/\/+$/, "");
  if (!s) return { ok: false, why: "" };
  let u;
  try {
    u = new URL(s);
  } catch {
    return { ok: false, why: "Not a valid URL." };
  }
  if ((u.pathname && u.pathname !== "/") || u.search || u.hash) return { ok: false, why: "Only a bare origin is accepted (no path, query or fragment)." };
  if (u.protocol === "https:") return { ok: true, origin: `${u.protocol}//${u.host}` };
  if (u.protocol === "http:") {
    if (isLocalOrPrivateHost(u.hostname)) return { ok: true, origin: `${u.protocol}//${u.host}`, warn: "http, not https. Only accepted because this looks like a local or private address." };
    return { ok: false, why: "http is only accepted for localhost or a private (RFC 1918) address; use https for anything else." };
  }
  return { ok: false, why: "Only http or https is accepted." };
}

export function patternFor(origin) {
  const status = originStatus(origin);
  if (!status.ok) return null;
  const u = new URL(status.origin);
  return `${u.protocol}//${u.host}/*`;
}

// MISP's own attribute-search page (source-verified in AttributesController.php,
// see docs/COMPLIANCE.md); IntelOwl has no documented per-value URL, so the
// deep link opens the instance itself rather than guess a path that 404s.
export function deepLinkFor(provider, origin, value) {
  const status = originStatus(origin);
  if (!status.ok) return null;
  if (provider === "misp") return { href: `${status.origin}/attributes/index?value=${encodeURIComponent(value)}`, label: "Open in MISP ↗" };
  if (provider === "intelowl") return { href: `${status.origin}/`, label: "Open IntelOwl ↗" };
  return null;
}

export function linkFor(value, ctx = {}) {
  return deepLinkFor(ctx.provider, ctx.origin, value);
}

// Tag display order: TLP first (the handling marker), then the ATT&CK
// galaxy/technique tag, then whatever else is on the attribute, and
// false-positive last (a deliberate downgrade, not a fact about the value
// like the others). The request asks for includeEventTags, which merges
// each event's own tags into every matching attribute's Tag array, but the
// merge order MISP returns depends on which side (event or attribute) a
// tag is attached to, not on this priority, so it is re-sorted here rather
// than trusted as given.
function tagClass(name) {
  if (/^tlp:/i.test(name)) return 0;
  if (/^misp-galaxy:mitre-attack-pattern=/i.test(name)) return 1;
  if (name === "false-positive") return 3;
  return 2;
}
function orderTags(names) {
  return names
    .map((name, i) => ({ name, i }))
    .sort((a, b) => tagClass(a.name) - tagClass(b.name) || a.i - b.i)
    .map((x) => x.name);
}

// MISP: /attributes/restSearch returns matching Attribute rows; summarised
// as an event count plus the union of their tags, and the sightings the
// rows carry (includeSightings) as one count.
function mispRows(json) {
  return json && json.response && Array.isArray(json.response.Attribute) ? json.response.Attribute.filter((r) => r && typeof r === "object") : [];
}

// The matched attributes a sighting can be recorded on: id, type and the
// sightings each already has.
export function mispHits(json) {
  return mispRows(json)
    .filter((r) => ID_RE.test(String(r.id ?? "")))
    .map((r) => ({ id: String(r.id), type: String(r.type || ""), eventId: String(r.event_id || ""), sightings: Array.isArray(r.Sighting) ? r.Sighting.length : 0 }));
}

function summarizeMisp(json) {
  const rows = mispRows(json);
  if (!rows.length) return [];
  const events = new Set(rows.map((r) => r.event_id).filter(Boolean));
  const tags = new Set();
  for (const r of rows) for (const t of Array.isArray(r.Tag) ? r.Tag : []) if (t && t.name) tags.add(t.name);
  const lines = [`${rows.length} matching attribute${rows.length === 1 ? "" : "s"} across ${events.size} event${events.size === 1 ? "" : "s"}.`];
  if (tags.size) {
    const ordered = orderTags([...tags]);
    lines.push(`tags: ${ordered.slice(0, 8).join(", ")}${ordered.length > 8 ? ", …" : ""}`);
  }
  if (rows.some((r) => Array.isArray(r.Sighting))) {
    const n = rows.reduce((sum, r) => sum + (Array.isArray(r.Sighting) ? r.Sighting.length : 0), 0);
    lines.push(`sightings: ${n}`);
  }
  return lines;
}

// IntelOwl: a job lookup by observable (GET /api/jobs?observable_name=),
// never a new analysis (analyze_observable would spend the instance's own
// analyzer quota on every click, too heavy for an explicit-click lookup).
function summarizeIntelowl(json) {
  const results = json && Array.isArray(json.results) ? json.results : Array.isArray(json) ? json : [];
  if (!results.length) return [];
  const latest = results[0];
  const status = latest && latest.status ? String(latest.status) : "unknown";
  const when = latest && (latest.received_request_time || latest.finished_analysis_time);
  const lines = [`${results.length} prior job${results.length === 1 ? "" : "s"} for this observable (latest: ${status}${when ? ` on ${String(when).slice(0, 10)}` : ""}).`];
  return lines;
}

export function summarize(provider, json) {
  if (provider === "misp") return summarizeMisp(json);
  if (provider === "intelowl") return summarizeIntelowl(json);
  return [];
}

async function askSafely(ask, msg) {
  try {
    const res = await ask(msg);
    return res || { ok: false, status: 0, error: "No answer from Reach's background worker." };
  } catch (err) {
    return { ok: false, status: 0, error: err && err.message ? err.message : String(err) };
  }
}

function writeError(res, verb) {
  return { status: "error", lines: [res && res.error ? res.error : `MISP ${verb} failed (${res ? res.status : 0}).`] };
}

// The events the analyst can propose to: the instance's most recent
// page, newest first, as { id, label }.
export function eventChoices(json) {
  const rows = Array.isArray(json) ? json : json && Array.isArray(json.response) ? json.response : [];
  return rows
    .map((e) => (e && e.Event && typeof e.Event === "object" ? e.Event : e))
    .filter((e) => e && ID_RE.test(String(e.id ?? "")))
    .map((e) => ({ id: String(e.id), label: `${str(e.info) || "(untitled)"}${e.date ? ` (${e.date})` : ""}${e.published === false ? ", unpublished" : ""}` }));
}

// "Record sighting" on a hit: one sighting per matched attribute (a value
// seen in several events has an attribute in each), in order, stopping at
// the first refusal; then the same lookup again so the row shows the
// count MISP now holds.
function sightingAction(value, c, ctx, hits) {
  const n = hits.length;
  return {
    id: "sighting",
    label: "Record sighting",
    title: n === 1 ? 'Record a sighting of this value on its MISP attribute, as source "Reach". One write, on this click.' : `Record a sighting of this value on each of the ${n} matching MISP attributes, as source "Reach". ${n} writes, on this click.`,
    run: async () => {
      for (const hit of hits) {
        const res = await askSafely(ctx.ask, { type: "reach:selfhosted:write", op: "sighting", attributeId: hit.id });
        if (!res.ok) return writeError(res, "sighting");
      }
      const again = await call(value, ctx);
      if (again.status === "ok") again.lines = [`Sighting recorded (source: Reach).`, ...again.lines];
      return again;
    },
  };
}

// "Propose to MISP" on a miss: only offered on a held value (the row
// checks the pin; a click here never holds), with the Hold reason as the
// attribute's comment. The analyst picks the event, then the attribute is
// added with to_ids false, a proposal for the instance's own reviewers.
function proposeAction(c, ctx) {
  return {
    id: "propose",
    label: "Propose to MISP",
    held: true,
    title: `Add this value as a ${mispTypeFor(c.kind, c.id)} attribute (to_ids false) to one of your recent MISP events, with the Hold reason as its comment. One write, on this click, after you pick the event.`,
    run: async ({ reason = "" } = {}) => {
      const listed = await askSafely(ctx.ask, { type: "reach:selfhosted:write", op: "events" });
      if (!listed.ok) return writeError(listed, "event listing");
      const choices = eventChoices(listed.data);
      if (!choices.length) return { status: "empty", lines: ["No events on MISP to propose to: create one there first."] };
      return {
        status: "choose",
        prompt: "Propose to which event?",
        choices,
        submit: async (eventId) => {
          const pick = choices.find((e) => e.id === String(eventId));
          if (!pick) return { status: "error", lines: ["Pick an event first."] };
          const res = await askSafely(ctx.ask, { type: "reach:selfhosted:write", op: "attribute", eventId: pick.id, kind: c.kind, id: c.id, comment: str(reason) });
          if (!res.ok) return writeError(res, "proposal");
          const a = res.data && res.data.Attribute ? res.data.Attribute : {};
          return { status: "ok", lines: [`Proposed to "${pick.label}" as ${a.type || mispTypeFor(c.kind, c.id)}${a.id ? ` (attribute ${a.id}` : " (attribute"}, to_ids false).`] };
        },
      };
    },
  };
}

export async function call(value, ctx = {}) {
  const c = classify(value, ctx);
  if (!c) return { status: "refused", lines: [] };
  const provider = PROVIDERS.includes(ctx.provider) ? ctx.provider : "misp";
  const link = deepLinkFor(provider, ctx.origin, value);
  if (typeof ctx.ask !== "function") return { status: "error", lines: ["Self-hosted enrichment needs Reach's background worker, not available here."], link };
  const res = await askSafely(ctx.ask, { type: "reach:selfhosted:lookup", kind: c.kind, id: c.id });
  if (!res.ok) {
    const text = res.error ? res.error : `${PROVIDER_LABEL[provider] || provider} returned ${res.status || 0}.`;
    return { status: "error", lines: [text], link };
  }
  const answered = PROVIDERS.includes(res.provider) ? res.provider : provider;
  const lines = summarize(answered, res.data);
  const out = lines.length ? { status: "ok", lines, link } : { status: "empty", lines: [`Nothing on record for this value in ${PROVIDER_LABEL[answered] || answered}.`], link };
  // The write actions, MISP only and only while the writes toggle is on
  // (the worker's status says so; a status message never fetches).
  if (answered === "misp") {
    const st = await askSafely(ctx.ask, { type: "reach:selfhosted:status" });
    if (st.ok && st.writes === true) {
      const hits = mispHits(res.data);
      if (out.status === "ok" && hits.length) out.actions = [sightingAction(value, c, ctx, hits)];
      else if (out.status === "empty") out.actions = [proposeAction(c, ctx)];
    }
  }
  return out;
}

export const source = {
  id: "selfhosted",
  label: "Self-hosted (MISP / IntelOwl)",
  kinds: ["hash", "ip", "domain", "url", "cve"],
  mode: "fetch",
  recipients: ["the self-hosted server you type into Reach's settings, under your own account there, never a third party Reach names"],
  call,
  linkFor,
};

export default { PROVIDERS, PROVIDER_LABEL, WRITES_HINT, classify, mispTypeFor, mispHits, eventChoices, originStatus, patternFor, deepLinkFor, linkFor, summarize, call, source, relay };
