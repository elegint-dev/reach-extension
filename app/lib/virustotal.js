// VirusTotal, the pure part: which clicked values are worth offering to
// VirusTotal at all, the v3 endpoint and GUI page for one, and the digest
// of a report the popup shows. No DOM, no chrome.*, no fetch. The fetch
// itself lives in background.js (the only place the user's key is read);
// the popups render from what this module makes of the response.
//
//   classify(value, { fieldName })  → { kind: "ip"|"domain"|"hash", id } | null
//   refusal(value, { fieldName })   → { kind, id, why } | null: a value shaped like one of the three
//                                     that classify() refused, with the reason in plain words, so the
//                                     popup can say why there is no offer instead of showing nothing
//   pathFor(kind, id)               → "/ip_addresses/8.8.8.8" (v3, relative to API_BASE)
//   guiUrlFor(kind, id)             → the public page for the same object
//   summarize(kind, json)           → what the popup shows, or null when the
//                                     response carries no analysis
//   describeError(status, body)     → one plain sentence for a failed lookup
//   looksLikeKey(key)               → the shape of a VT API key (64 hex)
//
// classify() is conservative. A value means something only on its
// sourcetype, and "looks like an IP" is a bare-name guess; so the only values
// offered are ones for which VirusTotal is the right question regardless
// of feed: a public IP address, a hostname with a public-looking TLD, or a
// hex string of exactly an MD5/SHA-1/SHA-256's length. Anything internal is
// refused here, before any click can send it: an RFC 1918, loopback,
// link-local, CGNAT or reserved address, a `.local`/`.internal`/`.corp`
// name, a 32-hex value on FDR's `aid` field (a sensor id, not a hash).

export const API_BASE = "https://www.virustotal.com/api/v3";
export const GUI_BASE = "https://www.virustotal.com/gui";
export const HOST_PATTERN = "https://www.virustotal.com/*";

// Free-tier limits, quoted back to the user on a 429 and in the setup text.
export const PUBLIC_QUOTA = { perMinute: 4, perDay: 500 };

// Field names whose values are hex ids that are not file hashes. FDR's
// sensor id (aid) and customer id (cid) are both 32 hex; offering them as
// MD5 lookups would spend quota on a guaranteed miss.
const NOT_A_HASH_FIELD = /^(aid|cid|agentid|sensorid|customerid|deviceid|machineid|uuid|guid|traceid|spanid|requestid|sessionid)$/;
const isIdField = (name) => NOT_A_HASH_FIELD.test(String(name || "").toLowerCase().replace(/[^a-z]/g, "")); // aid, agent_id, AgentId, agent.id

// TLDs that never resolve on the public internet. A hostname ending in one
// is internal by definition and must not be sent anywhere. `.test` and
// `.example` are RFC 2606 reserved (dev and documentation names), so
// foo.example is refused while example.com, a real name under .com, is not.
const PRIVATE_TLD = /\.(local|localhost|internal|intranet|lan|home|corp|private|test|example|invalid|localdomain|arpa)$/i;

const HEX = /^[0-9a-f]+$/i;

// Why a v4 address is not sent anywhere: "private" is an address inside a
// network (RFC 1918, loopback, link-local, CGNAT); "reserved" is a range
// that never appears as a real source on the internet (documentation
// TEST-NETs, benchmarking, multicast, 0/8). Seeded and documentation data
// is full of the second kind, which is why the popup says which it was.
function v4Refusal(a, b) {
  if (a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (
    a === 0 || // "this" network, 0.0.0.0/8
    (a === 192 && b === 0) || // IETF protocol assignments, TEST-NET-1
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51) || // TEST-NET-2 (198.51.100.0/24; close enough at /16)
    (a === 203 && b === 0) || // TEST-NET-3
    a >= 224 // multicast and reserved, incl. 255.255.255.255
  )
    return "reserved";
  return null;
}

function isPrivateV4(a, b) {
  return v4Refusal(a, b) !== null;
}

function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.some((n) => n > 255) ? null : o;
}

function classifyV4(s) {
  const o = parseV4(s);
  if (!o) return null;
  if (isPrivateV4(o[0], o[1])) return "private";
  return o.join(".");
}

// IPv6: accepted only in the compressed/uncompressed forms VirusTotal
// itself accepts (no zone id, no embedded v4 tail). Unique-local (fc00::/7),
// link-local (fe80::/10), loopback and unspecified are refused as private.
function classifyV6(s) {
  if (!s.includes(":") || /[^0-9a-f:]/i.test(s)) return null;
  const parts = s.split("::");
  if (parts.length > 2) return null;
  const groups = (p) => (p === "" ? [] : p.split(":"));
  const head = groups(parts[0]);
  const tail = parts.length === 2 ? groups(parts[1]) : [];
  if ([...head, ...tail].some((g) => g.length === 0 || g.length > 4)) return null;
  const total = head.length + tail.length;
  if (parts.length === 2 ? total > 7 : total !== 8) return null;
  const lower = s.toLowerCase();
  if (lower === "::" || lower === "::1") return "private";
  const first = (head[0] || "0").padStart(4, "0").toLowerCase();
  if (/^f[cd]/.test(first)) return "private"; // fc00::/7 unique local
  if (/^fe[89ab]/.test(first)) return "private"; // fe80::/10 link local
  if (/^ff/.test(first)) return "private"; // multicast
  return lower;
}

function classifyDomain(s) {
  if (s.length > 253 || !s.includes(".")) return null;
  if (/[^a-z0-9.\-]/i.test(s)) return null; // no scheme, path, port, @, underscore, unicode
  if (s.startsWith(".") || s.endsWith(".") || s.includes("..")) return null;
  const labels = s.split(".");
  for (const l of labels) {
    if (l.length > 63 || l.startsWith("-") || l.endsWith("-")) return null;
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/i.test(tld)) return null; // an all-digit "TLD" is an IP that failed above
  if (PRIVATE_TLD.test(s)) return "private";
  return s.toLowerCase();
}

export function classify(value, { fieldName = "" } = {}) {
  const s = String(value ?? "").trim();
  if (!s || s.length > 253) return null;

  const v4 = classifyV4(s);
  if (v4 === "private") return null;
  if (v4) return { kind: "ip", id: v4 };

  const v6 = classifyV6(s);
  if (v6 === "private") return null;
  if (v6) return { kind: "ip", id: v6 };

  if ((s.length === 32 || s.length === 40 || s.length === 64) && HEX.test(s)) {
    if (isIdField(fieldName)) return null;
    return { kind: "hash", id: s.toLowerCase() };
  }

  const d = classifyDomain(s);
  if (d === "private") return null;
  if (d) return { kind: "domain", id: d };

  return null;
}

// The reason classify() said no, for a value that looked like a candidate.
// Null when the value is not IP-, hash- or hostname-shaped at all (most
// values): then there is nothing to explain and the popup stays quiet.
export function refusal(value, { fieldName = "" } = {}) {
  const s = String(value ?? "").trim();
  if (!s || s.length > 253) return null;
  const o = parseV4(s);
  if (o) {
    const why = v4Refusal(o[0], o[1]);
    if (why === "private") return { kind: "ip", id: o.join("."), why: "a private address: inside your network, not something VirusTotal has seen" };
    if (why === "reserved") return { kind: "ip", id: o.join("."), why: "a reserved or documentation range (TEST-NET, multicast, benchmarking): nothing on the internet has this address" };
    return null;
  }
  if (classifyV6(s) === "private") return { kind: "ip", id: s.toLowerCase(), why: "a private, link-local or loopback IPv6 address" };
  if ((s.length === 32 || s.length === 40 || s.length === 64) && HEX.test(s) && isIdField(fieldName)) {
    return { kind: "hash", id: s.toLowerCase(), why: `an identifier on ${fieldName}, not a file hash` };
  }
  if (classifyDomain(s) === "private") return { kind: "domain", id: s.toLowerCase(), why: "an internal name (a TLD that never resolves on the public internet)" };
  return null;
}

const COLLECTION = { ip: "ip_addresses", domain: "domains", hash: "files" };
const GUI_SEGMENT = { ip: "ip-address", domain: "domain", hash: "file" };

export function pathFor(kind, id) {
  const c = COLLECTION[kind];
  if (!c) throw new Error(`VirusTotal: unknown kind ${kind}`);
  return `/${c}/${encodeURIComponent(id)}`;
}

export function guiUrlFor(kind, id) {
  const seg = GUI_SEGMENT[kind];
  if (!seg) throw new Error(`VirusTotal: unknown kind ${kind}`);
  return `${GUI_BASE}/${seg}/${encodeURIComponent(id)}`;
}

export function looksLikeKey(key) {
  return /^[0-9a-f]{64}$/i.test(String(key ?? "").trim());
}

// The digest the popup renders. `stats` is VirusTotal's own vendor tally;
// `facts` is a short list of [label, text] pairs that differ by kind. Dates
// come back as ISO strings so the renderer never touches epoch maths.
export function summarize(kind, json) {
  const attrs = json && json.data && json.data.attributes;
  if (!attrs) return null;
  const st = attrs.last_analysis_stats || {};
  const n = (k) => Number(st[k]) || 0;
  const stats = { malicious: n("malicious"), suspicious: n("suspicious"), harmless: n("harmless"), undetected: n("undetected") };
  stats.total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  const analysed = attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null;
  const facts = [];
  const push = (label, v) => {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return;
    facts.push([label, Array.isArray(v) ? v.join(", ") : String(v)]);
  };

  if (kind === "ip") {
    push("owner", attrs.as_owner ? (attrs.asn ? `${attrs.as_owner} (AS${attrs.asn})` : attrs.as_owner) : attrs.asn ? `AS${attrs.asn}` : null);
    push("country", attrs.country);
    push("network", attrs.network);
  } else if (kind === "domain") {
    push("registrar", attrs.registrar);
    const cats = attrs.categories && typeof attrs.categories === "object" ? [...new Set(Object.values(attrs.categories).map(String))] : [];
    push("categories", cats.slice(0, 4));
    if (attrs.creation_date) push("registered", new Date(attrs.creation_date * 1000).toISOString().slice(0, 10));
  } else if (kind === "hash") {
    const label = attrs.popular_threat_classification && attrs.popular_threat_classification.suggested_threat_label;
    push("threat label", label);
    push("name", attrs.meaningful_name || (attrs.names && attrs.names[0]));
    push("type", attrs.type_description || attrs.type_tag);
    if (typeof attrs.size === "number" && attrs.size > 0) push("size", attrs.size >= 1048576 ? `${(attrs.size / 1048576).toFixed(1)} MB` : attrs.size >= 1024 ? `${(attrs.size / 1024).toFixed(1)} KB` : `${attrs.size} B`);
    if (attrs.first_submission_date) push("first seen", new Date(attrs.first_submission_date * 1000).toISOString().slice(0, 10));
    push("sha256", attrs.sha256);
  }

  const reputation = typeof attrs.reputation === "number" ? attrs.reputation : null;
  const verdict = stats.total === 0 ? "unknown" : stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "clean";
  return { kind, verdict, stats, analysed, reputation, facts };
}

export function describeError(status, body) {
  const code = body && body.error && body.error.code;
  if (status === 0) return "Could not reach VirusTotal (network error).";
  if (status === 401) return code === "WrongCredentialsError" ? "VirusTotal rejected the API key. Check it in Reach's settings." : "VirusTotal wants an API key. Add yours in Reach's settings.";
  if (status === 403) return "VirusTotal refused this lookup for your account (a Premium-only endpoint, or a suspended key).";
  if (status === 404) return "Not in VirusTotal: nobody has submitted this yet.";
  if (status === 429) return `VirusTotal quota reached: the free key allows ${PUBLIC_QUOTA.perMinute} lookups a minute and ${PUBLIC_QUOTA.perDay} a day (resets 00:00 UTC).`;
  if (status >= 500) return `VirusTotal is having trouble (${status}). Try again in a moment.`;
  const msg = body && body.error && body.error.message;
  return msg ? `VirusTotal: ${msg}` : `VirusTotal returned ${status}.`;
}

export default { API_BASE, GUI_BASE, HOST_PATTERN, PUBLIC_QUOTA, classify, refusal, pathFor, guiUrlFor, looksLikeKey, summarize, describeError };
