// Value shapes: what a column's values look like, independent of its
// name. Every detector is whole-string anchored (a value either is the
// shape or it is not; no substring hits) and Sentinel-truncation aware:
// recipe.js cuts a top value at 200 characters before it is stored, so a
// detector for a shape that can be long (json, url, arn) matches a
// truncated prefix rather than demanding the value end cleanly.
//
//   shapeOf(value)                         -> { shape, detail } | null   one value
//   detectProcessName(value)               -> { shape, detail } | null   a binary/driver/DLL name, for app/lib/enrich.js
//   detectUrl(value)                       -> { shape, detail } | null   an absolute URL, for app/lib/enrich.js
//   classify(values: [{value,count}])     -> { shape, share, matched, total }
//                                             the dominant shape by count share
//   shapeSupports(shape, conceptType)      -> boolean   the shape is expected evidence for this taxonomy type
//   shapeVeto(shape, conceptType)          -> boolean   the shape rules a candidate of this type out
//   numericVeto(conceptType)               -> boolean   an all-numeric column can never carry this type
//   POSITIVE_SHAPES                        Set   shapes that are strong evidence on their own, name match or not
//   VETO_ONLY_SHAPES                       Set   shapes that never confirm a type by themselves, only rule one out
//   SUPPORTS, VETOES                       the evidence tables, exported so a test can hold their invariants
//
// propose.js is the only caller. No DOM, no store, no network.

const TRUNCATE_AT = 200; // recipe.js TOP_VALUE_MAX; kept local so this module has no cross-import

function truncated(s) {
  return s.length >= TRUNCATE_AT;
}

// ---------------------------------------------------------------------------
// Detectors. Each returns { shape, detail } or null. Order in shapeOf()
// matters: more specific patterns are tried before general ones.

const ARN_RE = /^arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:(.+)$/;
function detectArn(v) {
  const m = ARN_RE.exec(v);
  if (!m && !truncated(v)) return null;
  if (!m) {
    // A truncated value: the prefix through the resource part is enough.
    if (!/^arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:/.test(v)) return null;
    return { shape: "arn", detail: null };
  }
  const service = m[0].split(":")[2];
  const resource = m[1];
  let detail = null;
  if (/^user\//.test(resource)) detail = "user";
  else if (/^assumed-role\//.test(resource)) detail = "assumed-role";
  else if (/^role\//.test(resource)) detail = "role";
  else if (service === "sts") detail = "sts_session";
  return { shape: "arn", detail };
}

const ACCESS_KEY_RE = /^(AKIA|ASIA)[A-Z0-9]{16}$/;
function detectAccessKey(v) {
  return ACCESS_KEY_RE.test(v) ? { shape: "aws_access_key", detail: v.startsWith("ASIA") ? "temporary" : "long_term" } : null;
}

// An assumed-role principal id carries the session name after a colon
// (AROA...:session), so the suffix is optional.
const PRINCIPAL_ID_RE = /^(AIDA|AROA)[A-Z0-9]{17}(:[^\s:]+)?$/;
function detectPrincipalId(v) {
  return PRINCIPAL_ID_RE.test(v) ? { shape: "aws_principal_id", detail: null } : null;
}

const SID_RE = /^S-1-\d+(-\d+)+$/;
function detectSid(v) {
  return SID_RE.test(v) ? { shape: "sid", detail: null } : null;
}

const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
// Windows and Sysmon write GUIDs in braces ({550e8400-...}: LogonGuid,
// ProcessGuid, ProviderGuid); that is still a guid, not json.
function detectGuid(v) {
  const bare = v.length > 2 && v[0] === "{" && v[v.length - 1] === "}" ? v.slice(1, -1) : v;
  return GUID_RE.test(bare) ? { shape: "guid", detail: bare === v ? null : "braced" } : null;
}

// 40/64 hex only: sha1/sha256, unambiguous with a 32-char id. A 32-char hex
// string (md5, but also a CrowdStrike aid or a bare host id) is hex32: the
// string alone cannot tell an md5 apart from an opaque 32-char id, and
// shapeSupports lists hex32 under file_hash too.
const HEX_RE = /^[0-9a-fA-F]+$/;
function detectHash(v) {
  if (!HEX_RE.test(v)) return null;
  if (v.length === 40) return { shape: "hash", detail: "sha1" };
  if (v.length === 64) return { shape: "hash", detail: "sha256" };
  return null;
}
function detectHex32(v) {
  return HEX_RE.test(v) && v.length === 32 ? { shape: "hex32", detail: null } : null;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function isV4(v) {
  const m = IPV4_RE.exec(v);
  return Boolean(m && m.slice(1).every((o) => Number(o) <= 255));
}
const V6_GROUP_RE = /^[0-9a-fA-F]{1,4}$/;
// A real IPv6 check, not "hex and colons": at most one "::", every group 1
// to 4 hex digits, exactly 8 groups uncompressed or at most 7 compressed
// with at least one group present, an optional dotted v4 tail (which
// counts as two groups) and an optional %zone suffix. A MAC address (six
// groups, no "::"), a clock time (three groups) and a bare "::" all fail.
function isV6(v) {
  const zone = v.indexOf("%");
  const s = zone >= 0 ? v.slice(0, zone) : v;
  if (!s || !s.includes(":")) return false;
  const halves = s.split("::");
  if (halves.length > 2) return false;
  let groups = 0;
  for (let i = 0; i < halves.length; i++) {
    const half = halves[i];
    if (half === "") continue;
    const parts = half.split(":");
    for (let j = 0; j < parts.length; j++) {
      const p = parts[j];
      const last = i === halves.length - 1 && j === parts.length - 1;
      if (last && p.includes(".")) {
        if (!isV4(p)) return false;
        groups += 2;
      } else if (V6_GROUP_RE.test(p)) {
        groups += 1;
      } else {
        return false;
      }
    }
  }
  if (!groups) return false;
  return halves.length === 2 ? groups <= 7 : groups === 8;
}
function detectIp(v) {
  if (isV4(v)) return { shape: "ip", detail: "v4" };
  // Bracketed v6 ([2001:db8::1], the URL and proxy-log form) is still an
  // address; with a port after the bracket it is a socket, not an address.
  const bare = v.length > 2 && v[0] === "[" && v[v.length - 1] === "]" ? v.slice(1, -1) : v;
  if (isV6(bare)) return { shape: "ip", detail: "v6" };
  return null;
}

// 10-digit (seconds) or 13-digit (milliseconds) epoch: a subset of plain
// integers, so this is tried before detectInteger, and only inside the
// years 2001 to 2099 so an arbitrary 10-digit id is not a timestamp.
const EPOCH_MIN_S = 978307200; // 2001-01-01
const EPOCH_MAX_S = 4102444800; // 2100-01-01
function detectEpoch(v) {
  if (/^\d{10}$/.test(v)) {
    const n = Number(v);
    return n >= EPOCH_MIN_S && n < EPOCH_MAX_S ? { shape: "epoch", detail: "s" } : null;
  }
  if (/^\d{13}$/.test(v)) {
    const n = Number(v) / 1000;
    return n >= EPOCH_MIN_S && n < EPOCH_MAX_S ? { shape: "epoch", detail: "ms" } : null;
  }
  return null;
}

const ISO_TIME_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/;
function detectIsoTime(v) {
  return ISO_TIME_RE.test(v) ? { shape: "iso_time", detail: null } : null;
}

// A whole value must parse to an object or array. A value cut at 200
// characters cannot parse, so for those the opening is enough when it
// reads as JSON structure ({" or [{ or ["), not merely a brace: a braced
// GUID, a bracketed address, a [INFO] log prefix or a {DEFAULT}
// placeholder is not json.
const JSON_OPEN_RE = /^(\{\s*"|\[\s*[{["\d-]|\{\s*\}|\[\s*\])/;
function detectJson(v) {
  const s = v.trim();
  if (s[0] !== "{" && s[0] !== "[") return null;
  if (truncated(v)) return JSON_OPEN_RE.test(s) ? { shape: "json", detail: null } : null;
  try {
    const parsed = JSON.parse(s);
    return parsed && typeof parsed === "object" ? { shape: "json", detail: null } : null;
  } catch {
    return null;
  }
}

const URL_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/\S+$/;
// Exported (unlike detectCve/detectTechnique, kept for the same reason: a
// shape app/lib/enrich.js offers a lookup on, not a taxonomy type) so the
// self-hosted enrichment source can offer on a URL without a second regex.
export function detectUrl(v) {
  return URL_RE.test(v) ? { shape: "url", detail: null } : null;
}

const LOCAL_AT_DOMAIN_RE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const PUBLIC_EMAIL_DOMAINS = new Set(["gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me", "msn.com", "mail.com", "gmx.com", "gmx.de", "yandex.com", "zoho.com"]);
// UPN and email share the same local@domain shape (Microsoft's own guidance
// is that a UPN looks like an email address), and no value can tell them
// apart. The split below is a label only: a public mailbox provider reads
// as email, anything else as upn. Neither shape is positive evidence and
// neither vetoes anything, so which side of the line a mailbox column
// lands on never changes a proposal; both merely confirm a principal or
// user-name candidate the name already found.
function detectUpnOrEmail(v) {
  if (!LOCAL_AT_DOMAIN_RE.test(v)) return null;
  const domain = v.slice(v.lastIndexOf("@") + 1).toLowerCase();
  return PUBLIC_EMAIL_DOMAINS.has(domain) ? { shape: "email", detail: null } : { shape: "upn", detail: null };
}

const DOMAIN_RE = /^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
// A file name (svchost.exe, app.log) has the same dotted-labels form; the
// last label tells them apart.
const FILE_EXTENSIONS = new Set(["exe", "dll", "sys", "log", "txt", "json", "xml", "yml", "yaml", "ini", "cfg", "conf", "csv", "tmp", "dat", "bat", "cmd", "ps1", "vbs", "js", "py", "sh", "zip", "gz", "tar", "html", "htm", "php", "asp", "aspx", "jar", "war", "class", "so", "bin", "msi", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "lnk", "scr"]);
function detectDomain(v) {
  if (!DOMAIN_RE.test(v)) return null;
  const tld = v.slice(v.lastIndexOf(".") + 1).toLowerCase();
  return FILE_EXTENSIONS.has(tld) ? null : { shape: "domain", detail: null };
}

function detectInteger(v) {
  return /^-?\d+$/.test(v) ? { shape: "integer", detail: null } : null;
}

const BOOL_WORDS = new Set(["true", "false", "yes", "no"]);
function detectBool(v) {
  return BOOL_WORDS.has(v.toLowerCase()) ? { shape: "bool", detail: null } : null;
}

// CVE ids: CVE-YYYY-NNNN or longer (the official form allows four or more
// digits after the year, no upper bound). Kept out of DETECTORS/SUPPORTS:
// this is not a taxonomy-type detector, just a shape app/lib/enrich.js uses
// to offer the KEV lookup on any field, not only one named "cve".
const CVE_RE = /^CVE-(19|20)\d{2}-\d{4,}$/i;
export function detectCve(v) {
  const s = String(v == null ? "" : v).trim();
  return CVE_RE.test(s) ? { shape: "cve", detail: s.toUpperCase() } : null;
}

// MITRE ATT&CK technique ids: T#### or T####.### (a sub-technique). A
// tactic id (TA####) does not match: the extra "A" fails the digit run.
// Kept out of DETECTORS/SUPPORTS for the same reason as detectCve: a
// shape app/lib/enrich.js offers a lookup on, not a taxonomy type.
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/i;
export function detectTechnique(v) {
  const s = String(v == null ? "" : v).trim();
  return TECHNIQUE_RE.test(s) ? { shape: "technique", detail: s.toUpperCase() } : null;
}

// A process, driver or library file name: app/lib/enrich.js's kindsFor()
// splits this one shape into three offer kinds by extension (driver_name
// for .sys, dll_name for .dll, binary_name for everything else the LOL*
// living-off-the-land sources answer: LOLDrivers, LOLRMM, LOLBAS,
// GTFOBins, HijackLibs), so a driver click never grows a GTFOBins row.
// Kept out of DETECTORS/SUPPORTS for the same reason as detectCve: a
// lookup shape, not a taxonomy type. Deliberately
// narrow (app/lib/virustotal.js classify()'s own "a bare-name guess is
// not enough" discipline): a bare word with no path and no recognised
// extension never matches, so a random string or id column does not grow
// a GTFOBins row on every click. Two forms match: a name carrying one of
// the extensions LOL* datasets use (a Windows binary, driver or DLL,
// wherever it appears, bare or in a full path), or the basename of a
// path with no extension at all (a POSIX binary such as GTFOBins' own
// entries, which are never bare words in a Sysmon or auditd row).
const PROCESS_NAME_EXT = new Set(["exe", "dll", "sys", "ps1", "msi", "bat", "cmd", "vbs", "scr"]);
export function detectProcessName(v) {
  const s = String(v == null ? "" : v).trim();
  if (!s || /\s/.test(s) || s.length > 260) return null;
  const hasSep = /[\\/]/.test(s);
  const base = hasSep ? (s.split(/[\\/]/).filter(Boolean).pop() || "") : s;
  if (!base || !/^[\w.+-]+$/.test(base)) return null;
  const dot = base.lastIndexOf(".");
  const ext = dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
  if (ext && PROCESS_NAME_EXT.has(ext)) return { shape: "process_name", detail: base };
  if (!ext && hasSep) return { shape: "process_name", detail: base };
  return null;
}

const DETECTORS = [
  detectArn,
  detectAccessKey,
  detectPrincipalId,
  detectSid,
  detectGuid,
  detectHash,
  detectHex32,
  detectIp,
  detectEpoch,
  detectIsoTime,
  detectJson,
  detectUrl,
  detectUpnOrEmail,
  detectDomain,
  detectInteger,
  detectBool,
];

export function shapeOf(value) {
  const v = String(value == null ? "" : value).trim();
  if (!v) return null;
  for (const d of DETECTORS) {
    const got = d(v);
    if (got) return got;
  }
  return null;
}

// ---------------------------------------------------------------------------
// classify(): the dominant shape across a top-values list, weighted by count.

export function classify(values) {
  const list = Array.isArray(values) ? values.filter((v) => v && v.value !== undefined && v.value !== null && String(v.value) !== "") : [];
  const total = list.reduce((sum, v) => sum + (Number.isFinite(Number(v.count)) ? Number(v.count) : 1), 0);
  const byShape = new Map();
  const hitsByShape = new Map(); // distinct top values per shape, the count a person can check against the list
  for (const v of list) {
    const got = shapeOf(v.value);
    if (!got) continue;
    const w = Number.isFinite(Number(v.count)) ? Number(v.count) : 1;
    byShape.set(got.shape, (byShape.get(got.shape) || 0) + w);
    hitsByShape.set(got.shape, (hitsByShape.get(got.shape) || 0) + 1);
  }
  let shape = null;
  let matched = 0;
  for (const [s, w] of byShape) {
    if (w > matched) {
      shape = s;
      matched = w;
    }
  }
  return { shape, share: total ? matched / total : 0, matched, total, values: list.length, hits: shape ? hitsByShape.get(shape) : 0 };
}

// ---------------------------------------------------------------------------
// Evidence tables: value shape -> taxonomy type id (app/packs/taxonomy.json).
// Kept here, not in the taxonomy, because one taxonomy type accepts several
// shapes (principal: arn or upn or sid) and one shape supports several types.
//
// Three classes of shape:
//   positive: so specific to one kind of thing that the values alone carry
//     a proposal (an ARN, an AWS access key or principal id, a Windows SID);
//   veto-only: common enough that they only ever rule a candidate out (an
//     IP, a GUID, a hash): they never add to a score, name match or not;
//   the rest confirm: they add to a name match that already exists.
// A UPN is not positive: a sender, recipient or target-mailbox column looks
// exactly like one, so it only confirms a principal the name already found.

export const POSITIVE_SHAPES = new Set(["arn", "aws_access_key", "aws_principal_id", "sid"]);
export const VETO_ONLY_SHAPES = new Set(["ip", "guid", "hash"]);

// Shapes a type is expected to carry. A type with no row is "unknown":
// no shape confirms it and no shape vetoes it beyond the VETOES row and
// the universal json veto (shapeVeto).
export const SUPPORTS = {
  principal: ["arn", "upn", "email", "sid"],
  user_id: ["guid", "sid", "aws_principal_id"],
  user_name: ["upn", "email"],
  account_id: ["integer", "guid"],
  access_key: ["aws_access_key"],
  session_id: ["guid", "hex32"],
  app_id: ["guid"],
  source_ip: ["ip"],
  hostname: ["domain"],
  host_id: ["hex32", "guid"],
  domain: ["domain"],
  file_hash: ["hash", "hex32"],
  process_id: ["integer"],
  process_uid: ["integer", "hex32", "guid"],
  event_time: ["iso_time", "epoch"],
  event_id: ["guid", "integer"],
  request_id: ["guid"],
  resource_id: ["arn"],
  flag: ["bool", "integer"], // a Splunk flag is often 0/1, which reads as integer per value
  count: ["integer"],
  version: ["integer"],
  raw_object: ["json"],
};

// A veto is deliberately conservative: a shape that is plainly the wrong
// kind of thing for the type, checked only once classify() has 3+ values
// and a clear majority (the call site enforces the minimum and the share).
// No shape appears in both a type's SUPPORTS row and its VETOES row
// (tests/shapes.test.js holds the invariant).
export const VETOES = {
  principal: ["ip", "hash", "hex32", "domain", "json"],
  user_id: ["ip", "domain", "json"],
  user_name: ["ip", "hash", "hex32", "json", "arn"],
  source_ip: ["guid", "hash", "hex32", "arn", "upn", "email", "json"],
  hostname: ["ip", "guid", "hash", "hex32", "arn", "upn", "email", "json"],
  host_id: ["ip", "arn", "upn", "email", "domain", "json"],
  domain: ["ip", "guid", "hash", "hex32", "arn", "upn", "email", "json"],
  access_key: ["arn", "guid", "ip", "domain", "json"],
  file_hash: ["ip", "guid", "arn", "upn", "email", "domain", "json"],
  account_id: ["ip", "arn", "hash", "hex32", "domain", "json"],
  event_time: ["json", "arn", "upn", "guid"],
  event_id: ["arn", "upn", "domain", "json"],
  request_id: ["arn", "upn", "domain", "json"],
  session_id: ["arn", "upn", "domain", "json", "ip"],
  app_id: ["ip", "arn", "upn", "domain", "json"],
  resource_id: ["ip", "json"],
  flag: ["json", "arn", "upn", "domain", "guid", "ip"],
  count: ["json", "arn", "upn", "domain", "guid", "ip"],
  version: ["json", "arn", "upn", "domain", "guid", "ip"],
  raw_object: [], // handled specially: any non-json value vetoes raw_object
};

// Types whose values are never a plain number, so an all-numeric column
// (Splunk numeric_count == count; a Sentinel long/double/decimal) can
// never carry them. Everything else, including every type with no
// SUPPORTS row (a pid, a Windows event id, a result code, an enum), is
// left alone: "no shape list" means unknown, never a veto.
const NUMERIC_VETO_TYPES = new Set(["principal", "user_name", "access_key", "source_ip", "hostname", "domain", "file_hash", "user_agent", "command_line", "file_path", "file_name", "event_source", "region", "raw_object"]);

export function shapeSupports(shape, conceptType) {
  if (!shape || !conceptType) return false;
  return (SUPPORTS[conceptType] || []).includes(shape);
}

// The json veto is universal, not a row: a column of nested objects is a
// raw_object and nothing else, whether or not the type has a VETOES row
// (command_line, file_path, user_agent, event_source, process_id...).
export function shapeVeto(shape, conceptType) {
  if (!shape || !conceptType) return false;
  if (conceptType === "raw_object") return shape !== "json";
  if (shape === "json") return true;
  return (VETOES[conceptType] || []).includes(shape);
}

export function numericVeto(conceptType) {
  return Boolean(conceptType) && NUMERIC_VETO_TYPES.has(conceptType);
}

export default { shapeOf, classify, shapeSupports, shapeVeto, numericVeto, detectCve, detectTechnique, detectProcessName, detectUrl, POSITIVE_SHAPES, VETO_ONLY_SHAPES, SUPPORTS, VETOES };
