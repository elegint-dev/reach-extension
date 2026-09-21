// Segments: a value cut along its own shape, so a pattern can be built by
// keeping some pieces and opening others. A Windows path becomes drive,
// directories, basename and extension; an ARN becomes partition, service,
// region, account and the resource parts; an email becomes local part,
// plus-tag and domain labels. ladder.js turns a segment list with a state
// per segment (keep, any, like) into the cheapest SPL and KQL construct.
//
//   segment(value, shape?) -> {
//     shape,       path | cmdline | url | arn | email | upn | ip | domain | hostname | guid | json | text
//     detail,      path: windows | posix | unc | registry; ip: v4 | v6; guid: braced | null; else null
//     segments: [{ text, kind, sep, quoted? }],
//     tail,        text after the last segment (a closing bracket, brace or quote, a trailing separator)
//     truncated,   the value is at or past the 200-character cut recipe.js applies to a stored top value
//   }
//   SHAPES                          the shapes segment() can return
//   KINDS                           every segment kind, with the character class "like" means for it
//
// Round trip: segments.map((s) => s.sep + s.text).join("") + tail is the
// trimmed value, always. sep is the separator text that precedes the
// segment (empty for the first piece of most shapes; "arn:" for an ARN's
// partition; "://" for a URL's host). A closing quote or bracket has no
// segment of its own: it lands in the next segment's sep or in tail.
//
// Shape precedence: an explicit shape argument wins; then shapes.js
// shapeOf(), which knows the SIEM value shapes (arn, guid, ip, url, upn,
// email, domain, json, ...) but has no path or command-line detector;
// then a CIDR check (shapeOf refuses 10.0.0.0/8); then the local path and
// command-line detectors; then the punctuation fallback (shape text).
// A value with spaces whose first token is a path or an executable is a
// command line when something follows the executable (a flag, a quoted
// argument, more tokens after a module extension); "C:\Program Files\App\
// app.exe" alone is a path. The caller passes shape "cmdline" or "path"
// when the field already says which, and that always wins.
//
// Kinds by shape (the like-state character class is KINDS[kind]):
//   path      drive | server | share | hive | dir | basename | ext
//   cmdline   exe (or the exe's path kinds) | flag | arg
//   url       scheme | userinfo | host | port | dir | basename | ext | query | fragment
//   arn       partition | service | region | account | resource_type | resource
//   email/upn local | tag | label
//   ip        octet | group | zone | cidr
//   domain    label;  hostname: host then label
//   guid      hex
//   json      json (one segment, never split)
//   text      word | digits (alphanumeric runs; every punctuation run is a sep)
//
// Reuses shapes.shapeOf for the shape vocabulary and search.js pathReadings
// (registry detection), isIPv4, isIPv6 and isDomain. No DOM, no store,
// no network.

import { shapeOf } from "./shapes.js";
import { pathReadings, isIPv4, isIPv6, isDomain } from "./search.js";

const TRUNCATE_AT = 200; // recipe.js TOP_VALUE_MAX, as shapes.js keeps it

export const SHAPES = Object.freeze(["path", "cmdline", "url", "arn", "email", "upn", "ip", "domain", "hostname", "guid", "json", "text"]);

// The character class each kind stands for when a segment's state is
// "like": the same kind of thing in that position, nothing wider. A path
// segment never crosses a separator; an octet is up to three digits; a
// hex group keeps its length (ladder.js substitutes {n}).
export const KINDS = Object.freeze({
  drive: "[A-Za-z]:",
  server: "[^\\\\/]+",
  share: "[^\\\\/]+",
  hive: "[^\\\\/]+",
  dir: "[^\\\\/]+",
  basename: "[^\\\\/]+",
  ext: "[^\\\\/.]+",
  exe: "\\S+",
  flag: "[-/][^\\s]*",
  arg: "\\S+",
  scheme: "[a-zA-Z][a-zA-Z0-9+.-]*",
  userinfo: "[^/@]+",
  host: "[^/:?#]+",
  port: "\\d+",
  query: "[^&#]*",
  fragment: "[^\\s]*",
  partition: "[a-z0-9-]+",
  service: "[a-z0-9-]*",
  region: "[a-z0-9-]*",
  account: "\\d{0,12}",
  resource_type: "[^:/]+",
  resource: "[^:/]+",
  local: "[^@+]+",
  tag: "[^@]+",
  label: "[^.@]+",
  octet: "\\d{1,3}",
  group: "[0-9a-fA-F]{0,4}",
  zone: "[^\\s/]+",
  cidr: "\\d{1,3}",
  hex: "[0-9a-fA-F]+",
  json: "[\\s\\S]*",
  word: "\\w+",
  digits: "\\d+",
});

function seg(text, kind, sep, extra) {
  const s = { text, kind, sep };
  if (extra) Object.assign(s, extra);
  return s;
}

function result(shape, detail, segments, tail, value) {
  return { shape, detail, segments, tail: tail || "", truncated: value.length >= TRUNCATE_AT };
}

// ---------------------------------------------------------------------------
// Path

const MODULE_EXT_RE = /\.(exe|com|dll|sys|scr|cpl|ocx|drv|efi|bat|cmd|ps1|vbs|js|jse|wsf|msi|hta|sh|py|pl|rb|bin|so|dylib|ko)$/i;
const DRIVE_RE = /^[A-Za-z]:(?=[\\/]|$)/;
// A flag: -x, --long, /c; a path such as /tmp/x has a second separator and is an argument.
const FLAG_RE = /^(--?|\/)[A-Za-z0-9]/;

function isRegistry(v) {
  const r = pathReadings(v);
  return r.length === 1 && r[0].kind === "registry";
}

function looksLikePath(v) {
  return !/\s/.test(v) && hasSeparator(v);
}

function hasSeparator(v) {
  return v.includes("/") || v.includes("\\");
}

// Cut a path on both separators. Every piece keeps the separator that
// preceded it; the last non-empty piece is the basename, split from its
// extension; a trailing separator goes to tail.
function segmentPath(v) {
  const out = [];
  let detail = "posix";
  let rest = v;
  let firstSep = "";
  if (rest.startsWith("\\\\")) {
    detail = "unc";
    const m = /^\\\\([^\\/]*)(?:[\\/]([^\\/]*))?/.exec(rest);
    out.push(seg(m[1], "server", "\\\\"));
    if (m[2] !== undefined) out.push(seg(m[2], "share", rest[2 + m[1].length]));
    rest = rest.slice(m[0].length);
  } else if (DRIVE_RE.test(rest)) {
    detail = "windows";
    out.push(seg(rest.slice(0, 2), "drive", ""));
    rest = rest.slice(2);
  } else if (isRegistry(rest)) {
    detail = "registry";
    const cut = rest.slice(1).search(/[\\/]/); // \REGISTRY\... opens with its own separator
    const hive = cut < 0 ? rest : rest.slice(0, cut + 1);
    out.push(seg(hive, "hive", ""));
    rest = rest.slice(hive.length);
  } else if (rest.includes("\\") && !rest.includes("/")) {
    detail = "windows";
  }
  // The separator after a drive, share or hive, or the leading one of a
  // rooted path, belongs to the first piece after it.
  if (rest[0] === "/" || rest[0] === "\\") {
    firstSep = rest[0];
    rest = rest.slice(1);
    if (!out.length && rest.includes("\\") && !rest.includes("/")) detail = "windows";
  }
  let tail = "";
  const pieces = [];
  let cur = "";
  let sep = firstSep;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === "/" || ch === "\\") {
      pieces.push({ text: cur, sep });
      cur = "";
      sep = ch;
    } else cur += ch;
  }
  if (cur !== "" || (pieces.length === 0 && !out.length)) pieces.push({ text: cur, sep });
  else tail = sep;
  pieces.forEach((p, i) => {
    const last = i === pieces.length - 1;
    if (!last) {
      out.push(seg(p.text, "dir", p.sep));
      return;
    }
    const dot = p.text.lastIndexOf(".");
    if (dot > 0 && dot < p.text.length - 1) {
      out.push(seg(p.text.slice(0, dot), "basename", p.sep));
      out.push(seg(p.text.slice(dot + 1), "ext", "."));
    } else out.push(seg(p.text, "basename", p.sep));
  });
  return result("path", detail, out, tail, v);
}

// ---------------------------------------------------------------------------
// Command line

// Tokens of a command line: { text, quoted, lead } where lead is the
// whitespace before the token and text excludes the quotes.
function tokenize(v) {
  const toks = [];
  let i = 0;
  while (i < v.length) {
    let lead = "";
    while (i < v.length && /\s/.test(v[i])) lead += v[i++];
    if (i >= v.length) {
      if (lead) toks.push({ text: "", quoted: false, lead, trailing: true });
      break;
    }
    if (v[i] === '"') {
      const close = v.indexOf('"', i + 1);
      const end = close < 0 ? v.length : close;
      toks.push({ text: v.slice(i + 1, end), quoted: true, lead, unclosed: close < 0 });
      i = close < 0 ? v.length : close + 1;
    } else {
      let j = i;
      while (j < v.length && !/\s/.test(v[j])) j++;
      toks.push({ text: v.slice(i, j), quoted: false, lead });
      i = j;
    }
  }
  return toks;
}

// The number of leading tokens that make up the executable, or 0 when the
// value does not read as a command line. A quoted first token is the exe.
// A rooted POSIX path is the exe on its own when the next token is a flag,
// a quoted argument, another rooted path or a plain word (POSIX
// executables have no extension; /home/john doe/x continues the path).
// Otherwise the exe ends at the first token with a module extension, or
// is the first token alone when it holds a separator or is a bare word
// followed by a flag or a quoted argument.
function exeSpan(toks) {
  if (!toks.length) return 0;
  if (toks[0].quoted) return 1;
  const words = toks.filter((t) => !t.trailing);
  const first = words[0].text;
  const flagLike = (t) => FLAG_RE.test(t.text) || t.quoted;
  if (first[0] === "/" && words.length > 1) {
    const next = words[1];
    if (flagLike(next) || next.text[0] === "/" || !hasSeparator(next.text)) return 1;
  }
  for (let i = 0; i < words.length; i++) {
    if (MODULE_EXT_RE.test(words[i].text)) return i + 1;
  }
  const hasSep = hasSeparator(first);
  if (hasSep && words.slice(1).some(flagLike)) return 1;
  if (!hasSep && /^[A-Za-z][A-Za-z0-9_.-]*$/.test(first) && words.length > 1 && flagLike(words[1])) return 1;
  return 0;
}

function looksLikeCmdline(v) {
  if (!/\s/.test(v)) return false;
  const toks = tokenize(v);
  const span = exeSpan(toks);
  if (!span) return false;
  const words = toks.filter((t) => !t.trailing);
  // A path with spaces and nothing after its module extension is a path.
  return toks[0].quoted || span < words.length;
}

function segmentCmdline(v) {
  const toks = tokenize(v);
  const out = [];
  let tail = "";
  const span = Math.max(1, exeSpan(toks) || 1);
  let pending = ""; // a closing quote waiting to join the next sep
  const push = (s) => {
    s.sep = pending + s.sep;
    pending = "";
    out.push(s);
  };
  const words = toks.filter((t) => !t.trailing);
  const exeToks = words.slice(0, span);
  const exeText = exeToks.map((t, i) => (i ? t.lead : "") + t.text).join("");
  const exeSep = exeToks[0].lead + (exeToks[0].quoted ? '"' : "");
  if (hasSeparator(exeText)) {
    const p = segmentPath(exeText);
    p.segments.forEach((s, i) => push(i === 0 ? seg(s.text, s.kind, exeSep + s.sep, exeToks[0].quoted ? { quoted: true } : null) : s));
    if (p.tail) pending = p.tail;
  } else {
    push(seg(exeText, "exe", exeSep, exeToks[0].quoted ? { quoted: true } : null));
  }
  if (exeToks[0].quoted && !exeToks[0].unclosed) pending += '"';
  for (const t of words.slice(span)) {
    const kind = !t.quoted && FLAG_RE.test(t.text) && !t.text.includes("\\") && !(t.text[0] === "/" && t.text.includes("/", 1)) ? "flag" : "arg";
    push(seg(t.text, kind, t.lead + (t.quoted ? '"' : ""), t.quoted ? { quoted: true } : null));
    if (t.quoted && !t.unclosed) pending += '"';
  }
  const trailing = toks.find((t) => t.trailing);
  tail = pending + (trailing ? trailing.lead : "");
  return result("cmdline", null, out, tail, v);
}

// ---------------------------------------------------------------------------
// URL

const URL_PARTS_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/;

function segmentUrl(v) {
  const m = URL_PARTS_RE.exec(v);
  if (!m) return null;
  const [, scheme, authority, path, query, fragment] = m;
  const out = [seg(scheme, "scheme", "")];
  let auth = authority;
  let sep = "://";
  const at = auth.lastIndexOf("@");
  if (at >= 0) {
    out.push(seg(auth.slice(0, at), "userinfo", sep));
    auth = auth.slice(at + 1);
    sep = "@";
  }
  let host = auth;
  let port = null;
  const pm = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(auth);
  if (pm) {
    host = pm[1];
    if (pm[2] !== undefined) port = pm[2];
  }
  out.push(seg(host, "host", sep));
  if (port !== null) out.push(seg(port, "port", ":"));
  let tail = "";
  if (path) {
    const pieces = path.split("/").slice(1);
    pieces.forEach((p, i) => {
      const last = i === pieces.length - 1;
      if (!last) {
        out.push(seg(p, "dir", "/"));
        return;
      }
      if (p === "") {
        tail = "/";
        return;
      }
      const dot = p.lastIndexOf(".");
      if (dot > 0 && dot < p.length - 1) {
        out.push(seg(p.slice(0, dot), "basename", "/"));
        out.push(seg(p.slice(dot + 1), "ext", "."));
      } else out.push(seg(p, "basename", "/"));
    });
  }
  if (query !== undefined) {
    const pairs = query.slice(1).split("&");
    pairs.forEach((p, i) => out.push(seg(p, "query", i ? "&" : tail + "?")));
    if (pairs.length) tail = "";
  }
  if (fragment !== undefined) {
    out.push(seg(fragment.slice(1), "fragment", tail + "#"));
    tail = "";
  }
  return result("url", null, out, tail, v);
}

// ---------------------------------------------------------------------------
// ARN

const ARN_PARTS_RE = /^arn:([^:]*):([^:]*):([^:]*):([^:]*):(.*)$/;

function segmentArn(v) {
  const m = ARN_PARTS_RE.exec(v);
  if (!m) return null;
  const out = [seg(m[1], "partition", "arn:"), seg(m[2], "service", ":"), seg(m[3], "region", ":"), seg(m[4], "account", ":")];
  const resource = m[5];
  const parts = [];
  let cur = "";
  let sep = ":";
  for (const ch of resource) {
    if (ch === "/" || ch === ":") {
      parts.push({ text: cur, sep });
      cur = "";
      sep = ch;
    } else cur += ch;
  }
  parts.push({ text: cur, sep });
  parts.forEach((p, i) => out.push(seg(p.text, i === 0 && parts.length > 1 ? "resource_type" : "resource", p.sep)));
  return result("arn", null, out, "", v);
}

// ---------------------------------------------------------------------------
// Email and UPN

function segmentEmail(v, shape) {
  const at = v.lastIndexOf("@");
  if (at < 0) return null;
  const local = v.slice(0, at);
  const out = [];
  const plus = local.indexOf("+");
  if (plus > 0) {
    out.push(seg(local.slice(0, plus), "local", ""));
    out.push(seg(local.slice(plus + 1), "tag", "+"));
  } else out.push(seg(local, "local", ""));
  v.slice(at + 1).split(".").forEach((l, i) => out.push(seg(l, "label", i ? "." : "@")));
  return result(shape, null, out, "", v);
}

// ---------------------------------------------------------------------------
// IP, with CIDR

function splitCidr(v) {
  const slash = v.lastIndexOf("/");
  if (slash < 0) return null;
  const addr = v.slice(0, slash);
  const bits = v.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bits)) return null;
  if (isIPv4(addr) && Number(bits) <= 32) return { addr, bits, detail: "v4" };
  if (isIPv6(addr) && Number(bits) <= 128) return { addr, bits, detail: "v6" };
  return null;
}

function segmentIp(v, detail, cidr) {
  let addr = cidr ? cidr.addr : v;
  let lead = "";
  let tail = "";
  if (addr[0] === "[" && addr[addr.length - 1] === "]") {
    addr = addr.slice(1, -1);
    lead = "[";
    tail = "]";
  }
  const out = [];
  if (detail === "v4") {
    addr.split(".").forEach((o, i) => out.push(seg(o, "octet", i ? "." : lead)));
  } else {
    let zone = null;
    const pct = addr.indexOf("%");
    if (pct >= 0) {
      zone = addr.slice(pct + 1);
      addr = addr.slice(0, pct);
    }
    addr.split(":").forEach((g, i) => out.push(seg(g, "group", i ? ":" : lead)));
    if (zone !== null) out.push(seg(zone, "zone", "%"));
  }
  if (cidr) {
    out.push(seg(cidr.bits, "cidr", tail + "/"));
    tail = "";
  }
  return result("ip", detail, out, tail, v);
}

// ---------------------------------------------------------------------------
// Domain, hostname, GUID, JSON, fallback text

function segmentLabels(v, shape) {
  let tail = "";
  let s = v;
  if (s.endsWith(".")) {
    tail = ".";
    s = s.slice(0, -1);
  }
  const out = s.split(".").map((l, i) => seg(l, shape === "hostname" && i === 0 ? "host" : "label", i ? "." : ""));
  return result(shape, null, out, tail, v);
}

function segmentGuid(v) {
  const braced = v[0] === "{" && v[v.length - 1] === "}";
  const bare = braced ? v.slice(1, -1) : v;
  const out = bare.split("-").map((h, i) => seg(h, "hex", i ? "-" : braced ? "{" : ""));
  return result("guid", braced ? "braced" : null, out, braced ? "}" : "", v);
}

function segmentText(v) {
  const out = [];
  const re = /[A-Za-z0-9_]+/g;
  let last = 0;
  let m;
  while ((m = re.exec(v))) {
    out.push(seg(m[0], /^\d+$/.test(m[0]) ? "digits" : "word", v.slice(last, m.index)));
    last = m.index + m[0].length;
  }
  if (!out.length) return result("text", null, [seg(v, "word", "")], "", v);
  return result("text", null, out, v.slice(last), v);
}

// ---------------------------------------------------------------------------

function byShape(v, shape, detail) {
  switch (shape) {
    case "path": return segmentPath(v);
    case "cmdline": return segmentCmdline(v);
    case "url": return segmentUrl(v);
    case "arn": return segmentArn(v);
    case "email":
    case "upn": return segmentEmail(v, shape);
    case "ip": {
      const cidr = splitCidr(v);
      if (cidr) return segmentIp(v, cidr.detail, cidr);
      const d = detail || (isIPv4(v) ? "v4" : "v6");
      return segmentIp(v, d, null);
    }
    case "domain":
    case "hostname": return segmentLabels(v, shape);
    case "guid": return segmentGuid(v);
    case "json": return result("json", null, [seg(v, "json", "")], "", v);
    case "text": return segmentText(v);
    default: return null;
  }
}

export function segment(value, shape) {
  const v = String(value == null ? "" : value).trim();
  if (!v) return result("text", null, [], "", v);
  if (shape) {
    const got = byShape(v, shape, null);
    if (got) return got;
  }
  const known = shapeOf(v);
  if (known) {
    const got = byShape(v, known.shape, known.detail);
    if (got) return got;
  }
  const cidr = splitCidr(v);
  if (cidr) return segmentIp(v, cidr.detail, cidr);
  if (looksLikeCmdline(v)) return segmentCmdline(v);
  const first = v.split(/\s/)[0];
  if (looksLikePath(v) || (looksLikePath(first) && !v.includes('"'))) return segmentPath(v);
  if (!v.includes(" ") && isDomain(v) && !known) return segmentLabels(v, "domain");
  return segmentText(v);
}

export default { segment, SHAPES, KINDS };
