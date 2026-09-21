// SPL text primitives: the string literal, the list literal, the time
// modifier, the Splunk Cloud command lint. Every module that writes SPL
// (pivot.js, compile-spl.js, ladder.js) quotes and lints through here; the
// searches themselves are pack data rendered by pivot.js.
//
//   quote(value)            "…" with backslashes and quotes escaped
//   quoteList(values)       the inside of an IN (...) term
//   timeModifier(value)     a time modifier as Splunk reads it
//   stripComments(spl)      ```…``` blocks removed
//   TIME_HINT               the forms a time input takes, for an input's hint
//   lint(spl, { commands, macros })   → { ok, violations, warnings }   (warnings is always [] here; the shape is kql.lint's too)
//
// The FDR bundle's search renderer is app/lib/fdr-queries.js (generate,
// macrosFor); callers import it directly rather than through this module.
//
// Plain ES module. No dependencies. No DOM.

export class SplError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'SplError';
    this.code = code;
  }
}

// The forms a time input takes; timeModifier renders each as Splunk reads it.
export const TIME_HINT = "Relative (-24h, -7d@d, now), an epoch, or an ISO stamp (2022-07-27T10:40:00; with Z or an offset it is taken as that instant). Index time (_time), not the sensor's timestamp.";

// Splunk-Cloud-safe command allowlist (ARCHITECTURE §3 invariant 4).
export const ALLOWED_COMMANDS = Object.freeze([
  'search', 'eval', 'stats', 'eventstats', 'where', 'table', 'sort',
  'convert', 'rename', 'fields', 'head', 'lookup',
]);
export const FORBIDDEN_COMMANDS = Object.freeze(['join', 'map', 'transaction']);

const SAFE_TIME_RE = /^[A-Za-z0-9@:+\-._]+$/;

// An ISO 8601 stamp: date, optional time (T or a space), optional fraction,
// optional Z or offset. Splunk's time modifiers do not read this shape.
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?(Z|[+-]\d{2}:?\d{2})?$/;

// A time modifier as Splunk reads it. Relative forms (-24h, now, @d, an
// epoch) pass through. An ISO stamp with no zone is the wall clock the
// analyst typed, so it becomes %m/%d/%Y:%H:%M:%S, which Splunk reads in the
// user's own timezone. One with Z or an offset names an instant, so it
// becomes epoch seconds: the formatted form would silently move it into
// whatever timezone the search runs in. Anything else is quoted as given.
export function timeModifier(value) {
  const s = String(value == null ? '' : value).trim();
  const m = ISO_RE.exec(s);
  if (m) {
    const [, y, mo, d, hh = '00', mm = '00', ss = '00', zone] = m;
    if (zone) {
      const iso = `${y}-${mo}-${d}T${hh}:${mm}:${ss}${zone.length === 5 ? `${zone.slice(0, 3)}:${zone.slice(3)}` : zone}`;
      const epoch = Date.parse(iso);
      if (Number.isFinite(epoch)) return String(Math.floor(epoch / 1000));
    }
    return quote(`${mo}/${d}/${y}:${hh}:${mm}:${ss}`);
  }
  return SAFE_TIME_RE.test(s) ? s : quote(s);
}

// Invariant 5: `"` → `\"`, backslash → `\\`. Backslashes first so quotes are not double-escaped.
export function quote(value) {
  const s = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${s}"`;
}

// A list of values as the inside of an IN (...) term: each quoted as
// above, comma-separated. An empty list is refused: IN () is a syntax
// error, and a caller that has nothing to list has nothing to search.
export function quoteList(values) {
  if (!Array.isArray(values) || !values.length) throw new SplError('bad_list', 'a list needs at least one value');
  return values.map(quote).join(', ');
}

// ---------------------------------------------------------------------------
// lint(): Splunk-Cloud command allowlist (invariant 4). Comment-aware, quote-aware.

export function stripComments(spl) {
  return String(spl).replace(/```[\s\S]*?```/g, ' ');
}

function splitPipeline(text) {
  const segs = [];
  let cur = '';
  let inQ = false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQ) {
      cur += ch;
      if (ch === '\\') { cur += text[i + 1] || ''; i++; continue; }
      if (ch === '"') inQ = false;
      continue;
    }
    if (ch === '"') { inQ = true; cur += ch; continue; }
    if (ch === '[') { depth++; segs.push(cur); cur = ''; continue; }
    if (ch === ']') { depth = Math.max(0, depth - 1); segs.push(cur); cur = ''; continue; }
    if (ch === '|') { segs.push(cur); cur = ''; continue; }
    cur += ch;
  }
  segs.push(cur);
  return segs.map((s) => s.trim()).filter(Boolean);
}

// opts.commands / opts.macros extend the allowlists for a pack's own SPL
// (a macro call is fine only when the pack declares the macro);
// FORBIDDEN_COMMANDS can never be extended past.
export function lint(spl, opts = {}) {
  const violations = [];
  const allowed = new Set([...ALLOWED_COMMANDS, ...(opts.commands || []).map((c) => String(c).toLowerCase())]);
  const macros = new Set(opts.macros || []);
  const text = stripComments(spl);
  const segs = splitPipeline(text);
  if (segs.length === 0) return { ok: false, violations: ['empty search'], warnings: [] };
  segs.forEach((seg, i) => {
    const m = /^`([A-Za-z_][A-Za-z0-9_]*)(\(|`)/.exec(seg);
    if (m) {
      if (!macros.has(m[1])) violations.push(`unknown macro: ${m[1]}`);
      return;
    }
    const word = (/^([A-Za-z_][A-Za-z0-9_]*)/.exec(seg) || [])[1] || '';
    const lower = word.toLowerCase();
    if (FORBIDDEN_COMMANDS.includes(lower)) { violations.push(`forbidden command: ${lower}`); return; }
    if (allowed.has(lower)) {
      // `search` is fine anywhere; other commands are fine at any segment.
      return;
    }
    if (i === 0 && /^(index|sourcetype|earliest|latest)=/.test(seg)) return; // implicit search
    violations.push(`command not in allowlist: ${word || seg.slice(0, 20)}`);
  });
  return { ok: violations.length === 0, violations, warnings: [] };
}
