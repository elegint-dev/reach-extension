// Resolves an observed field-name string to a real key in fields.json.
//
// The name a caller has in hand is not always a bundle key verbatim:
// Splunk's JSON pretty-printer tags leaves with the full dotted path
// (e.g. "msg.process.TargetProcessId"), a right-click selection can carry
// stray punctuation, and casing conventions mix within the bundle itself
// (raw FDR CamelCase alongside CIM snake_case: "TargetProcessId" and
// "process_id" are both real, distinct keys). A naive exact-match lookup
// on the raw path misses most nested JSON fields even when they are
// genuinely in the catalogue. That miss reads as "Reach doesn't know
// this field" when it is really a parsing bug. resolve() tries a fixed
// chain of interpretations against the real key list and returns the
// first that exists, so a genuine catalogue miss and a resolution
// failure never look alike.
//
// Plain ES module. No DOM, no bundle singleton: callers supply `keys`
// (e.g. fields.searchIndex().fields).
//
//   resolve(rawName, keys) → { name, basis } | null
//     keys  → iterable of real field names (array or Set)
//     basis → which step matched, for logging/tests: 'exact' | 'last_segment' |
//             'case_insensitive' | 'last_segment_case_insensitive' |
//             'convention' | 'last_segment_convention'

function trim(name) {
  return String(name == null ? "" : name).trim();
}

function lastSegment(name) {
  const i = name.lastIndexOf(".");
  return i < 0 ? name : name.slice(i + 1);
}

// CamelCase -> snake_case, snake_case -> CamelCase. Tried both ways since
// the bundle mixes raw FDR (CamelCase) and CIM-layer (snake_case) keys.
function toSnake(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function toCamel(name) {
  return name.replace(/(^|_)([a-z])/g, (_, __, c) => c.toUpperCase());
}

function index(keys) {
  const exact = new Set();
  const byLower = new Map(); // first key wins on a case-insensitive collision
  for (const k of keys) {
    exact.add(k);
    const lower = k.toLowerCase();
    if (!byLower.has(lower)) byLower.set(lower, k);
  }
  return { exact, byLower };
}

export function resolve(rawName, keys) {
  const name = trim(rawName);
  if (!name || !keys) return null;

  const { exact, byLower } = index(keys);
  const has = (n) => exact.has(n);
  const findCi = (n) => byLower.get(n.toLowerCase()) || null;

  if (has(name)) return { name, basis: "exact" };

  const seg = lastSegment(name);
  if (seg !== name && has(seg)) return { name: seg, basis: "last_segment" };

  const ci = findCi(name);
  if (ci) return { name: ci, basis: "case_insensitive" };

  if (seg !== name) {
    const segCi = findCi(seg);
    if (segCi) return { name: segCi, basis: "last_segment_case_insensitive" };
  }

  const snake = toSnake(name);
  if (snake !== name.toLowerCase() && has(snake)) return { name: snake, basis: "convention" };
  const camel = toCamel(name);
  if (camel !== name && has(camel)) return { name: camel, basis: "convention" };

  if (seg !== name) {
    const segSnake = toSnake(seg);
    if (has(segSnake)) return { name: segSnake, basis: "last_segment_convention" };
    const segCamel = toCamel(seg);
    if (has(segCamel)) return { name: segCamel, basis: "last_segment_convention" };
  }

  return null;
}

export default { resolve };
