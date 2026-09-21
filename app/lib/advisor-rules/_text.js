// Text helpers every advisor rule scans with. Offsets always refer to the
// original text: mask() keeps the length, so a match on the masked copy
// slices the original at the same span.
//
//   mask(text, platform, fill?) quoted contents and comments blanked (with fill, a space), quotes kept, same length
//   stages(text, platform)      top-level pipe segments [{ start, end, text, head }]
//                               head: the first word lowercased; "" for a search block
//   subsearches(text)           SPL: top-level [ ... ] spans [{ start, end }]
//   literalAt(text, i)          the literal starting at i: { value, quoted, start, end } | null
//   fieldTests(block, platform) field comparisons in one stage: [{ field, op, value, quoted, start, end }]
//   trim(span, text)            the span with surrounding whitespace dropped
//
// Plain ES module. No DOM.

const KQL_COMMENT = "//";

export function mask(text, platform = "spl", fill = " ") {
  const s = String(text || "");
  const out = s.split("");
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch === '"' || (platform === "kql" && ch === "'")) {
      const q = ch;
      i++;
      while (i < s.length && s[i] !== q) {
        if (s[i] === "\\" && platform !== "kql") { out[i] = fill; i++; }
        if (i < s.length) { if (s[i] !== "\n") out[i] = fill; i++; }
      }
      i++;
      continue;
    }
    if (platform === "spl" && s.startsWith("```", i)) {
      const end = s.indexOf("```", i + 3);
      const stop = end < 0 ? s.length : end + 3;
      for (let k = i; k < stop; k++) if (s[k] !== "\n") out[k] = " ";
      i = stop;
      continue;
    }
    if (platform === "kql" && s.startsWith(KQL_COMMENT, i)) {
      const nl = s.indexOf("\n", i);
      const stop = nl < 0 ? s.length : nl;
      for (let k = i; k < stop; k++) out[k] = " ";
      i = stop;
      continue;
    }
    i++;
  }
  return out.join("");
}

export function trim(span, text) {
  let [a, b] = span;
  while (a < b && /\s/.test(text[a])) a++;
  while (b > a && /\s/.test(text[b - 1])) b--;
  return [a, b];
}

export function stages(text, platform = "spl") {
  const s = String(text || "");
  const m = mask(s, platform);
  const out = [];
  let start = 0;
  let depth = 0;
  for (let i = 0; i < m.length; i++) {
    const ch = m[i];
    if (ch === "[" || ch === "(") depth++;
    else if (ch === "]" || ch === ")") depth = Math.max(0, depth - 1);
    else if (ch === "|" && depth === 0) {
      push(start, i);
      start = i + 1;
    }
  }
  push(start, m.length);
  return out;
  function push(a, b) {
    const [x, y] = trim([a, b], s);
    if (x >= y) return;
    const seg = s.slice(x, y);
    const word = (/^([A-Za-z_][A-Za-z0-9_-]*)/.exec(m.slice(x, y)) || [])[1] || "";
    // The first SPL segment is the search block unless a generating
    // command opens it; a written-out leading `search` is still the block.
    const head = out.length === 0 && platform === "spl" && !/^(tstats|inputlookup|makeresults|rest|from|datamodel|metadata|dbinspect|history|loadjob|mstats|pivot|savedsearch)$/i.test(word) ? "" : word.toLowerCase();
    out.push({ start: x, end: y, text: seg, head });
  }
}

export function subsearches(text) {
  const s = String(text || "");
  const m = mask(s, "spl");
  const out = [];
  let depth = 0;
  let open = -1;
  for (let i = 0; i < m.length; i++) {
    if (m[i] === "[") {
      if (depth === 0) open = i;
      depth++;
    } else if (m[i] === "]" && depth > 0) {
      depth--;
      if (depth === 0) out.push({ start: open, end: i + 1 });
    }
  }
  return out;
}

export function literalAt(text, i) {
  const s = String(text || "");
  let k = i;
  while (k < s.length && /\s/.test(s[k])) k++;
  if (k >= s.length) return null;
  if (s[k] === '"' || s[k] === "'") {
    const q = s[k];
    let e = k + 1;
    let v = "";
    while (e < s.length && s[e] !== q) {
      if (s[e] === "\\" && e + 1 < s.length) { v += s[e + 1]; e += 2; continue; }
      v += s[e];
      e++;
    }
    return { value: v, quoted: true, start: k, end: Math.min(e + 1, s.length) };
  }
  if (s[k] === "@" && s[k + 1] === '"') {
    const e = s.indexOf('"', k + 2);
    return { value: s.slice(k + 2, e < 0 ? s.length : e), quoted: true, start: k, end: e < 0 ? s.length : e + 1 };
  }
  const bare = /^[^\s()\[\]|,]+/.exec(s.slice(k));
  if (!bare) return null;
  return { value: bare[0], quoted: false, start: k, end: k + bare[0].length };
}

const SPL_TEST = /(?<![\w.:$'"])([A-Za-z_][A-Za-z0-9_.:{}]*)\s*(!=|==|=|>=|<=|>|<)\s*/g;
const KQL_TEST = /(?<![\w.'"\]])([A-Za-z_][A-Za-z0-9_.]*)\s+(==|!=|=~|!~|has_cs|!has_cs|has|!has|contains_cs|!contains_cs|contains|!contains|startswith_cs|!startswith_cs|startswith|!startswith|endswith_cs|!endswith_cs|endswith|!endswith|in~|!in~|in|!in|has_any|has_all|matches regex)\s*/g;

export function fieldTests(block, platform = "spl") {
  const text = block.text;
  const m = mask(text, platform);
  const re = platform === "kql" ? KQL_TEST : SPL_TEST;
  const out = [];
  re.lastIndex = 0;
  for (const hit of m.matchAll(re)) {
    const field = hit[1];
    if (platform === "spl" && /^(earliest|latest|_index_earliest|_index_latest)$/.test(field)) continue;
    const lit = literalAt(text, hit.index + hit[0].length);
    if (!lit) continue;
    out.push({ field, op: hit[2], value: lit.value, quoted: lit.quoted, start: block.start + hit.index, end: block.start + lit.end });
  }
  return out;
}

export default { mask, stages, subsearches, literalAt, fieldTests, trim };
