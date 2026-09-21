// The same field tested three or more times in one OR chain reads as one
// list: field IN (a, b, c), the ladder's in construct, quoted by
// spl.quoteList.

import { stages, mask, fieldTests } from "./_text.js";

export const rule = {
  id: "spl/or-to-in",
  platform: "spl",
  severity: "note",
  title: "OR chain",
  why: "the same field tested over and over in an OR chain reads as one list: field IN (...) says it once",
  find(text) {
    const out = [];
    for (const st of stages(text, "spl")) {
      if (st.head !== "" && st.head !== "search") continue;
      const m = mask(st.text, "spl", "x"); // a quoted value stays one token
      // Each run of terms joined by OR, bare or inside one pair of parentheses.
      for (const hit of m.matchAll(/(?:[^\s()|]+(?:\s+OR\s+)){2,}[^\s()|]+/g)) {
        const sub = { start: st.start + hit.index, end: st.start + hit.index + hit[0].length, text: text.slice(st.start + hit.index, st.start + hit.index + hit[0].length) };
        const tests = fieldTests(sub, "spl").filter((t) => t.op === "=");
        if (tests.length < 3) continue;
        const byField = new Map();
        for (const t of tests) {
          if (!byField.has(t.field)) byField.set(t.field, []);
          byField.get(t.field).push(t);
        }
        for (const [field, list] of byField) {
          if (list.length < 3 || list.length !== tests.length) continue;
          out.push({ start: sub.start, end: sub.end, fix: { text: `${field} IN (${list.map((t) => (t.quoted ? `"${t.value}"` : t.value)).join(", ")})`, construct: "in", label: "one IN list" } });
        }
      }
    }
    return out;
  },
  cases: {
    hit: ["index=main (user=a OR user=b OR user=c)", 'index=main action="login" OR action="logout" OR action="fail"'],
    miss: ["index=main user IN (a, b, c)", "index=main user=a OR user=b", "index=main user=a OR host=b OR action=c", "index=main | where x=1 OR x=2 OR x=3"],
  },
};

export default rule;
