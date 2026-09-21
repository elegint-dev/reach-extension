// =~ compares case-insensitively, which the term index cannot answer; ==
// on the exact case is indexed, and has answers a whole term whatever
// its case.

import { stages, fieldTests } from "./_text.js";

export const rule = {
  id: "kql/ci-equals",
  platform: "kql",
  severity: "note",
  title: "=~ is not indexed",
  why: "=~ folds case on every value, so the index cannot answer it; == on the exact case is indexed, and has answers a whole term case-insensitively from the index",
  find(text) {
    const out = [];
    for (const st of stages(text, "kql")) {
      if (st.head !== "where") continue;
      for (const t of fieldTests(st, "kql")) {
        if (t.op !== "=~" && t.op !== "!~") continue;
        const bang = t.op === "!~" ? "!" : "";
        out.push({ start: t.start, end: t.end, fix: { text: /^[A-Za-z0-9_]{3,}$/.test(t.value) ? `${t.field} ${bang}has "${t.value}"` : `${t.field} ${bang}== "${t.value}"`, construct: "literal", label: "== on the exact case, or has for a whole term" } });
      }
    }
    return out;
  },
  cases: {
    hit: ['SigninLogs | where UserPrincipalName =~ "alice@example.com"', 'SecurityEvent | where Account !~ "SYSTEM"'],
    miss: ['SigninLogs | where UserPrincipalName == "alice@example.com"', 'SecurityEvent | where Account has "system"', 'SecurityEvent | where Account matches regex "(?i)system"'],
  },
};

export default rule;
