// contains reads every value; has looks the term up in the index. When
// the literal is one whole term (letters, digits, underscore; three or
// more characters), has finds the same rows.

import { stages, fieldTests } from "./_text.js";

const TERM = /^[A-Za-z0-9_]{3,}$/;

export const rule = {
  id: "kql/contains-to-has",
  platform: "kql",
  severity: "caution",
  title: "contains where has works",
  why: "contains scans every value of the column; has answers a whole term from the term index. The literal here is one term, so has finds the same rows",
  find(text) {
    const out = [];
    for (const st of stages(text, "kql")) {
      if (st.head !== "where" && st.head !== "search") continue;
      for (const t of fieldTests(st, "kql")) {
        if (!/^!?contains(_cs)?$/.test(t.op) || !TERM.test(t.value)) continue;
        const op = t.op.replace("contains", "has");
        out.push({ start: t.start, end: t.end, fix: { text: `${t.field} ${op} "${t.value}"`, construct: "has", label: "the term index" } });
      }
    }
    return out;
  },
  cases: {
    hit: ['SecurityEvent | where CommandLine contains "mimikatz"', 'SigninLogs | where UserPrincipalName !contains "svc_backup"', 'DeviceProcessEvents | where FileName contains_cs "Cmd"'],
    miss: ['SecurityEvent | where CommandLine contains "-enc "', 'SecurityEvent | where CommandLine has "mimikatz"', 'SecurityEvent | where CommandLine contains "a/b"', 'SecurityEvent | where CommandLine contains "ab"', 'SecurityEvent | extend x = "contains" | where x == "y"'],
  },
};

export default rule;
