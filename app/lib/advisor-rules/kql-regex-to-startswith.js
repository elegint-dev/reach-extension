// matches regex runs the engine on every value. A pattern that is only an
// anchored literal is startswith or endswith; one that is only a literal
// is has (a whole term) or contains.

import { stages, fieldTests } from "./_text.js";

const META = /[.*+?^${}()|[\]\\]/;

function lit(v) {
  return v.includes("\\") ? `@"${v}"` : `"${v}"`;
}

// The pattern as a plain string when it has no metacharacter beyond
// escaped ones (\. and \\ are literals); null when it is a real regex.
function plain(pattern) {
  const escaped = /\\([.*+?^${}()|[\]\\/-])/g;
  if (META.test(pattern.replace(escaped, ""))) return null;
  return pattern.replace(escaped, "$1");
}

export const rule = {
  id: "kql/regex-to-startswith",
  platform: "kql",
  severity: "note",
  title: "regex for a literal",
  why: "matches regex runs the engine on every value; an anchored literal is startswith or endswith, and a bare literal is has or contains, which the engine can index or scan far cheaper",
  find(text) {
    const out = [];
    for (const st of stages(text, "kql")) {
      if (st.head !== "where") continue;
      for (const t of fieldTests(st, "kql")) {
        if (t.op !== "matches regex") continue;
        const p = t.value;
        let fix = null;
        if (p.startsWith("^") && !p.endsWith("$") && plain(p.slice(1)) !== null) fix = { text: `${t.field} startswith ${lit(plain(p.slice(1)))}`, construct: "like", label: "startswith" };
        else if (p.endsWith("$") && !p.startsWith("^") && plain(p.slice(0, -1)) !== null) fix = { text: `${t.field} endswith ${lit(plain(p.slice(0, -1)))}`, construct: "like", label: "endswith" };
        else if (p.startsWith("^") && p.endsWith("$") && plain(p.slice(1, -1)) !== null) fix = { text: `${t.field} == ${lit(plain(p.slice(1, -1)))}`, construct: "literal", label: "==" };
        else if (plain(p) !== null) fix = { text: /^[A-Za-z0-9_]{3,}$/.test(plain(p)) ? `${t.field} has ${lit(plain(p))}` : `${t.field} contains ${lit(plain(p))}`, construct: "has", label: "has or contains" };
        if (fix) out.push({ start: t.start, end: t.end, fix });
      }
    }
    return out;
  },
  cases: {
    hit: ['DeviceProcessEvents | where FolderPath matches regex @"^C:\\\\Windows"', 'DeviceProcessEvents | where FileName matches regex "\\\\.exe$"', 'SecurityEvent | where CommandLine matches regex "mimikatz"', 'SecurityEvent | where CommandLine matches regex @"^powershell$"'],
    miss: ['DeviceProcessEvents | where FileName matches regex "^(cmd|powershell)\\\\.exe$"', 'SecurityEvent | where CommandLine matches regex "-e(nc|ncoded)?\\\\s"', 'DeviceProcessEvents | where FolderPath startswith "C:\\\\Windows"'],
  },
};

export default rule;
