// field!=value keeps only events that carry the field; NOT field=value
// keeps the events without it too. Neither is wrong; the one that was
// meant depends on what an absent field means.

import { stages, fieldTests } from "./_text.js";

export const rule = {
  id: "spl/neq-null",
  platform: "spl",
  severity: "note",
  title: "!= drops the field-less",
  why: "field!=value matches only events that have the field; events without it are dropped silently. NOT field=value keeps them",
  find(text) {
    const out = [];
    for (const st of stages(text, "spl")) {
      if (st.head !== "" && st.head !== "search") continue;
      for (const t of fieldTests(st, "spl")) {
        if (t.op !== "!=") continue;
        out.push({ start: t.start, end: t.end, fix: { text: `NOT ${t.field}=${t.quoted ? `"${t.value}"` : t.value}`, construct: "not", label: "keep events that lack the field" } });
      }
    }
    return out;
  },
  cases: {
    hit: ["index=main sourcetype=okta user!=svc_backup", 'index=main | search action!="login"'],
    miss: ["index=main NOT user=svc_backup", 'index=main | where user!="root"', "index=main user=admin"],
  },
};

export default rule;
