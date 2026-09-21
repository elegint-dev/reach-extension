// A dotted column is a path into a dynamic column. Compared bare against
// a string literal it compares as dynamic, and the term index cannot
// answer it; tostring() makes the comparison a string one, and has on the
// dynamic column itself reads the term index.

import { stages, fieldTests, mask } from "./_text.js";

export const rule = {
  id: "kql/dynamic-untyped",
  platform: "kql",
  severity: "note",
  title: "dynamic path compared bare",
  why: "a path into a dynamic column is dynamic-typed: compared bare to a string it is parsed on every row, and the index cannot answer it; tostring() makes it a string comparison, or has on the column itself reads the term index",
  find(text) {
    const out = [];
    for (const st of stages(text, "kql")) {
      if (st.head !== "where") continue;
      const m = mask(st.text, "kql");
      for (const t of fieldTests(st, "kql")) {
        if (!t.field.includes(".") || !/^(==|!=|=~|!~|in|!in|in~|!in~)$/.test(t.op)) continue;
        const before = m.slice(0, t.start - st.start);
        if (/\b(tostring|toint|tolong|todouble|tobool|todatetime|toguid|tolower|toupper)\s*\(\s*$/.test(before)) continue;
        const head = t.field.split(".")[0];
        out.push({ start: t.start, end: t.end, fix: { text: `tostring(${t.field}) ${t.op} "${t.value}"`, construct: "literal", label: `tostring(), or ${head} has "${t.value}" for the term index` } });
      }
    }
    return out;
  },
  cases: {
    hit: ['AuditLogs | where InitiatedBy.user.userPrincipalName == "alice@example.com"', 'AzureActivity | where Properties.status =~ "Failed"'],
    miss: ['AuditLogs | where tostring(InitiatedBy.user.userPrincipalName) == "alice@example.com"', 'AuditLogs | where InitiatedBy has "alice@example.com"', 'AuditLogs | where OperationName == "Add member to role"', 'AuditLogs | extend U = tostring(InitiatedBy.user.userPrincipalName) | where U == "alice"'],
  },
};

export default rule;
