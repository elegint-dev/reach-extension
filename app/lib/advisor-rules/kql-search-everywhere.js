// search without a table, and union *, read every table in the
// workspace. The generated queries always name a table; a hand-written
// one that does not pays for the whole workspace.

import { stages, mask } from "./_text.js";

export const rule = {
  id: "kql/search-everywhere",
  platform: "kql",
  severity: "caution",
  title: "whole-workspace search",
  why: "search without a table, or union *, reads every table in the workspace; name the table the value lives in",
  find(text) {
    const out = [];
    const list = stages(text, "kql");
    if (!list.length) return out;
    const first = list[0];
    const m = mask(first.text, "kql");
    if (/^search\s+(?!in\s*\()/i.test(m) && !/\bin\s*\(/.test(m)) out.push({ start: first.start, end: first.end, fix: { text: `search in (<Table>) ${first.text.replace(/^search\s+/i, "")}`, label: "search in (Table), or the table's own where" } });
    else if (/^union\s+(?:withsource\s*=\s*\S+\s+)?\*\s*$/i.test(m)) out.push({ start: first.start, end: first.end, fix: { text: "union Table1, Table2", label: "the tables the value can be in" } });
    return out;
  },
  cases: {
    hit: ['search "mimikatz"', 'search "alice@example.com" | take 10', "union * | where TimeGenerated > ago(1h)", "union withsource=T * | summarize count() by T"],
    miss: ['search in (SecurityEvent) "mimikatz"', 'SecurityEvent | search "mimikatz"', "union SecurityEvent, Event | where TimeGenerated > ago(1h)", 'SigninLogs | where UserPrincipalName == "alice@example.com"'],
  },
};

export default rule;
