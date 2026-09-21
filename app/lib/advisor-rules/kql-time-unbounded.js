// A query without a time predicate runs over whatever the portal's
// picker holds; a saved query, a rule or a workbook needs its own.

import { mask, trim } from "./_text.js";

const TIME_RE = /\b(TimeGenerated|ago\s*\(|datetime\s*\(|between\s*\(|now\s*\(|startofday\s*\(|endofday\s*\()/;

export const rule = {
  id: "kql/time-unbounded",
  platform: "kql",
  severity: "note",
  title: "time range",
  why: "no time predicate in the query: the portal's picker decides the window, and a saved query, a rule or a workbook needs its own",
  find(text) {
    const s = String(text || "");
    const m = mask(s, "kql");
    if (!m.trim() || TIME_RE.test(m) || /\{\{\s*(earliest|latest|window)\s*\}\}|\$(earliest|latest|window)\$/.test(s)) return [];
    const [start, end] = trim([0, m.indexOf("|") < 0 ? s.length : m.indexOf("|")], s);
    return [{ start, end, fix: { text: `${s.slice(start, end)} | where TimeGenerated > ago(1d)`, label: "a window the question needs" } }];
  },
  cases: {
    hit: ['SigninLogs | where UserPrincipalName == "alice@example.com"', "SecurityEvent | summarize count() by Account"],
    miss: ["SigninLogs | where TimeGenerated > ago(1d)", 'SecurityEvent | where TimeGenerated between (datetime(2026-09-01) .. datetime(2026-09-02)) | where Account == "x"', "SecurityEvent | where TimeGenerated > $earliest$"],
  },
};

export default rule;
