// A where that follows an extend but does not read what the extend
// computed can run before it, on fewer rows. The engine reorders some
// simple cases on its own; a filter written first is a filter run first.

import { stages, mask } from "./_text.js";

function extended(st) {
  const names = [];
  const body = mask(st.text.replace(/^extend\s*/i, (w) => " ".repeat(w.length)), "kql");
  for (const m of body.matchAll(/(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*|\['[^']*'\])\s*=(?!=)/g)) names.push(m[1].replace(/^\['|'\]$/g, ""));
  return names;
}

export const rule = {
  id: "kql/where-after-extend",
  platform: "kql",
  severity: "note",
  title: "where after extend",
  why: "this where reads nothing the extend before it computed, so it can run first and the extend on fewer rows",
  find(text) {
    const out = [];
    const list = stages(text, "kql");
    for (let i = 1; i < list.length - 1; i++) {
      if (list[i].head !== "extend") continue;
      const names = extended(list[i]);
      const next = list[i + 1];
      if (next.head !== "where" || !names.length) continue;
      const m = mask(next.text, "kql");
      if (names.some((n) => new RegExp(`(?<![\\w.])${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w.])`).test(m))) continue;
      out.push({ start: next.start, end: next.end, fix: { text: `${next.text} | ${list[i].text}`, label: "the where first, then the extend" } });
    }
    return out;
  },
  cases: {
    hit: ['SigninLogs | extend Domain = tostring(split(UserPrincipalName, "@")[1]) | where ResultType == "0"', 'SecurityEvent | extend Proc = tolower(Process), Len = strlen(CommandLine) | where EventID == 4688'],
    miss: ['SigninLogs | extend Domain = tostring(split(UserPrincipalName, "@")[1]) | where Domain == "example.com"', 'SigninLogs | where ResultType == "0" | extend Domain = "x"', "SecurityEvent | extend Len = strlen(CommandLine) | project Len | where Len > 10"],
  },
};

export default rule;
