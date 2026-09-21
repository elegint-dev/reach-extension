// A subsearch is bounded: 10,000 results and 60 seconds by default, then
// the outer search runs on whatever came back.

import { subsearches } from "./_text.js";

export const rule = {
  id: "spl/subsearch-limits",
  platform: "spl",
  severity: "note",
  title: "subsearch",
  why: "a subsearch stops at 10,000 results or 60 seconds and the outer search runs on what came back; the truncation shows only in the job's messages",
  find(text) {
    return subsearches(text).map((s) => ({ start: s.start, end: s.end, fix: { text: "| stats values() by <key>, or a lookup for a fixed list", label: "a stats join or a lookup has no such cap" } }));
  },
  cases: {
    hit: ["index=main [search index=alerts | fields user]", "index=main user IN ([| inputlookup bad_users | fields user])"],
    miss: ["index=main user IN (a, b, c)", 'index=main | eval s="[x]"', "index=main | lookup bad_users user OUTPUT flag"],
  },
};

export default rule;
