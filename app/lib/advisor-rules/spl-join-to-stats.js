// join runs a subsearch and merges in memory on the search head; stats by
// the shared key does the same work on the indexers with no row cap.

import { stages } from "./_text.js";

export const rule = {
  id: "spl/join-to-stats",
  platform: "spl",
  severity: "caution",
  title: "join",
  why: "join runs the inner search as a subsearch (10,000 rows, 60 s) and merges on the search head; stats by the key with values() over both sets has no such cap",
  find(text) {
    const out = [];
    for (const st of stages(text, "spl")) {
      if (st.head !== "join") continue;
      const m = /^join(?:\s+(?:type|max|usetime|earlier|overwrite|left|right)=\S+)*\s+([A-Za-z_][\w.,]*)?/i.exec(st.text);
      const key = m && m[1] ? m[1] : "<key>";
      out.push({ start: st.start, end: st.end, fix: { text: `(search A) OR (search B) | stats values(*) as * by ${key}`, construct: "stats", label: "one search over both sets, stats by the key" } });
    }
    return out;
  },
  cases: {
    hit: ["index=main sourcetype=a | join user [search index=main sourcetype=b] | table user", "index=main | join type=left host [ search index=assets ]"],
    miss: ["(index=main sourcetype=a) OR (index=main sourcetype=b) | stats values(action) as action by user", "index=main | search join_key=1", 'index=main | eval note="join later"'],
  },
};

export default rule;
