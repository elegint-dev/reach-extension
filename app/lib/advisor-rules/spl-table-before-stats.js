// table is a formatting command: it pulls results to the search head, so a
// stats after it runs there instead of on the indexers. fields keeps the
// same columns without ending the distributed part of the search.

import { stages } from "./_text.js";

const REPORTING = new Set(["stats", "chart", "timechart", "eventstats", "streamstats", "top", "rare", "tstats", "sistats", "dedup", "sort", "transaction", "geostats"]);

export const rule = {
  id: "spl/table-before-stats",
  platform: "spl",
  severity: "caution",
  title: "table before stats",
  why: "table ends the distributed part of the search; a stats after it runs on the search head alone. fields keeps the columns and lets stats run on the indexers",
  find(text) {
    const out = [];
    const list = stages(text, "spl");
    list.forEach((st, i) => {
      if (st.head !== "table") return;
      if (!list.slice(i + 1).some((s) => REPORTING.has(s.head))) return;
      out.push({ start: st.start, end: st.end, fix: { text: st.text.replace(/^table/i, "fields"), construct: "fields", label: "fields in place of table" } });
    });
    return out;
  },
  cases: {
    hit: ["index=main | table user, action | stats count by user", "index=main | table _time user | sort - _time"],
    miss: ["index=main | stats count by user | table user, count", "index=main | fields user, action | stats count by user", "index=main | table user"],
  },
};

export default rule;
