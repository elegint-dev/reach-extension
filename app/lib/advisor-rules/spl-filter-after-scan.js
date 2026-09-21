// A where or search stage right after the search block filters events the
// scan already returned. The same test written as a term in the search
// block lets the lexicon narrow the scan. The optimiser pushes some of
// these down on its own; optimizedSearch on the job shows whether it did.

import { stages, fieldTests } from "./_text.js";

// Stages that create or rename fields: a filter after one of these may be
// on a field that only exists there, which no term can express.
const DERIVING = new Set(["eval", "rex", "stats", "tstats", "lookup", "spath", "extract", "kv", "rename", "transaction", "join", "append", "appendcols", "appendpipe", "inputlookup", "makeresults", "xmlkv", "multikv", "mvexpand", "eventstats", "streamstats", "bin", "bucket", "fillnull", "iplocation", "addinfo", "chart", "timechart", "top", "rare", "convert", "replace", "strcat", "makemv", "nomv", "untable", "xyseries", "map", "foreach", "erex", "xpath", "from", "collect", "cluster", "kmeans", "outlier", "predict", "geostats", "addtotals", "accum", "delta", "autoregress"]);

export const rule = {
  id: "spl/filter-after-scan",
  platform: "spl",
  severity: "note",
  title: "filter after the scan",
  why: "a filter stage runs after the scan; the same test as a term in the search block narrows the scan first",
  find(text, ctx = {}) {
    const out = [];
    const list = stages(text, "spl");
    if (!list.length || list[0].head !== "") return out; // no search block: a generating command
    for (let i = 1; i < list.length; i++) {
      const st = list[i];
      if (DERIVING.has(st.head)) break;
      if (st.head !== "where" && st.head !== "search") continue;
      const body = st.text.replace(/^(where|search)\s*/i, (w) => " ".repeat(w.length));
      for (const t of fieldTests({ ...st, text: body }, "spl")) {
        if (st.head === "where" && !/^(=|==)$/.test(t.op)) continue;
        if (typeof ctx.classOf === "function" && ctx.classOf(t.field) === "pipeline_derived") continue;
        if (!t.quoted && !/^[A-Za-z0-9_.:$*@\\/-]+$/.test(t.value)) continue;
        const term = `${t.field}=${t.quoted ? `"${t.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : t.value}`;
        out.push({ start: t.start, end: t.end, fix: { text: term, construct: "literal", label: "the same test in the search block" } });
      }
    }
    return out;
  },
  cases: {
    hit: ['index=main sourcetype=okta | where action="user.session.start"', "index=main | fields user, action | search action=login", "index=main | where status=404 | stats count"],
    miss: ['index=main | eval a=lower(user) | where a="root"', "index=main | where len(user) > 8", "index=main | stats count by user | where count > 5", '| tstats count where index=main by host | where host="web01"', 'index=main | rex "user=(?<u>\\w+)" | search u=root'],
  },
};

export default rule;
