// index=* reads every index the role can see. Reach binds the index from
// scope per sourcetype, so a generated search should never carry it.

import { stages, mask } from "./_text.js";

export const rule = {
  id: "spl/index-star",
  platform: "spl",
  severity: "caution",
  title: "index=*",
  why: "index=* reads every index the role can search: name the index the sourcetype lives in",
  find(text) {
    const out = [];
    for (const st of stages(text, "spl")) {
      if (st.head !== "" && st.head !== "search" && st.head !== "tstats") continue;
      const m = mask(st.text, "spl");
      for (const hit of m.matchAll(/(?<![\w.])index\s*=\s*(?:"\s*"|\*)(?![\w*])/g)) {
        const raw = text.slice(st.start + hit.index, st.start + hit.index + hit[0].length);
        if (!/\*/.test(raw)) continue; // a quoted value the mask blanked that is not *
        out.push({ start: st.start + hit.index, end: st.start + hit.index + hit[0].length, fix: { text: "index=<the sourcetype's index>", label: "the index scope binds for the sourcetype, or the one the event sits in" } });
      }
    }
    return out;
  },
  cases: {
    hit: ["index=* sourcetype=aws:cloudtrail eventName=ConsoleLogin", 'index="*" host=web01', "| tstats count where index=* by sourcetype"],
    miss: ["index=main sourcetype=aws:cloudtrail", "index=$index$ sourcetype=aws:cloudtrail", "index=sec* sourcetype=okta", 'index=main | search index="prod"'],
  },
};

export default rule;
