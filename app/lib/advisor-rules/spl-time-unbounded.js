// A search without a time bound runs over whatever the picker holds; one
// with earliest=0 runs over everything ever indexed.

import { stages, mask } from "./_text.js";

export const rule = {
  id: "spl/time-unbounded",
  platform: "spl",
  severity: "note",
  title: "time range",
  why: "no earliest or latest in the search: the time picker decides the window, and a paste into a scheduled search or an alert needs its own",
  find(text) {
    const list = stages(text, "spl");
    if (!list.length || list[0].head !== "") return [];
    const block = list[0];
    const m = mask(block.text, "spl");
    const all = /(?<![\w.])earliest\s*=\s*(0|1)(?![\w.:@-])/.exec(m);
    if (all) return [{ start: block.start + all.index, end: block.start + all.index + all[0].length, severity: "caution", why: "earliest=0 is all time: every bucket the index holds is opened", fix: { text: "earliest=-24h", label: "a window the question needs" } }];
    if (/(?<![\w.])(earliest|latest|_index_earliest|_index_latest)\s*=/.test(m) || /\$(earliest|latest|window)\$/.test(block.text)) return [];
    return [{ start: block.start, end: block.end, fix: { text: `${block.text} earliest=-24h`, label: "a window the question needs" } }];
  },
  cases: {
    hit: ["index=main sourcetype=okta user=admin", "index=main earliest=0 user=admin"],
    miss: ["index=main earliest=-24h user=admin", "index=main earliest=$earliest$ latest=now", "| tstats count where index=main by host", "index=main earliest=1758000000 latest=1758100000"],
  },
};

export default rule;
