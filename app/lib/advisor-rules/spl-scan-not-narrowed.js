// The search block is what the lexicon can answer. Nothing indexed in it
// means every bucket the role searches by default is opened; only tests on
// calculated or lookup fields mean every event is read and evaluated.

import { stages, mask, fieldTests } from "./_text.js";

const INDEXED = new Set(["index", "sourcetype", "source", "host", "splunk_server", "punct"]);

export const rule = {
  id: "spl/scan-not-narrowed",
  platform: "spl",
  severity: "note",
  title: "scan not narrowed",
  why: "no index, sourcetype, source or host in the search block: every index the role searches by default is opened",
  find(text, ctx = {}) {
    const list = stages(text, "spl");
    if (!list.length || list[0].head !== "") return [];
    const block = list[0];
    const tests = fieldTests(block, "spl");
    const m = mask(block.text, "spl");
    const hasIndexed = tests.some((t) => INDEXED.has(t.field));
    const bare = m.replace(/^search\b/i, " ").replace(/[A-Za-z_][\w.:{}]*\s*(!=|==|=|>=|<=|>|<)\s*("[^"]*"|\S+)/g, " ").replace(/\b(AND|OR|NOT|IN)\b|[()]/g, " ").trim();
    if (!hasIndexed && !bare) return [{ start: block.start, end: block.end, fix: { text: `index=<the sourcetype's index> sourcetype=<the sourcetype> ${block.text}`, label: "the index and sourcetype scope binds" } }];
    if (typeof ctx.classOf !== "function") return [];
    const onFields = tests.filter((t) => !INDEXED.has(t.field));
    if (!onFields.length || bare) return [];
    const classes = onFields.map((t) => ctx.classOf(t.field));
    if (classes.every((c) => c === "calculated" || c === "lookup_output")) {
      return [{ start: block.start, end: block.end, severity: "caution", why: "every field test in the search block is on a calculated or lookup field: the index cannot narrow on those, so every event in the range is read and evaluated", fix: { text: "add a raw token the value carries, or a test on an extracted field", construct: "term", label: "a token the lexicon can answer" } }];
    }
    return [];
  },
  cases: {
    hit: ["user=admin action=login", "index=main risk_score=90"],
    miss: ["index=main user=admin", "sourcetype=okta user=admin", "admin failed | stats count", "index=main | stats count"],
    ctx: { classOf: (f) => (f === "risk_score" ? "calculated" : "raw_token") },
  },
};

export default rule;
