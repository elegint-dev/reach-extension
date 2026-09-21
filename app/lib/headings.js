// headings: every heading the panel may draw, one entry per meaning. A
// view never writes a heading string of its own; it asks here with the
// entry's id and the count, and the words come from TERMS so the Sentinel
// page reads table, column and workspace where the Splunk page reads
// sourcetype, field and index.
//
//   HEADINGS                 the frozen list of { id, level, text(T, n) }
//   heading(id, n)           the string under this page's TERMS
//   headingNode(id, n)       the element for the entry's level (h2, h3 or summary), with data-heading
//   matcher(T)               text => the entry a rendered heading resolves to, or null
//   ENTITY_ORDER, TOOL_ORDER the master h2 orders for entity pages and tool pages (C4)
//
// Levels: h2 is a section, h3 a band inside one (the ledger, a feed under
// Feeds), summary a fold directly under a section. A count in the text is
// written "(N)" in the table and drawn as the number.

import { TERMS } from "./platform.js";
import { h } from "../components/h.js";

const count = (base) => (T, n) => (n === undefined || n === null ? base : `${base} (${Number(n).toLocaleString("en-US")})`);
const plain = (base) => () => base;

const entry = (id, level, text) => Object.freeze({ id, level, text });

export const HEADINGS = Object.freeze([
  // entity pages
  entry("meaning", "h2", plain("Meaning")),
  entry("fleet-baseline", "h2", plain("Baseline: what my fleet runs")),
  entry("other-sourcetypes", "h2", (T, n) => count(`Other ${T.sourcetypes}`)(T, n)),
  entry("values", "h2", plain("Values")),
  entry("decode-table", "summary", count("Decode table")),
  entry("same-role-fields", "summary", (T, n) => count(`Same-role ${T.fields}`)(T, n)),
  entry("field-changes", "h2", (T, n) => count(`${T.Field} changes`)(T, n)),
  entry("verdict", "h2", plain("Verdict")),
  entry("evidence", "summary", plain("Evidence")),
  entry("enrichment", "h2", plain("Enrichment")),
  entry("other-sources", "summary", count("Other sources")),
  entry("pivots", "h2", count("Pivots")),
  entry("on-the-record", "h3", count("On the record")),
  entry("search-time-lookups", "h3", count("Search-time lookups")),
  entry("one-join-away", "h3", count("One join away")),
  entry("suggested-joins", "h3", count("Suggested joins")),
  entry("not-reachable", "h3", count("Not reachable")),
  entry("workflows", "h2", plain("Workflows")),
  entry("pattern", "h2", plain("Pattern")),
  entry("other-forms", "summary", count("Other forms")),
  entry("live-test", "summary", plain("Live test")),
  entry("profile", "h2", plain("Profile")),
  entry("extraction", "h2", plain("Extraction")),
  entry("cim-mapping", "h2", plain("CIM mapping")),
  entry("pack-description", "summary", plain("Pack description")),
  entry("record-types", "h2", count("Record types")),
  entry("fields", "h2", (T, n) => count(T.Fields)(T, n)),
  entry("query-advisor", "h2", plain("Query advisor")),
  // tool pages
  entry("setup", "h2", plain("Setup")),
  entry("tools", "h2", plain("Tools")),
  entry("environment", "h2", (T) => T.Env),
  entry("queries", "h2", plain("Queries")),
  entry("pasted-results", "h2", plain("Pasted results")),
  entry("discovered-sourcetypes", "h2", (T, n) => count(`Discovered ${T.sourcetypes}`)(T, n)),
  entry("feeds", "h2", count("Feeds")),
  entry("sourcetypes", "h2", (T, n) => count(T.Sourcetypes)(T, n)),
  entry("join-leads", "h2", plain("Join leads")),
  entry("skipped-fields", "summary", (T, n) => count(`Skipped ${T.fields}`)(T, n)),
  entry("matches", "h2", count("Matches")),
  entry("nearest-names", "h2", count("Nearest names")),
  entry("inputs", "h2", count("Inputs")),
  entry("searches", "h2", count("Searches")),
  entry("rows", "h2", count("Rows")),
  entry("expected-results", "h2", plain("Expected results")),
  entry("disambiguation", "h2", plain("Disambiguation")),
  entry("troubleshooting", "h2", plain("Troubleshooting")),
  entry("draft-runbook", "h2", count("Draft from your investigations")),
  entry("steps", "h2", count("Steps")),
  entry("benign-conditions", "h2", count("Benign conditions")),
  entry("escalation-conditions", "h2", count("Escalation conditions")),
  entry("threads", "h2", count("Threads")),
  entry("timeline", "h2", plain("Timeline")),
  entry("search-history", "h2", count("Search history")),
  entry("investigations", "h2", plain("Investigations")),
  entry("import-investigation", "h2", plain("Import an investigation")),
  entry("export-notes", "h2", plain("Export notes")),
  entry("import-notes", "h2", plain("Import notes")),
]);

// One master order per page family: a page's h2 sequence is a subsequence of its family's.
export const ENTITY_ORDER = Object.freeze([
  "verdict", "meaning", "fleet-baseline", "other-sourcetypes", "values", "field-changes", "enrichment", "pivots", "workflows", "pattern", "profile", "extraction", "cim-mapping", "record-types", "fields", "query-advisor", "threads", "timeline", "search-history", "investigations", "import-investigation",
]);
export const TOOL_ORDER = Object.freeze([
  "setup", "workflows", "tools", "environment", "queries", "pasted-results", "discovered-sourcetypes", "feeds", "sourcetypes", "fields", "join-leads", "matches", "nearest-names", "inputs", "searches", "rows", "expected-results", "disambiguation", "troubleshooting", "draft-runbook", "steps", "benign-conditions", "escalation-conditions", "export-notes", "import-notes",
]);

const BY_ID = new Map(HEADINGS.map((e) => [e.id, e]));

export function get(id) {
  const e = BY_ID.get(id);
  if (!e) throw new Error(`no heading ${id}`);
  return e;
}

export function heading(id, n, T = TERMS) {
  return get(id).text(T, n);
}

export function headingNode(id, n, attrs = {}) {
  const e = get(id);
  return h(e.level, { ...attrs, dataset: { ...(attrs.dataset || {}), heading: e.id } }, e.text(TERMS, n));
}

// A rendered heading back to its entry: where the text writes a count,
// any number matches, and so does the text with no count at all.
export function matcher(T = TERMS) {
  const rules = HEADINGS.map((e) => {
    const probe = e.text(T, 7);
    const pattern = probe.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(" \\(7\\)", "(?: \\(\\d[\\d,]*\\))?");
    return { entry: e, re: new RegExp(`^${pattern}$`) };
  });
  return (text) => {
    const t = String(text || "").replace(/\s+/g, " ").trim();
    const hit = rules.find((r) => r.re.test(t));
    return hit ? hit.entry : null;
  };
}

export default { HEADINGS, ENTITY_ORDER, TOOL_ORDER, get, heading, headingNode, matcher };
