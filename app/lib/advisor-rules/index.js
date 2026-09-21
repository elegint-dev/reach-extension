// Every advisor rule, one module each. A rule is
//   { id, platform: spl | kql, severity: caution | note, title, why, find(text, ctx) -> [{ start, end, why?, severity?, fix? }], cases: { hit, miss, ctx? } }
// with cases the test suite runs: every hit text yields the rule at least
// once, every miss text never does.

import splLeadingWildcard from "./spl-leading-wildcard.js";
import splIndexStar from "./spl-index-star.js";
import splFilterAfterScan from "./spl-filter-after-scan.js";
import splJoinToStats from "./spl-join-to-stats.js";
import splNeqNull from "./spl-neq-null.js";
import splSubsearchLimits from "./spl-subsearch-limits.js";
import splTableBeforeStats from "./spl-table-before-stats.js";
import splTimeUnbounded from "./spl-time-unbounded.js";
import splOrToIn from "./spl-or-to-in.js";
import splScanNotNarrowed from "./spl-scan-not-narrowed.js";
import kqlContainsToHas from "./kql-contains-to-has.js";
import kqlCiEquals from "./kql-ci-equals.js";
import kqlRegexToStartswith from "./kql-regex-to-startswith.js";
import kqlWhereAfterExtend from "./kql-where-after-extend.js";
import kqlDynamicUntyped from "./kql-dynamic-untyped.js";
import kqlSearchEverywhere from "./kql-search-everywhere.js";
import kqlTimeUnbounded from "./kql-time-unbounded.js";

export const RULES = Object.freeze([
  splLeadingWildcard,
  splIndexStar,
  splScanNotNarrowed,
  splFilterAfterScan,
  splJoinToStats,
  splTableBeforeStats,
  splNeqNull,
  splSubsearchLimits,
  splOrToIn,
  splTimeUnbounded,
  kqlSearchEverywhere,
  kqlContainsToHas,
  kqlCiEquals,
  kqlRegexToStartswith,
  kqlDynamicUntyped,
  kqlWhereAfterExtend,
  kqlTimeUnbounded,
]);

export default RULES;
