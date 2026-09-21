// Discover: #/discover
// Two views behind one route, by platform (app/lib/platform.js):
//   Splunk    discover-splunk.js: the fixed reporting searches run in an open
//             Splunk tab with that tab's session, health and deltas between runs
//   Sentinel  discover-sentinel.js: the recipe; Reach writes the queries, the
//             user runs them in the portal and brings the one result cell back

import { isSentinel } from "../lib/platform.js";
import * as splunk from "./discover-splunk.js";
import * as sentinel from "./discover-sentinel.js";

export function render(ctx) {
  return (isSentinel() ? sentinel : splunk).render(ctx);
}

export default { render };
