// The options page: the module list (app/components/moduleList.js), the
// same element the side panel's Settings fold draws, mounted on its own
// page for the store listing's settings link and for the popups' "set it
// up" links, which land on a module's head
// (options.html?platform=<platform>#module-<id>). The list is the current
// platform's, the one the panel shows: the query names it, else the
// platform remembered from the last Reach page opened.

import { moduleList } from "./app/components/moduleList.js";
import * as modules from "./app/lib/modules.js";
import * as scope from "./app/lib/scope.js";
import * as sentinelSettings from "./app/lib/sentinel-settings.js";
import { PLATFORM, TERMS, appQuery } from "./app/lib/platform.js";

function platformLine() {
  const other = PLATFORM === "sentinel" ? "splunk" : "sentinel";
  const line = document.getElementById("platform");
  line.replaceChildren(`The modules for ${TERMS.platform}. `, Object.assign(document.createElement("a"), { href: `options.html${appQuery(other)}`, textContent: `Show the ${other === "sentinel" ? "Microsoft Sentinel" : "Splunk"} modules →` }));
}

async function main() {
  await Promise.all([modules.hydrate(), scope.hydrate().catch(() => {}), sentinelSettings.hydrate().catch(() => {})]);
  platformLine();
  const mount = document.getElementById("modules");
  mount.replaceChildren(moduleList({ platform: PLATFORM, context: "options" }));
  landOnHash();
  window.addEventListener("hashchange", landOnHash);
}

function landOnHash() {
  const target = location.hash ? document.getElementById(location.hash.slice(1)) : null;
  if (target) target.scrollIntoView({ block: "start" });
}

main();
