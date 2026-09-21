// Every extension path a content script can ask for is listed under
// web_accessible_resources, and nothing else under app/ is: the static
// import closure of each module a content script loads by
// chrome.runtime.getURL(), plus the directories those modules fetch from
// relative to import.meta.url, and the one script injected into the page.
// A dynamic import from a content script that falls outside the list fails
// silently in the browser, so the list is checked here on every run.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
const war = manifest.web_accessible_resources[0];
const contentScripts = ["json-tree-fields.js", "value-popup.js", "field-info-popup.js", "discovery-agent.js", "search-history.js", "sentinel-workspace.js", "sentinel-grid.js"];

// A WAR resource pattern: "*" matches any run of characters, "/" included.
function rule(pattern) {
  return new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
}
const rules = war.resources.map(rule);
const allowed = (path) => rules.some((r) => r.test(path));

// Paths a content script names directly (a query string is not a path).
function askedFor() {
  const out = new Set();
  for (const file of contentScripts) {
    const src = readFileSync(join(root, file), "utf8");
    for (const m of src.matchAll(/chrome\.runtime\.getURL\("([^"?#]+)/g)) out.add(m[1]);
    for (const m of src.matchAll(/\.src\s*=\s*chrome\.runtime\.getURL\("([^"?#]+)/g)) out.add(m[1]);
  }
  return out;
}

// The static import closure of a set of modules, plus the directories the
// closure fetches from at runtime (packs.js, pack-fields.js and friends build
// URLs from import.meta.url), as "dir/*".
function closure(entries) {
  const seen = new Set();
  const queue = [...entries];
  while (queue.length) {
    const p = queue.pop();
    if (seen.has(p) || p.endsWith("/*")) {
      seen.add(p);
      continue;
    }
    seen.add(p);
    if (!p.endsWith(".js")) continue;
    const abs = join(root, p);
    const src = readFileSync(abs, "utf8");
    const specs = [
      ...src.matchAll(/(?:^|\n)\s*(?:import|export)\b[^;'"]*?from\s*["']([^"']+)["']/g),
      ...src.matchAll(/(?:^|\n)\s*import\s*["']([^"']+)["']/g),
      ...src.matchAll(/import\(\s*["']([^"']+)["']\s*\)/g),
    ];
    for (const m of specs) if (m[1].startsWith(".")) queue.push(relative(root, resolve(dirname(abs), m[1])));
    for (const m of src.matchAll(/new URL\(`([^`]+)`, import\.meta\.url\)/g)) {
      const dir = m[1].replace(/\$\{[^}]+\}.*$/, "");
      queue.push(`${relative(root, resolve(dirname(abs), dir))}/*`);
    }
  }
  return [...seen].sort();
}

test("web_accessible_resources is the app page, what content scripts import, and the page-injected script", () => {
  assert.deepEqual(war.matches, ["*://*/*"]); // Splunk origins are user-chosen at runtime; the pattern mirrors optional_host_permissions
  assert.deepEqual(war.resources, ["index.html", "app/lib/*", "app/components/*", "app/data/*", "app/packs/*", "live-lookup.js", "search-history-inject.js", "sentinel-editor-inject.js"]);
});

test("every path a content script loads, and every module or directory that pulls in, is web-accessible", () => {
  const asked = askedFor();
  assert.ok(asked.has("live-lookup.js") && asked.has("search-history-inject.js") && asked.has("sentinel-editor-inject.js") && asked.has("app/lib/popup-ui.js"), [...asked].join(", "));
  const missing = [];
  for (const p of asked) if (!p.endsWith(".html") && !allowed(p)) missing.push(p);
  for (const p of closure([...asked].filter((p) => p.endsWith(".js")))) if (!allowed(p.replace(/\/\*$/, "/x"))) missing.push(p);
  assert.deepEqual(missing, []);
});

test("the app shell, its views and styles are not web-accessible: only index.html loads them, same-origin", () => {
  for (const p of ["boot.js", "app/app.js", "app/views/discover-splunk.js", "app/styles/base.css", "app/gallery.html", "background.js", "popup.js", "options.html", "manifest.json"]) {
    assert.equal(allowed(p), false, p);
  }
  // No content script reaches them either.
  const reach = new Set(closure([...askedFor()].filter((p) => p.endsWith(".js"))));
  for (const p of reach) assert.ok(!/^app\/(views|styles)\/|^app\/app\.js$|^boot\.js$/.test(p), p);
});
