// Every module under app/ and every root content/background script is
// walked over its import edges (static import/export...from, and the
// dynamic import(chrome.runtime.getURL(...)) the popups use to reach
// app/lib); a cycle among them is the shape that made spl.js re-export
// fdr-queries.js's generate() instead of the other way round.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));

function jsFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...jsFiles(p));
    else if (name.endsWith(".js")) out.push(p);
  }
  return out;
}

const rootScripts = readdirSync(root).filter((n) => n.endsWith(".js")).map((n) => path.join(root, n));
const files = [...jsFiles(path.join(root, "app")), ...rootScripts];

const IMPORT_RE = /(?:^|\s)(?:import|export)\s[^;]*?from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)|getURL\(\s*["']([^"']+)["']\s*\)/g;

function edgesOf(file) {
  const src = readFileSync(file, "utf8");
  const out = [];
  for (const m of src.matchAll(IMPORT_RE)) {
    const spec = m[1] || m[2] || m[3];
    if (!spec || !spec.endsWith(".js")) continue;
    const target = spec.startsWith(".") ? path.resolve(path.dirname(file), spec) : path.join(root, spec);
    out.push(target);
  }
  return out;
}

const graph = new Map(files.map((f) => [f, edgesOf(f).filter((t) => files.includes(t))]));

function findCycle() {
  const state = new Map(); // 0 unvisited, 1 in stack, 2 done
  const stack = [];
  function dfs(node) {
    state.set(node, 1);
    stack.push(node);
    for (const next of graph.get(node) || []) {
      if (state.get(next) === 1) return stack.slice(stack.indexOf(next)).concat(next);
      if (!state.get(next)) {
        const cyc = dfs(next);
        if (cyc) return cyc;
      }
    }
    stack.pop();
    state.set(node, 2);
    return null;
  }
  for (const node of graph.keys()) {
    if (!state.get(node)) {
      const cyc = dfs(node);
      if (cyc) return cyc;
    }
  }
  return null;
}

test("import graph under app/ and the root scripts has no cycle", () => {
  const cycle = findCycle();
  const shown = cycle ? cycle.map((f) => path.relative(root, f)).join(" -> ") : "";
  assert.equal(cycle, null, `cycle found: ${shown}`);
});
