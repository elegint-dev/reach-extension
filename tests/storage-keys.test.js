// Storage key names are spelled once, in app/lib/storage-keys.js: the
// module registry lists the same names, every relay descriptor reads keys
// its module owns, and no runtime file under app/ or the worker, nor the
// popup and the value-click content scripts, types one of the literals
// itself.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { KEYS } from "../app/lib/storage-keys.js";
import * as modules from "../app/lib/modules.js";
import { relay as virustotal } from "../app/lib/enrich/virustotal.js";
import { relay as circl } from "../app/lib/enrich/circl.js";
import { relay as epss } from "../app/lib/enrich/epss.js";
import { relay as selfhosted } from "../app/lib/enrich/selfhosted.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const values = new Set(Object.values(KEYS));

// A portal fact the grid script rewrites on every blade load, not a
// module's stored data: named here, listed in no registry entry.
const NOT_IN_REGISTRY = new Set([KEYS.sentinelWorkspace]);

test("every chrome.storage.local key the registry lists is in KEYS", () => {
  const missing = [];
  for (const m of modules.MODULES) for (const k of modules.keysOf(m.id).chrome) if (!values.has(k)) missing.push(`${m.id}: ${k}`);
  assert.deepEqual(missing, []);
});

test("every KEYS entry is a registry key, or named as the one that is not", () => {
  const registry = new Set(modules.MODULES.flatMap((m) => [...modules.keysOf(m.id).chrome, ...modules.keysOf(m.id).local]));
  const stray = [...values].filter((k) => !registry.has(k) && !NOT_IN_REGISTRY.has(k));
  assert.deepEqual(stray, []);
});

test("each relay descriptor reads only keys its module owns", () => {
  for (const d of [virustotal, circl, epss, selfhosted]) {
    const owner = modules.sourceOwner(d.id);
    assert.ok(owner, d.id);
    const owned = new Set(modules.keysOf(owner.id).chrome);
    for (const k of d.keys) {
      assert.ok(values.has(k), `${d.id}: ${k} is not in KEYS`);
      assert.ok(owned.has(k), `${d.id}: ${k} is not a key of module ${owner.id}`);
    }
  }
});

function jsFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...jsFiles(p));
    else if (name.endsWith(".js")) out.push(p);
  }
  return out;
}

test("no runtime file under app/ or the worker spells a key literal the registry and storage-keys.js already hold", () => {
  const files = [
    ...jsFiles(path.join(root, "app")),
    path.join(root, "background.js"),
    path.join(root, "options.js"),
    path.join(root, "value-popup.js"),
    path.join(root, "sentinel-grid.js"),
    path.join(root, "popup.js"),
  ].filter((f) => !/app\/(lib\/(storage-keys|modules)\.js|data\/|packs\/)/.test(f));
  const hits = [];
  for (const f of files) {
    const src = readFileSync(f, "utf8");
    for (const k of values) {
      const re = new RegExp(`["'\`]${k.replace(/[.]/g, "\\.")}["'\`]`);
      const m = re.exec(src);
      if (m) hits.push(`${path.relative(root, f)}: ${k}`);
    }
  }
  assert.deepEqual(hits, []);
});
