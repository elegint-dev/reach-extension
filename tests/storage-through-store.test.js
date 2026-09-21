// Every app module reaches chrome.storage through app/lib/store.js (a
// document through app/lib/document.js, a literal key through the store's
// literal helpers): no other file under app/ names chrome.storage in code.
// runtime.js probes for it and storage-keys.js spells the names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const APP = fileURLToPath(new URL("../app", import.meta.url));
const ALLOWED = new Set(["lib/store.js", "lib/runtime.js", "lib/storage-keys.js"]);

async function jsFiles(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await jsFiles(p)));
    else if (e.name.endsWith(".js")) out.push(p);
  }
  return out;
}

function codeOnly(text) {
  return text
    .split("\n")
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\//g, "");
}

test("chrome.storage is named in code only by store.js, runtime.js and storage-keys.js", async () => {
  const hits = [];
  for (const file of await jsFiles(APP)) {
    const rel = path.relative(APP, file);
    if (ALLOWED.has(rel)) continue;
    if (/chrome\.storage/.test(codeOnly(await readFile(file, "utf8")))) hits.push(rel);
  }
  assert.deepEqual(hits, []);
});
