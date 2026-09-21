// "Fleet corpus" is retired wording (the feature is the fleet baseline
// now); nothing under app/ says it any more, in a string or a comment.
// Identifiers (orgCorpus, org_corpus, ORG_CORPUS_*) carry no space and
// never match.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const APP_DIR = fileURLToPath(new URL("../app/", import.meta.url));

async function jsFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await jsFiles(full)));
    else if (entry.isFile() && entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

test("no .js file under app/ contains the retired phrase 'Fleet corpus'", async () => {
  const files = await jsFiles(APP_DIR);
  assert.ok(files.length > 50, `expected many source files, found ${files.length}`);
  const hits = [];
  for (const f of files) {
    const text = await readFile(f, "utf8");
    if (/fleet\s+corpus/i.test(text)) hits.push(path.relative(APP_DIR, f));
  }
  assert.deepEqual(hits, []);
});
