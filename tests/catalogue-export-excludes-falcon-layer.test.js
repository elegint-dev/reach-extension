// catalogue.exportUser() is the user layer alone (board it_9951cfe3, part
// 5): the imported Falcon dictionary is the team's own file, and never
// rides along in a "Share notes" export.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const catalogue = await import("../app/lib/catalogue.js");
const fd = await import("../app/lib/falcon-dictionary.js");

const SAMPLE = JSON.parse(await readFile(new URL("./fixtures/falcon-dictionary.sample.json", import.meta.url), "utf8"));

await catalogue.load();

test("an imported Falcon dictionary does not appear in exportUser()'s output", async () => {
  await store.remove(fd.KEY);
  fd._reset();
  await fd.load();
  await fd.importDoc(SAMPLE);
  assert.equal(fd.present(), true);

  const exported = JSON.stringify(catalogue.exportUser());
  assert.doesNotMatch(exported, /falcon-fdr-schema/);
  assert.doesNotMatch(exported, /Sensor identity and platform metadata/);
});
