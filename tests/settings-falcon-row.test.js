// The Data group's Falcon dictionary row (board it_9951cfe3, part 1): the
// row's summary line and its Forget control track the store, and Forget
// removes the layer.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

const store = await import("../app/lib/store.js");
const modules = await import("../app/lib/modules.js");
const fd = await import("../app/lib/falcon-dictionary.js");
const { moduleList } = await import("../app/components/moduleList.js");
await modules.hydrate();

const SAMPLE = JSON.parse(await readFile(new URL("./fixtures/falcon-dictionary.sample.json", import.meta.url), "utf8"));

function falconRowEl(list) {
  const nodes = dom.walk(list, (n) => n.classList && n.classList.contains("r-module__falcon"));
  return nodes[0] || null;
}

function falconStatus(list) {
  const row = falconRowEl(list);
  return row ? dom.text(row) : "";
}

// Scoped to the row: VirusTotal and the self-hosted relay carry their own
// "Forget" inside their own fold, and dom.walk finds a closed fold's
// contents too.
function forgetButton(list) {
  const row = falconRowEl(list);
  const nodes = row ? dom.walk(row, (n) => n.tagName === "BUTTON" && dom.text(n) === "Forget") : [];
  return nodes[0] || null;
}

test("the row reads 'No Falcon dictionary imported' at rest, and the summary once one is, live off the store", async () => {
  await store.remove(fd.KEY);
  fd._reset();
  await fd.load();

  const list = moduleList({ platform: "splunk", context: "options" });
  await new Promise((r) => setTimeout(r, 0)); // the row's own load().then(refresh)
  assert.match(falconStatus(list), /No Falcon dictionary imported/);

  await fd.importDoc(SAMPLE);
  await new Promise((r) => setTimeout(r, 0)); // falconDictionary.subscribe(refresh)
  assert.match(falconStatus(list), /Falcon dictionary: 6 fields, 2 events, pulled/);

  const forget = forgetButton(list);
  assert.ok(forget, "a Forget button is present once a dictionary is imported");
  dom.fire(forget, "click");
  await new Promise((r) => setTimeout(r, 0));
  assert.match(falconStatus(list), /No Falcon dictionary imported/);
  assert.equal(fd.present(), false);
});
