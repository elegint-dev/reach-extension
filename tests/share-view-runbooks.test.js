// The Share page with runbooks (app/views/share.js): the scope line and
// the export sentence count them, Export writes one file with the notes
// and the runbooks in it, Import takes the runbooks out of the same file
// (or a file holding one runbook) and says what happened to them, and
// with the Runbooks module off the file's runbooks are left out and said so.
import "./_splunk.js";
import "./_bundle.js";
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }), confirm: () => true };
const store = await import("../app/lib/store.js");
const modules = await import("../app/lib/modules.js");
const catalogue = await import("../app/lib/catalogue.js");
const rbStore = await import("../app/lib/runbooks-store.js");
const view = await import("../app/views/share.js");
await catalogue.load();
await modules.hydrate();

const edited = JSON.parse(await readFile(new URL("./fixtures/runbook-edited.json", import.meta.url), "utf8"));
const settle = () => new Promise((r) => setTimeout(r, 0));

// URL.createObjectURL and the anchor click that download() drives.
const files = [];
const savedURL = globalThis.URL;
globalThis.URL = Object.assign(function URL(...a) { return new savedURL(...a); }, savedURL, { createObjectURL: (blob) => { files.push(blob); return "blob:x"; }, revokeObjectURL() {} });
globalThis.Blob = class { constructor(parts, opts) { this.text = parts.join(""); this.type = opts && opts.type; } };
dom.Node.prototype.click = function () { dom.fire(this, "click"); };

function open() {
  const navs = [];
  const el = view.render({ catalogue, params: {}, navigate: (r, p) => navs.push([r, p]) });
  document.body.appendChild(el);
  return { el, navs };
}

async function importFile(el, text) {
  const input = el.querySelector(".r-share__file");
  input.files = [{ text: async () => text }];
  const btn = el.querySelector(".r-share__box").querySelectorAll("button").find((b) => dom.text(b) === "Import");
  dom.fire(btn, "click");
  for (let i = 0; i < 10; i++) await settle();
  return el.querySelectorAll("p").find((p) => p.classList.contains("r-secondary") && !p.parentNode.classList.contains("r-section"));
}

beforeEach(async () => {
  document.body.replaceChildren();
  files.length = 0;
  await store.remove(rbStore.KEY);
  rbStore._reset();
  await rbStore.load();
});

test("the scope line counts the runbooks and Export writes the notes and the runbooks as one file", async () => {
  await rbStore.importDoc({ runbooks: [edited] });
  const { el } = open();
  await settle();
  assert.match(dom.text(el.querySelector(".r-scope")), /1 runbook/);
  assert.match(dom.text(el), /with your runbooks \(seeded and edited alike, one per rule\)/);
  const exportBtn = el.querySelector(".r-actions").children[0];
  assert.equal(exportBtn.disabled, false, "one runbook is enough to export");
  dom.fire(exportBtn, "click");
  assert.equal(files.length, 1);
  const doc = JSON.parse(files[0].text);
  assert.equal(doc.format, "reach-catalogue");
  assert.deepEqual(doc.runbooks, [edited]);
  assert.match(dom.text(el), /and 1 runbook\./);
});

test("Import takes the runbooks out of the envelope, or a file holding one runbook, and says what happened to them", async () => {
  const { el, navs } = open();
  await settle();
  const envelope = { ...catalogue.exportUser(), runbooks: [edited, { format: "reach-runbook", version: 1, id: "bad", steps: [] }] };
  const status = await importFile(el, JSON.stringify(envelope));
  assert.match(dom.text(status), /^Imported: bindings 0 added, 0 updated, \d+ skipped; notes .*Runbooks 1 added, 0 updated, 0 skipped\. 1 runbook rejected \(bad: Runbook id "bad" is not a rule key/);
  assert.equal(rbStore.get(edited.id).notes, edited.notes);
  assert.equal(navs.at(-1)[0], "share");

  const { el: el2 } = open();
  await settle();
  const one = await importFile(el2, JSON.stringify({ ...edited, notes: "newer", updated: edited.updated + 1 }));
  assert.equal(dom.text(one), "Runbooks 0 added, 1 updated, 0 skipped.");
  assert.equal(rbStore.get(edited.id).notes, "newer");

  const { el: el3 } = open();
  await settle();
  const bad = await importFile(el3, JSON.stringify({ format: "reach-pack", version: 1 }));
  assert.match(dom.text(bad), /^Not a Reach export/);
});

test("with the Runbooks module off the file's runbooks are left out and the status says so", async () => {
  await modules.setEnabled("runbooks", false);
  try {
    const { el } = open();
    await settle();
    assert.doesNotMatch(dom.text(el.querySelector(".r-scope")), /runbook/);
    const status = await importFile(el, JSON.stringify({ ...catalogue.exportUser(), runbooks: [edited] }));
    assert.match(dom.text(status), /The file's runbooks were left out: the Runbooks module is off\.$/);
    assert.equal(rbStore.has(edited.id), false);
  } finally {
    await modules.setEnabled("runbooks", true);
  }
});

after(() => {
  globalThis.URL = savedURL;
  restore();
});
