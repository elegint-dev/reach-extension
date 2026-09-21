// Sharing runbooks (app/lib/share.js, app/lib/runbooks-store.js exportDoc,
// importDoc): the envelope carries the user layer and the runbooks
// together and splits them back, a runbook round-trips through export and
// import unchanged, merge keeps the newer runbook per rule, replace keeps
// only the file's, a file with one runbook imports on its own, and a
// runbook that fails the checks is rejected with the reason while the
// rest land.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const catalogue = await import("../app/lib/catalogue.js");
const share = await import("../app/lib/share.js");
const rb = await import("../app/lib/runbooks-store.js");
await catalogue.load();

const edited = JSON.parse(await readFile(new URL("./fixtures/runbook-edited.json", import.meta.url), "utf8"));

beforeEach(async () => {
  await store.remove(rb.KEY);
  rb._reset();
  await rb.load();
});

test("the envelope is the catalogue export with a runbooks list on it, and read() splits the two back", () => {
  const cat = catalogue.exportUser();
  const doc = share.build({ catalogue: cat, runbooks: [edited] });
  assert.equal(doc.format, "reach-catalogue");
  assert.equal(doc.version, cat.version);
  assert.deepEqual(doc.runbooks, [edited]);
  assert.notEqual(doc.runbooks[0], edited, "a copy, not the store's object");
  const parts = share.read(JSON.stringify(doc));
  assert.equal("runbooks" in parts.catalogue, false);
  assert.deepEqual(Object.keys(parts.catalogue).sort(), Object.keys(cat).sort());
  assert.deepEqual(parts.runbooks, [edited]);
  assert.equal("runbooks" in share.build({ catalogue: cat, runbooks: [] }), false, "no runbooks, no key");
  assert.deepEqual(share.read({ format: "reach-runbook", version: 1, id: "x" }), { catalogue: null, runbooks: [{ format: "reach-runbook", version: 1, id: "x" }] });
  assert.deepEqual(share.read({ format: "reach-runbooks", version: 1, runbooks: [edited] }), { catalogue: null, runbooks: [edited] });
  assert.deepEqual(share.read({ format: "something-else" }), { catalogue: null, runbooks: null });
  assert.deepEqual(share.read("null"), { catalogue: null, runbooks: null });
});

test("a runbook round-trips through export and import unchanged", async () => {
  const r = await rb.importDoc({ runbooks: [edited] });
  assert.deepEqual(r, { added: 1, updated: 0, kept: 0, rejected: [] });
  const out = rb.exportDoc();
  assert.equal(out.format, "reach-runbooks");
  assert.equal(out.version, 1);
  assert.deepEqual(out.runbooks, [edited]);
  await store.remove(rb.KEY);
  rb._reset();
  await rb.load();
  await rb.importDoc(JSON.stringify(out));
  assert.deepEqual(rb.get(edited.id), edited);
});

test("merge keeps the newer runbook per rule and counts what happened; replace keeps only the file's", async () => {
  await rb.importDoc({ runbooks: [edited] });
  const older = { ...edited, notes: "older", updated: edited.updated - 1 };
  const newer = { ...edited, notes: "newer", updated: edited.updated + 1 };
  const other = { ...edited, id: "escu:id:114c6bfe-9406-11ec-bcce-acde48001122", rule: { platform: "splunk", name: "Other", keys: [] }, title: "Other" };
  assert.deepEqual(await rb.importDoc({ runbooks: [older] }), { added: 0, updated: 0, kept: 1, rejected: [] });
  assert.equal(rb.get(edited.id).notes, edited.notes);
  assert.deepEqual(await rb.importDoc({ runbooks: [newer, other] }), { added: 1, updated: 1, kept: 0, rejected: [] });
  assert.equal(rb.get(edited.id).notes, "newer");
  assert.deepEqual(rb.get(other.id).rule.keys, [{ source: "escu", by: "id", value: "114c6bfe-9406-11ec-bcce-acde48001122" }], "the id itself is a key when the list lacks it");
  assert.deepEqual(await rb.importDoc({ runbooks: [older] }, { mode: "replace" }), { added: 1, updated: 0, kept: 0, rejected: [] });
  assert.deepEqual(rb.list().map((r) => r.id), [edited.id]);
  assert.equal(rb.get(edited.id).notes, "older");
});

test("a runbook that fails the checks is rejected with the reason, and the rest of the file lands", async () => {
  const good = { ...edited };
  const r = await rb.importDoc({
    runbooks: [
      good,
      { format: "reach-runbook", version: 1, id: "not a key", steps: [{ question: "x" }] },
      { format: "reach-runbook", version: 2, id: "escu:id:x", steps: [] },
      { format: "reach-pack", version: 1, id: "escu:id:x" },
      { format: "reach-runbook", version: 1, id: "escu:name:empty", steps: [{ question: "" }, { kind: "pivot" }] },
      "nope",
    ],
  });
  assert.equal(r.added, 1);
  assert.deepEqual(
    r.rejected.map((x) => x.id),
    ["not a key", "escu:id:x", "escu:id:x", "escu:name:empty", "#6"],
  );
  assert.match(r.rejected[0].why, /not a rule key/);
  assert.match(r.rejected[1].why, /version 2 is not 1/);
  assert.match(r.rejected[2].why, /expected format reach-runbook, got "reach-pack"/);
  assert.match(r.rejected[3].why, /no step with a question/);
  assert.match(r.rejected[4].why, /expected an object/);
  await assert.rejects(() => rb.importDoc({ format: "reach-catalogue", version: 2, sourcetypes: {} }), /Not a runbook export/);
});

test("the checks bound what a foreign file can put in the store: text lengths, step count, unsafe parameter names, a bad url", () => {
  const raw = {
    ...edited,
    title: "t".repeat(1000),
    notes: "n".repeat(10_000),
    techniques: ["T1110", "not-a-technique", "T1078.004"],
    seeded_from: { ...edited.seeded_from, url: "javascript:alert(1)" },
    steps: Array.from({ length: 100 }, (_, i) => ({ id: "same", question: `q${i}`, pivot: { packId: "p", edge: "e", binds: { __proto__: "x", value: "dest" } } })),
    benign_when: Array.from({ length: 100 }, (_, i) => `c${i}`),
    origin: "whatever",
  };
  const out = rb.check(raw);
  assert.equal(out.title.length, 300);
  assert.equal(out.notes.length, 4000);
  assert.deepEqual(out.techniques, ["T1110", "T1078.004"]);
  assert.equal(out.seeded_from.url, null);
  assert.equal(out.steps.length, rb.MAX_STEPS);
  assert.equal(new Set(out.steps.map((s) => s.id)).size, rb.MAX_STEPS, "duplicate step ids are made unique");
  assert.deepEqual(Object.keys(out.steps[0].pivot.binds), ["value"]);
  assert.equal(out.benign_when.length, rb.MAX_CONDITIONS);
  assert.equal(out.origin, "seed");
});
