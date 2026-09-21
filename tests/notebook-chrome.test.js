// The notebook on store.js's chrome.storage.local backend, the one the
// extension runs on: a record lands under reach.notebook, one change event
// per write (through onChanged, not a second notify), and a write from
// another context (a popup on the Splunk page) is adopted by this one. The
// fake is installed before store.js loads, so this file runs alone.
import { test } from "node:test";
import assert from "node:assert/strict";

import { fakeChrome } from "./_chrome.js";

const fake = fakeChrome();
fake.install();
const { local } = fake;

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
assert.equal(store.backend(), "chrome");

const from = { platform: "splunk", container: "aws:cloudtrail", scope: "main", event: { id: "ev-1", time: 1_758_204_115_000 }, search: { text: "index=main sourcetype=aws:cloudtrail", sid: "1758204120.1" } };

test("chrome backend: a record is written under reach.notebook, one change event per write", async () => {
  const events = [];
  const off = notebook.subscribe((ev) => events.push(ev.type));
  await notebook.load();
  const e = await notebook.record({ field: "user", value: "bob", from, reason: "on the alert" });
  assert.ok(local.has("reach.notebook"));
  const raw = local.get("reach.notebook");
  assert.equal(raw.investigations[0].entries[0].id, e.id);
  assert.equal(raw.current, raw.investigations[0].id);
  assert.deepEqual(events, ["change"], "onChanged notifies once; no second notify from the write");
  await notebook.note("a note", { on: e.id });
  assert.deepEqual(events, ["change", "change"]);
  off();
  assert.equal(notebook.current().entries.length, 2);
});

test("chrome backend: a write from another context is adopted, a damaged one is not", async () => {
  const mine = notebook.current();
  const other = local.get("reach.notebook");
  other.investigations[0].entries.push({ id: "from-popup", kind: "pin", at: 1, field: "ip", value: "203.0.113.9", from });
  other.investigations[0].title = "Named in the popup";
  await chrome.storage.local.set({ "reach.notebook": other });
  const now = notebook.current();
  assert.equal(now.id, mine.id);
  assert.equal(now.title, "Named in the popup");
  assert.deepEqual(now.entries.map((x) => x.id).slice(-1), ["from-popup"]);

  const events = [];
  const off = notebook.subscribe((ev) => events.push(ev));
  await chrome.storage.local.set({ "reach.notebook": { v: 1, current: "x", investigations: [{ id: "__proto__", entries: [] }, { id: "kept", entries: [{ id: "n", kind: "note", text: "t", polluted: 1 }] }] } });
  assert.deepEqual(notebook.list().map((i) => i.id), ["kept"]);
  assert.equal(notebook.currentId(), null);
  assert.equal(notebook.get("kept").entries[0].polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.deepEqual(events.map((ev) => ev.type), ["change"]);
  off();

  await chrome.storage.local.remove("reach.notebook");
  assert.deepEqual(notebook.list(), []);
  const again = await notebook.record({ field: "user", value: "carol", from });
  assert.equal(local.get("reach.notebook").investigations[0].entries[0].id, again.id);
  assert.match(notebook.exportText(), /Pinned user = carol on aws:cloudtrail \(index main, Splunk\) from event ev-1 at/);
});
