// The search history document (app/lib/searches.js): one entry per
// hand-off with its control, surface and where it came from; the newest
// entry absorbs a repeat of its own text and nothing older does; the
// current investigation's id is stamped without the notebook being
// touched; at most 200 entries and 500,000 bytes, oldest out first; the
// list reads newest first with the investigation's own entries first.
// Runs on store.js's memory backend.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const searches = await import("../app/lib/searches.js");
const notebook = await import("../app/lib/notebook.js");
assert.equal(store.backend(), "memory");

const T = Date.UTC(2026, 8, 20, 10, 0, 0);

beforeEach(async () => {
  await store.remove(searches.KEY);
  await store.remove(notebook.KEY);
  await searches.load({ force: true });
  await notebook.load({ force: true });
});

test("a record carries the control, the surface, the language of its platform, the container, field, value and name, and ran false unless said", async () => {
  const e = await searches.record({ text: "  index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin  ", platform: "splunk", source: "copy", origin: "pivot", container: "aws:cloudtrail", field: "eventName", value: "ConsoleLogin", name: "logins by this user", at: T });
  assert.equal(e.text, "index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin");
  assert.equal(e.platform, "splunk");
  assert.equal(e.language, "spl");
  assert.equal(e.source, "copy");
  assert.equal(e.origin, "pivot");
  assert.equal(e.ran, false);
  assert.equal(e.container, "aws:cloudtrail");
  assert.equal(e.field, "eventName");
  assert.equal(e.value, "ConsoleLogin");
  assert.equal(e.name, "logins by this user");
  assert.equal(e.at, T);
  assert.equal(e.investigation, undefined, "no investigation is current");
  assert.match(e.id, /^s_/);
  const stored = await store.get(searches.KEY);
  assert.deepEqual(stored, { v: 1, entries: [e] });
  const k = await searches.record({ text: "SigninLogs | take 10", platform: "sentinel", source: "open", origin: "pivot", ran: true, sid: "1700000000.3", at: T + 1 });
  assert.equal(k.language, "kql");
  assert.equal(k.ran, true);
  assert.equal(k.sid, "1700000000.3");
  assert.equal(await searches.record({ text: "   " }), null, "an empty text writes nothing");
  assert.equal(searches.count(), 2);
});

test("a repeat of the newest entry's text moves that entry; a repeat of an older text is a new entry (three pages, one copy each, then two repeats)", async () => {
  const texts = ["index=main a=1", "index=main b=2", "index=main c=3"];
  for (const [i, text] of texts.entries()) await searches.record({ text, platform: "splunk", source: "copy", at: T + i });
  assert.equal(searches.count(), 3);
  const again = await searches.record({ text: texts[2], platform: "splunk", source: "run", ran: true, sid: "1.2", at: T + 10 });
  assert.equal(searches.count(), 3, "a second copy on the third page's row leaves the count at three");
  assert.equal(again.at, T + 10);
  assert.equal(again.source, "run");
  assert.equal(again.ran, true);
  assert.equal(again.sid, "1.2");
  await searches.record({ text: texts[0], platform: "splunk", source: "copy", at: T + 11 });
  assert.equal(searches.count(), 4, "a second copy on the first page's row makes it four");
  assert.deepEqual(
    searches.list().map((e) => e.text),
    [texts[0], texts[2], texts[1], texts[0]],
    "newest first",
  );
});

test("a write stamps the current investigation's id, never starts one and leaves the notebook document byte for byte", async () => {
  const none = await searches.record({ text: "index=main x=1", at: T });
  assert.equal(none.investigation, undefined);
  assert.equal(await store.get(notebook.KEY), undefined, "no investigation was started");
  const inv = await notebook.start({ title: "the one" });
  const before = JSON.stringify(await store.get(notebook.KEY));
  const e = await searches.record({ text: "index=main y=2", at: T + 1 });
  assert.equal(e.investigation, inv.id);
  assert.equal(JSON.stringify(await store.get(notebook.KEY)), before, "the notebook did not change");
  assert.deepEqual(searches.forInvestigation(inv.id).map((x) => x.text), ["index=main y=2"]);
  const other = await notebook.start({ title: "another" });
  await searches.record({ text: "index=main z=3", at: T + 2 });
  assert.deepEqual(
    searches.list({ investigation: inv.id }).map((x) => x.text),
    ["index=main y=2", "index=main z=3", "index=main x=1"],
    "the named investigation's entries first, then the rest newest first",
  );
  assert.deepEqual(searches.list({ investigation: other.id }).map((x) => x.text), ["index=main z=3", "index=main y=2", "index=main x=1"]);
});

test("at most 200 entries are kept, the oldest out first", async () => {
  for (let i = 0; i < 205; i++) await searches.record({ text: `index=main n=${i}`, at: T + i });
  assert.equal(searches.count(), searches.MAX_ENTRIES);
  const list = searches.list();
  assert.equal(list[0].text, "index=main n=204");
  assert.equal(list[list.length - 1].text, "index=main n=5");
});

test("past the byte budget the oldest entries are dropped until the document fits, and the write says so once", async () => {
  const big = "x".repeat(20_000);
  const events = [];
  const off = searches.subscribe((ev) => events.push(ev));
  for (let i = 0; i < 30; i++) await searches.record({ text: `search ${i} ${big}`, at: T + i });
  off();
  assert.ok(searches.bytes() <= searches.MAX_BYTES, `${searches.bytes()} bytes`);
  assert.ok(searches.count() < 30 && searches.count() > 0);
  assert.equal(searches.list()[0].text.slice(0, 9), "search 29", "the newest stays");
  const pruned = events.filter((ev) => ev.type === "pruned");
  assert.ok(pruned.length >= 1);
  assert.match(pruned[0].warning, /search history was over its 500 KB bound/);
});

test("remove drops one entry, clear drops them all, and a damaged stored value adopts to an empty document", async () => {
  const a = await searches.record({ text: "index=main a=1", at: T });
  await searches.record({ text: "index=main b=2", at: T + 1 });
  assert.equal((await searches.remove(a.id)).id, a.id);
  assert.equal(await searches.remove("nope"), null);
  assert.equal(searches.count(), 1);
  assert.equal(await searches.clear(), 1);
  assert.equal(searches.count(), 0);
  assert.equal(await searches.clear(), 0);
  await store.set(searches.KEY, { v: 1, entries: [{ id: "ok", text: "index=main", at: T, source: "nonsense", origin: "elsewhere", platform: "kql" }, { text: "" }, "junk", { id: "ok", text: "dup", at: T }] });
  const d = await searches.load({ force: true });
  assert.equal(d.entries.length, 1);
  assert.deepEqual(d.entries[0], { id: "ok", at: T, platform: "sentinel", language: "kql", text: "index=main", source: "copy", origin: "pivot", ran: false });
  await store.set(searches.KEY, "garbage");
  assert.deepEqual(await searches.load({ force: true }), { v: 1, entries: [] });
});
