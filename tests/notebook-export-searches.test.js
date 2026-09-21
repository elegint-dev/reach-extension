// The Markdown and plain-text exports carry the current investigation's
// searches under their own heading, after Open threads and before the
// values appendix, one line each with the time, language, control, name,
// container and the text; nothing when the investigation has none, so the
// frozen export fixture stands; never inside the machine copy, so the
// import round-trip is unchanged.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const searches = await import("../app/lib/searches.js");
const md = await import("../app/lib/notebook-md.js");

const T = Date.UTC(2026, 8, 20, 9, 30, 0);
const from = { platform: "splunk", container: "aws:cloudtrail", scope: "main", search: { text: "index=main", sid: "1" } };

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await store.remove(searches.KEY);
  await notebook.load({ force: true });
  await searches.load({ force: true });
});

test("the export lists this investigation's searches under Search history, between Open threads and the appendix, and leaves them out of the machine copy", async () => {
  const inv = await notebook.start({ title: "the case" });
  await notebook.record({ field: "user", value: "bob", from, reason: "on the alert" });
  await searches.record({ text: 'index=main sourcetype=aws:cloudtrail user="bob"\n| stats count by eventName', platform: "splunk", source: "copy", origin: "pivot", container: "aws:cloudtrail", name: "what bob did", at: T });
  await searches.record({ text: "SigninLogs | where UserPrincipalName == 'bob'", platform: "sentinel", source: "run", origin: "runbook", ran: true, sid: "1700000000.3", at: T + 60_000 });
  const other = await notebook.start({ title: "another" });
  await searches.record({ text: "index=main elsewhere=1", platform: "splunk", source: "copy", at: T + 120_000 });
  await notebook.setCurrent(inv.id);

  const text = notebook.exportMarkdown(inv.id);
  const lines = text.split("\n");
  const at = (s) => lines.indexOf(s);
  assert.ok(at("## Search history") > at("## Open threads"));
  assert.ok(at("## Search history") < at("## Appendix: values"));
  assert.equal(lines[at("## Search history") + 2], "- 2026-09-20 09:30:00 UTC · SPL · copy · what bob did · on aws:cloudtrail: `index=main sourcetype=aws:cloudtrail user=\"bob\" | stats count by eventName`");
  assert.equal(lines[at("## Search history") + 3], "- 2026-09-20 09:31:00 UTC · KQL · run · sid 1700000000.3: `SigninLogs | where UserPrincipalName == 'bob'`");
  assert.ok(!text.includes("elsewhere=1"), "another investigation's search stays out");
  const machine = text.slice(text.indexOf("```json"));
  assert.ok(!machine.includes("what bob did"), "the machine copy carries the investigation only");
  const back = md.parse(text);
  assert.equal(back.entries.length, 1);

  const plain = notebook.exportText(inv.id);
  assert.ok(plain.includes("\nSEARCH HISTORY\n\n- 2026-09-20 09:30:00 UTC · SPL · copy · what bob did · on aws:cloudtrail: index=main sourcetype=aws:cloudtrail user=\"bob\" | stats count by eventName\n"));
  assert.ok(!plain.includes("SEARCH HISTORY\n\n- 2026-09-20 09:32"));

  const none = notebook.exportMarkdown(other.id, { thread: null });
  assert.ok(none.includes("## Search history"), "the other investigation lists its own one");
  assert.ok(none.includes("elsewhere=1"));
});

test("with no search the heading is absent, in the Markdown, the plain text and a one-thread export", async () => {
  const inv = await notebook.start({ title: "quiet" });
  const pin = await notebook.record({ field: "user", value: "bob", from, reason: "on the alert" });
  assert.ok(!notebook.exportMarkdown(inv.id).includes("## Search history"));
  assert.ok(!notebook.exportText(inv.id).includes("SEARCH HISTORY"));
  await searches.record({ text: "index=main a=1", platform: "splunk", at: T });
  assert.ok(notebook.exportMarkdown(inv.id).includes("## Search history"));
  assert.ok(!notebook.exportMarkdown(inv.id, { thread: pin.id }).includes("## Search history"), "a thread's export is the thread alone");
  assert.ok(!md.toMarkdown(inv).includes("## Search history"), "the pure writer adds nothing unasked");
});
