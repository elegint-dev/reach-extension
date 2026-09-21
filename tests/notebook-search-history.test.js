// The notebook page's Search history (N) section (app/views/notebook.js):
// registered between Timeline and Investigations; drawn with no
// investigation open once the log has an entry, and not before; rows
// newest first with the current investigation's own first, each the
// name, where it ran, the shared timestamp, a one-line preview with the
// full text in its title, Re-run through the editor bridge, Copy and
// remove; Clear history empties the document.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { ENTITY_ORDER, heading } from "../app/lib/headings.js";

const restore = dom.install();
const store = await import("../app/lib/store.js");
const modules = await import("../app/lib/modules.js");
const notebook = await import("../app/lib/notebook.js");
const searches = await import("../app/lib/searches.js");
const view = await import("../app/views/notebook.js");
test.after(async () => {
  await new Promise((r) => setTimeout(r, 1000)); // the copy button's flash restores its label before the document goes
  restore();
});

const ctx = { params: {}, navigate() {} };
const settle = () => new Promise((r) => setTimeout(r, 0));
const T = Date.UTC(2026, 8, 20, 9, 30, 0);
const section = (el) => el.querySelectorAll(".r-nb__searches")[0] || null;
const rows = (el) => (section(el) ? section(el).querySelectorAll(".r-nb__search") : []);

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await store.remove(searches.KEY);
  await notebook.load({ force: true });
  await searches.load({ force: true });
  modules.reset();
});

test("the heading is registered as an h2 between Timeline and Investigations", () => {
  assert.equal(heading("search-history", 3), "Search history (3)");
  const i = ENTITY_ORDER.indexOf("search-history");
  assert.equal(ENTITY_ORDER[i - 1], "timeline");
  assert.equal(ENTITY_ORDER[i + 1], "investigations");
});

test("with no investigation and no entry the section is absent; one entry draws it under the empty title block", async () => {
  let el = view.render(ctx);
  await settle();
  assert.equal(section(el), null);
  assert.equal(el.querySelectorAll(".r-title").length, 1, "the empty title block");
  await searches.record({ text: "index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin", platform: "splunk", source: "copy", origin: "pivot", container: "aws:cloudtrail", name: "logins", at: T });
  el = view.render(ctx);
  await settle();
  assert.ok(section(el));
  assert.equal(dom.text(section(el).querySelectorAll("h2")[0]), "Search history (1)");
  assert.equal(notebook.current(), null, "the write started no investigation");
});

test("rows are newest first with the current investigation's own first; each has the name, where it ran, the timestamp, a one-line preview and the actions", async () => {
  await searches.record({ text: "index=main a=1", platform: "splunk", source: "copy", origin: "pivot", container: "aws:cloudtrail", name: "first", at: T });
  const inv = await notebook.start({ title: "the case" });
  const long = `index=main sourcetype=aws:cloudtrail\n  | search eventName=ConsoleLogin ${"x".repeat(200)}\n| stats count by userIdentity.arn`;
  await searches.record({ text: long, platform: "splunk", source: "run", origin: "pivot", container: "aws:cloudtrail", field: "eventName", value: "ConsoleLogin", name: "logins by this identity", at: T + 60_000 });
  await notebook.start({ title: "another" });
  await searches.record({ text: "SigninLogs | take 10", platform: "sentinel", source: "open", origin: "runbook", container: "SigninLogs", name: "sign-ins", at: T + 120_000 });
  await notebook.setCurrent(inv.id);
  const el = view.render(ctx);
  await settle();
  assert.equal(dom.text(section(el).querySelectorAll("h2")[0]), "Search history (3)");
  const list = rows(el);
  assert.equal(list.length, 3);
  assert.deepEqual(
    list.map((r) => dom.text(r.querySelectorAll(".r-nb__sname")[0])),
    ["logins by this identity", "sign-ins", "first"],
    "this investigation's entry first, then the rest newest first",
  );
  const mine = list[0];
  assert.ok(mine.className.includes("r-nb__search--mine"));
  assert.equal(dom.text(mine.querySelectorAll(".r-nb__time")[0]), "2026-09-20 09:31:00 UTC");
  assert.equal(dom.text(mine.querySelectorAll(".r-nb__kind")[0]), "SPL");
  assert.equal(dom.text(list[1].querySelectorAll(".r-nb__kind")[0]), "KQL");
  assert.match(dom.text(mine.querySelectorAll(".r-nb__text")[0]), /on aws:cloudtrail · from pivot · ran/);
  const code = mine.querySelectorAll(".r-nb__query")[0];
  const shown = dom.text(code);
  assert.ok(!shown.includes("\n"), "one line");
  assert.equal(shown.length, view.PREVIEW_CHARS);
  assert.ok(shown.endsWith("…"));
  assert.equal(code.getAttribute("title"), long, "the full text in the title");
  assert.deepEqual(mine.querySelectorAll(".r-nb__act").map(dom.text), ["Re-run", "Copy", "×"]);
  assert.equal(section(el).querySelectorAll(".r-nb__headacts button").map(dom.text).join(), "Clear history");
});

test("Re-run hands the text to the editor bridge and writes a run entry; remove drops a row; Clear history empties the document", async () => {
  await searches.record({ text: "index=main a=1", platform: "splunk", source: "copy", origin: "pivot", at: T });
  await searches.record({ text: "index=main b=2", platform: "splunk", source: "copy", origin: "pivot", at: T + 1 });
  const el = view.render(ctx);
  await settle();
  const older = rows(el)[1];
  assert.equal(dom.text(older.querySelectorAll(".r-nb__query")[0]), "index=main a=1");
  const rerun = older.querySelectorAll(".r-nb__act")[0];
  dom.fire(rerun, "click", { currentTarget: rerun });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(searches.count(), 3, "the re-run is a new hand-off of an older text");
  const [newest] = searches.list();
  assert.equal(newest.text, "index=main a=1");
  assert.equal(newest.source, "run");
  assert.match(dom.text(el.querySelectorAll(".r-nb__status")[0]), /clipboard|search bar/i, "the bridge's notice lands on the status line");
  await settle();
  const rm = rows(el)[0].querySelectorAll(".r-nb__act")[2];
  dom.fire(rm, "click", { currentTarget: rm });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(searches.count(), 2);
  globalThis.window = { confirm: () => true };
  const clear = section(el).querySelectorAll(".r-nb__headacts button")[0];
  dom.fire(clear, "click", { currentTarget: clear });
  await new Promise((r) => setTimeout(r, 20));
  delete globalThis.window;
  assert.equal(searches.count(), 0);
  await settle();
  assert.equal(rows(el).length, 0);
});
