// A failure named only at the end of a full discovery told nobody which
// sourcetype failed until the run finished (app/lib/discovery-sweep.js
// keeps st.errors as it goes; app/views/discover-splunk.js only drew them
// in the finished line). This exercises the fix: a failures list under the
// progress line, drawn live off sweep state, one Retry per row calling the
// same function the row's own button uses.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as layer from "../app/lib/layer.js";
import * as store from "../app/lib/store.js";
import * as sweep from "../app/lib/discovery-sweep.js";
import { render } from "../app/views/discover-splunk.js";

dom.install();
await catalogue.load();

const ORIGIN = "https://splunk.test";

let answer = () => ({ rows: [] });
const fake = fakeChrome({ answer: (msg) => answer(msg), storage: false });
fake.install();
const calls = fake.messages;

const inventoryRows = (names) => names.map((st) => ({ index: "main", sourcetype: st, count: "10", first_seen: "1700000000", last_seen: "1700000100" }));
const summary = (fields) => [{ field: "reach_total", count: "100" }, ...fields.map(([field, count]) => ({ field, count: String(count), distinct_count: "3", is_exact: "1", numeric_count: "0", values: "[]" }))];

// A stub Splunk: b:feed's profile fails once, then succeeds (Retry).
function splunk({ sourcetypes = [], failProfileOnce = [] } = {}) {
  const failed = new Set();
  return (msg) => {
    if (msg.type === "reach:discover:run") {
      const spl = msg.spl;
      if (/^\| tstats/.test(spl)) return { rows: inventoryRows(sourcetypes) };
      if (/fieldsummary/.test(spl)) {
        const st = /sourcetype=(\S+)/.exec(spl)[1];
        if (failProfileOnce.includes(st) && !failed.has(st)) {
          failed.add(st);
          throw new Error("No open Splunk tab on https://splunk.test. Open one (and keep it open) so the request can run with your session.");
        }
        return { rows: summary([["user", 90]]) };
      }
      if (/stats count by/.test(spl)) return { rows: [] };
      if (/inputlookup/.test(spl)) return { rows: [] };
      throw new Error(`unexpected SPL: ${spl}`);
    }
    if (msg.type === "reach:discover:rest") return { entries: [] };
    if (msg.type === "reach:discover:tabs") return { origins: [{ origin: ORIGIN, tabs: 1 }] };
    throw new Error(`unexpected message ${msg.type}`);
  };
}

const spls = () => calls.filter((m) => m.type === "reach:discover:run").map((m) => m.spl);

beforeEach(async () => {
  calls.length = 0;
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
  await store.set(sweep.KEY, {});
});

function ctxFor() {
  return { params: { env: ORIGIN }, catalogue, navigate() {}, href: () => "#", setUrl() {}, goBack() {} };
}

function failureRows(el) {
  return el.querySelectorAll(".r-discover__failure-list li");
}

test("an error pushed mid-run renders in the failures list before the sweep ends", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed"], failProfileOnce: ["b:feed"] });
  const ctx = ctxFor();
  const el = render(ctx);
  await el.afterMount();
  // discovery-sweep.js's notify() catches whatever a listener throws (so
  // one broken subscriber cannot break the sweep), so an assertion made
  // inside the subscribe callback would be swallowed silently; capture
  // what the DOM showed instead and assert on it once the sweep is done.
  let midRunRowCount = null;
  let midRunRowText = "";
  const off = sweep.subscribe((s) => {
    if (s.running && s.errors.length && midRunRowCount === null) {
      midRunRowCount = failureRows(el).length;
      midRunRowText = failureRows(el).map((r) => dom.text(r)).join(" | ");
    }
  });
  await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  off();
  assert.equal(midRunRowCount, 1, "the row was in the DOM while the sweep was still running");
  assert.match(midRunRowText, /b:feed/);
  assert.match(midRunRowText, /profile/);
});

test("the failures list survives the run finishing, and the finished line keeps its summary", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed"], failProfileOnce: ["b:feed"] });
  const ctx = ctxFor();
  const el = render(ctx);
  await el.afterMount();
  await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(failureRows(el).length, 1);
  const progress = el.querySelectorAll("p[aria-live]").find((p) => /Full discovery/.test(dom.text(p)));
  assert.match(dom.text(progress), /Full discovery finished, 2 of 2, 0 skipped, 1 failed\./);
  assert.doesNotMatch(dom.text(progress), /b:feed \(profile\)/, "the itemised text moved to the failures list");
});

test("a relay error's text shows in the failures list as is", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed"], failProfileOnce: ["b:feed"] });
  const ctx = ctxFor();
  const el = render(ctx);
  await el.afterMount();
  await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  const row = failureRows(el)[0];
  assert.match(dom.text(row), /No open Splunk tab on https:\/\/splunk\.test\. Open one \(and keep it open\) so the request can run with your session\./);
});

test("Retry on a failed row calls the same profile function the row's own button uses, with the row's arguments", async () => {
  answer = splunk({ sourcetypes: ["a:feed", "b:feed"], failProfileOnce: ["b:feed"] });
  const ctx = ctxFor();
  const el = render(ctx);
  await el.afterMount();
  await sweep.start(ORIGIN, { index: "*", earliest: "-7d" });
  assert.equal(failureRows(el).length, 1);
  calls.length = 0;
  const retryBtn = failureRows(el)[0].querySelectorAll("button")[0];
  dom.fire(retryBtn, "click");
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  const profileCalls = spls().filter((s) => /fieldsummary/.test(s));
  assert.equal(profileCalls.length, 1, "retry re-ran exactly one profile search");
  assert.match(profileCalls[0], /sourcetype=b:feed/, "on the failed row's own sourcetype");
});
