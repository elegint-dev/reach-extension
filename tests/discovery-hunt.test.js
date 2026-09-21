// discovery.hunt(): a pack hunt's rendered search runs once through the
// relay as it stands, with open job bounds since the window is inside the
// text; the rows come back to the caller, capped, and nothing lands in
// the discovered layer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const sent = [];
let answer = () => ({ rows: [] });
globalThis.chrome = {
  runtime: {
    id: "test-extension",
    lastError: null,
    sendMessage(msg, cb) {
      sent.push(msg);
      Promise.resolve().then(() => cb({ ok: true, ...answer(msg) }));
    },
  },
};

const layer = await import("../app/lib/layer.js");
const discovery = await import("../app/lib/discovery.js");
const ROWS = JSON.parse(await readFile(new URL("./fixtures/hunt-rows.json", import.meta.url), "utf8"));
const ORIGIN = "https://splunk.test";
const SPL = "search index=main sourcetype=crowdstrike:events:sensor earliest=-7d event_platform=Mac | stats count by aid";

test("the search goes to the origin verbatim with open bounds and the rows come back untouched; the layer stays empty", async () => {
  answer = () => ({ rows: ROWS, messages: [{ type: "INFO", text: "x" }] });
  const r = await discovery.hunt(ORIGIN, `${SPL}\n`);
  assert.deepEqual(sent.at(-1), { type: "reach:discover:run", origin: ORIGIN, spl: SPL, earliest: "0", latest: "now", app: "search" });
  assert.deepEqual(r.rows, ROWS);
  assert.equal(r.truncated, false);
  assert.deepEqual(r.messages, [{ type: "INFO", text: "x" }]);
  assert.deepEqual(await layer.readAll(), {});
});

test("more rows than the cap come back cut and flagged; an empty search never leaves the page; a relay error surfaces", async () => {
  answer = () => ({ rows: Array.from({ length: discovery.HUNT_MAX_ROWS + 5 }, (_, i) => ({ n: i })) });
  const r = await discovery.hunt(ORIGIN, SPL, { timeoutMs: 5000 });
  assert.equal(r.rows.length, discovery.HUNT_MAX_ROWS);
  assert.equal(r.truncated, true);
  assert.equal(sent.at(-1).timeoutMs, 5000);
  const before = sent.length;
  await assert.rejects(() => discovery.hunt(ORIGIN, "   "), /empty/);
  assert.equal(sent.length, before);
  globalThis.chrome.runtime.sendMessage = (msg, cb) => Promise.resolve().then(() => cb({ ok: false, error: "No open Splunk tab" }));
  await assert.rejects(() => discovery.hunt(ORIGIN, SPL), /No open Splunk tab/);
});
