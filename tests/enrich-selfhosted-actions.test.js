// The self-hosted source's MISP write actions (app/lib/enrich/selfhosted.js
// call()): a hit carries "Record sighting", a miss "Propose to MISP", each
// only while the worker's status says writes are on, each one message per
// click through the relay, and the type a value is proposed as follows its
// kind. Fixtures are the answers a MISP 2.5.47 gave when recorded.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as selfhosted from "../app/lib/enrich/selfhosted.js";

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";

// A fake worker: lookup and status answers as given, every write logged.
function worker({ lookup, writes = true, write = () => ({ ok: true, status: 200, data: {} }) }) {
  const sent = [];
  const ask = async (msg) => {
    sent.push(msg);
    if (msg.type === "reach:selfhosted:status") return { ok: true, configured: true, permitted: true, provider: "misp", origin: "https://misp.example.org", writes };
    if (msg.type === "reach:selfhosted:lookup") return typeof lookup === "function" ? lookup(msg) : lookup;
    if (msg.type === "reach:selfhosted:write") return write(msg);
    return null;
  };
  return { ask, sent };
}
const ctx = (w) => ({ provider: "misp", origin: "https://misp.example.org", ask: w.ask });

test("mispTypeFor: a hash by digest length, ip as ip-dst, domain, url, cve as vulnerability, nothing else", () => {
  assert.equal(selfhosted.mispTypeFor("hash", "d41d8cd98f00b204e9800998ecf8427e"), "md5");
  assert.equal(selfhosted.mispTypeFor("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1");
  assert.equal(selfhosted.mispTypeFor("hash", HASH), "sha256");
  assert.equal(selfhosted.mispTypeFor("hash", "abc"), null);
  assert.equal(selfhosted.mispTypeFor("ip", "8.8.8.8"), "ip-dst");
  assert.equal(selfhosted.mispTypeFor("domain", "evil.example"), "domain");
  assert.equal(selfhosted.mispTypeFor("url", "https://evil.example/x"), "url");
  assert.equal(selfhosted.mispTypeFor("cve", "CVE-2021-44228"), "vulnerability");
  assert.equal(selfhosted.mispTypeFor("technique", "T1003"), null);
});

test("summarize: a restSearch answer with sightings adds one sightings line with the count across the matched rows", () => {
  const lines = selfhosted.summarize("misp", fixture("misp-restsearch-sightings.json"));
  assert.match(lines[0], /^1 matching attribute across 1 event\./);
  assert.equal(lines.at(-1), "sightings: 2");
  assert.ok(!selfhosted.summarize("misp", fixture("misp-restsearch-hit.json")).some((l) => l.startsWith("sightings")), "no sightings line when the rows carry no Sighting array");
});

test("mispHits: the matched attributes' ids, types and sighting counts; a row without a numeric id is dropped", () => {
  assert.deepEqual(selfhosted.mispHits(fixture("misp-restsearch-sightings.json")), [{ id: "1", type: "sha256", eventId: "1", sightings: 2 }]);
  assert.deepEqual(selfhosted.mispHits({ response: { Attribute: [{ id: "x", type: "md5" }, null] } }), []);
  assert.deepEqual(selfhosted.mispHits(fixture("misp-restsearch-miss.json")), []);
});

test("eventChoices: the recent page as id and label, newest first as MISP sorted it", () => {
  const choices = selfhosted.eventChoices(fixture("misp-events-index.json"));
  assert.deepEqual(choices.map((c) => c.id), ["2", "1"]);
  assert.equal(choices[0].label, "Reach write-back check (2026-09-20), unpublished");
  assert.equal(choices[1].label, "Reach demo: T1003.001 capture (2026-09-19)");
  assert.deepEqual(selfhosted.eventChoices({ nope: true }), []);
});

test("call: a hit carries Record sighting and a miss Propose to MISP, only while the worker's status says writes are on", async () => {
  const on = worker({ lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-sightings.json") } });
  const hit = await selfhosted.call(HASH, ctx(on));
  assert.equal(hit.status, "ok");
  assert.deepEqual(hit.actions.map((a) => [a.id, a.label, a.held === true]), [["sighting", "Record sighting", false]]);

  const miss = await selfhosted.call("evil-c2.example.net", { ...ctx(worker({ lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-miss.json") } })), fieldName: "query" });
  assert.equal(miss.status, "empty");
  assert.deepEqual(miss.actions.map((a) => [a.id, a.label, a.held === true]), [["propose", "Propose to MISP", true]]);

  const off = worker({ lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-sightings.json") }, writes: false });
  const gated = await selfhosted.call(HASH, ctx(off));
  assert.equal(gated.status, "ok");
  assert.equal(gated.actions, undefined);
  assert.ok(off.sent.every((m) => m.type !== "reach:selfhosted:write"), "a lookup never writes");
});

test("call: an IntelOwl answer carries no action, whatever the toggle says", async () => {
  const w = worker({ lookup: { ok: true, status: 200, provider: "intelowl", data: fixture("intelowl-jobs-hit.json") } });
  const res = await selfhosted.call(HASH, { ...ctx(w), provider: "intelowl" });
  assert.equal(res.status, "ok");
  assert.equal(res.actions, undefined);
});

test("Record sighting sends one sighting write per matched attribute, then looks the value up again and leads with the new count", async () => {
  let sightings = 2;
  const w = worker({
    lookup: () => {
      const data = fixture("misp-restsearch-sightings.json");
      const row = data.response.Attribute[0];
      row.Sighting = Array.from({ length: sightings }, (_, i) => ({ id: String(i + 1), source: i ? "Reach" : "" }));
      return { ok: true, status: 200, provider: "misp", data };
    },
    write: (msg) => {
      assert.deepEqual(msg, { type: "reach:selfhosted:write", op: "sighting", attributeId: "1" });
      sightings += 1;
      return { ok: true, status: 200, provider: "misp", data: fixture("misp-sighting-add.json") };
    },
  });
  const first = await selfhosted.call(HASH, ctx(w));
  assert.equal(first.lines.at(-1), "sightings: 2");
  const after = await first.actions[0].run({});
  assert.equal(after.status, "ok");
  assert.equal(after.lines[0], "Sighting recorded (source: Reach).");
  assert.equal(after.lines.at(-1), "sightings: 3");
  assert.equal(w.sent.filter((m) => m.type === "reach:selfhosted:write").length, 1);
  assert.deepEqual(after.actions.map((a) => a.id), ["sighting"], "the refreshed row offers the action again");
});

test("Record sighting on a refused write shows the worker's sentence and sends nothing more", async () => {
  const w = worker({ lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-sightings.json") }, write: () => ({ ok: false, status: 0, reason: "writes off", error: "Writes to MISP are off." }) });
  const first = await selfhosted.call(HASH, ctx(w));
  const after = await first.actions[0].run({});
  assert.deepEqual(after, { status: "error", lines: ["Writes to MISP are off."] });
  assert.equal(w.sent.filter((m) => m.type === "reach:selfhosted:lookup").length, 1);
});

test("Propose to MISP lists recent events first, then on the pick sends one attribute write with the kind, the value and the Hold reason", async () => {
  const w = worker({
    lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-miss.json") },
    write: (msg) => (msg.op === "events" ? { ok: true, status: 200, provider: "misp", data: fixture("misp-events-index.json") } : { ok: true, status: 200, provider: "misp", data: fixture("misp-attribute-add.json") }),
  });
  const miss = await selfhosted.call("proposed-by-reach.example.net", { ...ctx(w), fieldName: "query" });
  const step = await miss.actions[0].run({ reason: "held: seen in DNS from the T1003.001 host" });
  assert.equal(step.status, "choose");
  assert.equal(step.prompt, "Propose to which event?");
  assert.deepEqual(step.choices.map((c) => c.id), ["2", "1"]);
  assert.equal(w.sent.filter((m) => m.type === "reach:selfhosted:write").length, 1, "listing events is the only write message so far");

  const done = await step.submit("2");
  assert.equal(done.status, "ok");
  assert.equal(done.lines[0], 'Proposed to "Reach write-back check (2026-09-20), unpublished" as domain (attribute 8, to_ids false).');
  const writes = w.sent.filter((m) => m.type === "reach:selfhosted:write");
  assert.deepEqual(writes.at(-1), { type: "reach:selfhosted:write", op: "attribute", eventId: "2", kind: "domain", id: "proposed-by-reach.example.net", comment: "held: seen in DNS from the T1003.001 host" });

  const stray = await step.submit("99");
  assert.equal(stray.status, "error");
  assert.equal(writes.length, w.sent.filter((m) => m.type === "reach:selfhosted:write").length, "an id outside the listed page sends nothing");
});

test("Propose to MISP with no events to pick from says so and sends no attribute", async () => {
  const w = worker({ lookup: { ok: true, status: 200, provider: "misp", data: fixture("misp-restsearch-miss.json") }, write: () => ({ ok: true, status: 200, provider: "misp", data: [] }) });
  const miss = await selfhosted.call("8.8.8.8", ctx(w));
  const step = await miss.actions[0].run({ reason: "" });
  assert.equal(step.status, "empty");
  assert.equal(w.sent.filter((m) => m.type === "reach:selfhosted:write" && m.op === "attribute").length, 0);
});

test("Record sighting on a value matched in two events sends one sighting per attribute, in order, and stops at the first refusal", async () => {
  const two = () => {
    const data = fixture("misp-restsearch-sightings.json");
    const a = data.response.Attribute[0];
    data.response.Attribute = [a, { ...a, id: "5", event_id: "2", Sighting: [] }];
    return { ok: true, status: 200, provider: "misp", data };
  };
  const w = worker({ lookup: two, write: () => ({ ok: true, status: 200, provider: "misp", data: fixture("misp-sighting-add.json") }) });
  const first = await selfhosted.call(HASH, ctx(w));
  assert.match(first.lines[0], /^2 matching attributes across 2 events\./);
  assert.match(first.actions[0].title, /2 writes, on this click/);
  await first.actions[0].run({});
  assert.deepEqual(w.sent.filter((m) => m.type === "reach:selfhosted:write").map((m) => m.attributeId), ["1", "5"]);

  let calls = 0;
  const failing = worker({ lookup: two, write: () => (++calls === 1 ? { ok: true, status: 200, provider: "misp", data: fixture("misp-sighting-add.json") } : { ok: false, status: 403, error: "https://misp.example.org returned 403." }) });
  const res = await (await selfhosted.call(HASH, ctx(failing))).actions[0].run({});
  assert.equal(res.status, "error");
  assert.equal(calls, 2, "the second write's refusal ends the run");
});
