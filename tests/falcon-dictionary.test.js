// app/lib/falcon-dictionary.js: importing the analyst's own FDR schema
// pull, forgetting it, and what a field or event reads back once it is in.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const store = await import("../app/lib/store.js");
const fd = await import("../app/lib/falcon-dictionary.js");

const SAMPLE = JSON.parse(await readFile(new URL("./fixtures/falcon-dictionary.sample.json", import.meta.url), "utf8"));

beforeEach(async () => {
  await store.remove(fd.KEY);
  fd._reset();
  await fd.load();
});

test("check() refuses a document naming the wrong version, source, or a missing map", () => {
  assert.throws(() => fd.check({ ...SAMPLE, version: 2 }), /version 2 is not|expected version/);
  assert.throws(() => fd.check({ ...SAMPLE, source: "something-else" }), /expected source/);
  const { fields, ...noFields } = SAMPLE;
  assert.throws(() => fd.check(noFields), /no fields map/);
  const { events, ...noEvents } = SAMPLE;
  assert.throws(() => fd.check(noEvents), /no events map/);
  assert.throws(() => fd.check(null), /expected a JSON object/);
});

test("importDoc() stores the stripped document and returns its counts", async () => {
  const counts = await fd.importDoc(SAMPLE);
  assert.equal(counts.fields, 6);
  assert.equal(counts.events, 2); // AidMaster and LzmaFileWritten, one description each kept
  assert.equal(counts.pulled_at, SAMPLE.pulled_at);
  assert.equal(fd.present(), true);
});

test("a field's stored record keeps type, values and event membership, drops an empty description", async () => {
  await fd.importDoc(SAMPLE);
  const platform = fd.fieldOn("Platform");
  assert.equal(platform.type, "integer");
  assert.deepEqual(platform.values, { "0": "Windows", "1": "Mac", "2": "Linux" });
  assert.deepEqual(platform.events, ["AidMaster"]);
  const commandLine = fd.fieldOn("CommandLine"); // source description is "" (empty)
  assert.equal(commandLine.type, "string");
  assert.equal(commandLine.values, undefined);
  assert.equal(commandLine.description, undefined);
  const computerName = fd.fieldOn("ComputerName"); // source description is non-empty and kept
  assert.equal(computerName.description, "The hostname reported by the sensor.");
});

test("an event's description is the first non-empty one across its variants", async () => {
  await fd.importDoc(SAMPLE);
  assert.equal(fd.eventOn("AidMaster").description, "Sensor identity and platform metadata, emitted once per sensor check-in.");
  assert.equal(fd.eventOn("LzmaFileWritten").description, "LZMA-compressed file write, macOS."); // the mac variant is listed first
});

test("forget() removes the layer; a field and the counts read empty again", async () => {
  await fd.importDoc(SAMPLE);
  await fd.forget();
  assert.equal(fd.present(), false);
  assert.equal(fd.counts(), null);
  assert.equal(fd.fieldOn("Platform"), null);
});

test("isFalconContainer: a Splunk crowdstrike: sourcetype and a Sentinel table named for CrowdStrike, nothing else", () => {
  assert.equal(fd.isFalconContainer("crowdstrike:events:sensor"), true);
  assert.equal(fd.isFalconContainer("ReachCrowdStrike_CL"), true);
  assert.equal(fd.isFalconContainer("aws:cloudtrail"), false);
  assert.equal(fd.isFalconContainer(""), false);
});

test("importDoc() refuses an oversized document rather than pruning it silently", async () => {
  const big = { ...SAMPLE, fields: { ...SAMPLE.fields } };
  const filler = "x".repeat(200);
  for (let i = 0; i < 2000; i++) big.fields[`Filler${i}`] = { type: "string", description: "", values: Object.fromEntries(Array.from({ length: 50 }, (_, j) => [`v${j}`, filler])) };
  await assert.rejects(() => fd.importDoc(big), /MB stored, over the/);
  assert.equal(fd.present(), false);
});
