// The alias map the app installs from the loaded packs: a Falcon workflow
// input and the sensor column it names are one held fact, a concept's
// columns are one held fact, and nothing merges two concepts.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });

const catalogue = await import("../app/lib/catalogue.js");
const held = await import("../app/lib/held.js");
const facts = await import("../app/lib/facts.js");
const investigation = await import("../app/lib/investigation.js");
const concepts = await import("../app/lib/concepts.js");
const packs = await import("../app/lib/packs.js");

await catalogue.load();
facts.installAliases();

test("pid, tpid and hostname are held as the sensor columns they name; aid is already its own column", () => {
  assert.equal(held.canonicalKey("pid"), "rawprocessid");
  assert.equal(held.canonicalKey("tpid"), "targetprocessid");
  assert.equal(held.canonicalKey("hostname"), "computername");
  assert.equal(held.canonicalKey("aid"), "aid");
  assert.equal(held.canonicalKey("earliest"), "earliest");
});

test("a click on RawProcessId and a typed pid are one fact in the store and both names in bound()", () => {
  investigation.clear();
  investigation.set("RawProcessId", "936");
  investigation.set("pid", "936");
  investigation.set("TargetProcessId", "255667414");
  investigation.set("tpid", "255667414");
  assert.deepEqual(investigation.all(), { rawprocessid: "936", targetprocessid: "255667414" });
  const b = facts.bound();
  assert.equal(b.pid, "936");
  assert.equal(b.tpid, "255667414");
  investigation.clear();
});

test("no alias joins two concepts: every canonical column resolves to one concept on this platform", () => {
  const params = packs.conceptParams();
  const pairs = held.aliasPairs({ bindings: concepts.allBindings("splunk"), params });
  const canon = new Set(pairs.map(([, c]) => c));
  for (const c of canon) {
    const keys = new Set(concepts.allBindings("splunk").filter((b) => b.column.toLowerCase() === c).map((b) => b.key));
    assert.ok(keys.size <= 1, `${c} carries ${[...keys].join(", ")}`);
  }
  for (const [a, c] of pairs) assert.notEqual(a, c);
});
