// The mac signing hunt's two searches in KQL, byte for byte against the
// golden fixture tests/fixtures/hunt-queries.json, on the Sentinel sample
// table. The fixture is frozen; it is not regenerated from the code under
// test.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as workflows from "../app/lib/workflows.js";
import * as pivot from "../app/lib/pivot.js";
import * as kql from "../app/lib/kql.js";

await catalogue.load();
const cases = JSON.parse(readFileSync(new URL("./fixtures/hunt-queries.json", import.meta.url), "utf8")).filter((c) => c.lang === "kql");

function render(c) {
  const def = workflows.get("hunt_mac_signing", { params: {} });
  const r = def.results(c.params).find((x) => x.id === c.result);
  const bound = { ...(c.params.index ? { index: c.params.index } : {}), ...r.params };
  const g = pivot.generate(r.pivot.edge, bound, { pack: packs.pack("crowdstrike-falcon") });
  return { text: g.spl, hazards: g.hazards.map((h) => ({ level: h.level, text: h.text })), missing: g.missing, sourcetype: g.sourcetype, lang: g.lang };
}

test("the fixture covers both searches under the default window, a bound window and a bound index", () => {
  assert.deepEqual(cases.map((c) => c.id), ["namespace default window", "path default window", "namespace window -30d", "path window -30d", "namespace window and index", "path window and index"]);
});

for (const c of cases) {
  test(`KQL parity: ${c.id}`, () => {
    const got = render(c);
    assert.equal(got.lang, "kql");
    assert.equal(got.text, c.text);
    assert.deepEqual(got.hazards, c.hazards);
    assert.deepEqual(got.missing, c.missing);
    assert.equal(got.sourcetype, "ReachCrowdStrike_CL");
  });
}

test("the KQL twin windows on TimeGenerated, tests the same signer fields, summarizes by host and image, lints clean and carries no Splunk hazard", () => {
  const text = render(cases[0]).text;
  assert.match(text, /^ReachCrowdStrike_CL\n\| where TimeGenerated > ago\(7d\)/);
  assert.match(text, /\| where not\(CsValidationCategory == 1 and TeamId == "-"\)/);
  assert.match(text, /by Aid, ComputerName, ImageFileName/);
  assert.deepEqual(kql.lint(text).violations, []);
  for (const c of cases) assert.ok(!render(c).hazards.some((h) => /index|_time/.test(h.text)), `${c.id}: a Splunk hazard on the KQL twin`);
  const path = render(cases[1]).text;
  assert.match(path, /\| where ImageFileName matches regex @"\^\(\?:\/Library\/Apple\/System\/Library\/CoreServices\/MRT\\\.app\/\|/);
  assert.match(path, /\|\/usr\/sbin\/\)"/);
  assert.deepEqual(kql.lint(path).violations, []);
});
