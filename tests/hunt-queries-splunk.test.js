// The mac signing hunt's two searches in SPL, byte for byte against the
// golden fixture tests/fixtures/hunt-queries.json: the window default,
// a bound window, and a bound index. The fixture is frozen; it is not
// regenerated from the code under test.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as workflows from "../app/lib/workflows.js";
import * as pivot from "../app/lib/pivot.js";

await catalogue.load();
const cases = JSON.parse(readFileSync(new URL("./fixtures/hunt-queries.json", import.meta.url), "utf8")).filter((c) => c.lang === "spl");

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
  test(`SPL parity: ${c.id}`, () => {
    const got = render(c);
    assert.equal(got.lang, "spl");
    assert.equal(got.text, c.text);
    assert.deepEqual(got.hazards, c.hazards);
    assert.deepEqual(got.missing, c.missing);
    assert.equal(got.sourcetype, c.sourcetype);
  });
}

test("the SPL reads the sensor's own signer fields, keeps the window in the text, groups by host and image, and carries no lookup", () => {
  const spl = render(cases[0]).text;
  assert.match(spl, /earliest=-7d/);
  assert.match(spl, /event_platform=Mac event_simpleName=ProcessRollup2/);
  assert.match(spl, /NOT \(CsValidationCategory=1 TeamId="-"\)/);
  assert.match(spl, /by aid, ComputerName, ImageFileName/);
  assert.doesNotMatch(spl, /lookup/);
  const path = render(cases[1]).text;
  assert.match(path, /ImageFileName IN \("\/Library\/Apple\/System\/Library\/CoreServices\/MRT\.app\/\*", /);
  assert.match(path, /"\/usr\/sbin\/\*"\)/);
  assert.doesNotMatch(path, /[0-9a-f]{64}/, "no hash from the corpus rides along");
});
