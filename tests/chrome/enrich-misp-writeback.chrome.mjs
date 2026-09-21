// The self-hosted module on with a MISP origin, key and the writes toggle
// stored: a hit row offers "Record sighting" and the click sends exactly
// one POST to /sightings/add/<attribute id> through the module service
// worker, then reads the value again for the new count. The requests are
// read off a fetch spy installed on the worker itself, which also answers
// them from the recorded fixtures (the origin does not exist).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { launch, openValuePopup, shot, ROOT, SECTION_WAIT } from "./harness.mjs";
import path from "node:path";

let h;
let page;
const ORIGIN = "https://misp.fixture.test";
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";
const LOOKUP = `${ORIGIN}/attributes/restSearch?returnFormat=json&value=${HASH}&includeEventTags=1&includeSightings=1`;
const SIGHTING = `${ORIGIN}/sightings/add/1`;
const fixture = (name) => JSON.parse(readFileSync(path.join(ROOT, "tests", "fixtures", name), "utf8"));
const leaf = (name, row = 1) => `.shared-eventsviewer-list-body-row:nth-of-type(${row}) .json-tree .f-v[data-field-name="${name}"]`;

before(async () => {
  h = await launch({ extraOrigins: [`${ORIGIN}/*`] });
  await h.setStorage({
    "reach.modules": { enabled: { selfhosted: true } },
    "reach.enrich.selfhosted.provider": "misp",
    "reach.enrich.selfhosted.origin": ORIGIN,
    "reach.enrich.selfhosted.token": "fixture-key",
    "reach.enrich.selfhosted.writes": true,
  });
  page = await h.splunkPage();
});
after(async () => {
  if (h) await h.close();
});

// Logs every worker fetch as { url, method, body } into
// globalThis.__reachFetchLog and answers the MISP origin from the fixtures.
async function installFetchSpy() {
  await h.worker.evaluate(
    ({ origin, hit, sighting }) => {
      if (globalThis.__reachFetchSpied) return;
      globalThis.__reachFetchSpied = true;
      globalThis.__reachFetchLog = [];
      let sightings = hit.response.Attribute[0].Sighting.length;
      const orig = globalThis.fetch.bind(globalThis);
      globalThis.fetch = (...args) => {
        const url = String(args[0] && args[0].url ? args[0].url : args[0]);
        const init = args[1] || {};
        globalThis.__reachFetchLog.push({ url, method: init.method || "GET", body: typeof init.body === "string" ? init.body : null });
        if (!url.startsWith(origin)) return orig(...args);
        let json;
        if (url.includes("/sightings/add/")) {
          sightings += 1;
          json = sighting;
        } else {
          json = JSON.parse(JSON.stringify(hit));
          json.response.Attribute[0].Sighting = Array.from({ length: sightings }, (_, i) => ({ id: String(i + 1) }));
        }
        return Promise.resolve(new Response(JSON.stringify(json), { status: 200, headers: { "content-type": "application/json" } }));
      };
    },
    { origin: ORIGIN, hit: fixture("misp-restsearch-sightings.json"), sighting: fixture("misp-sighting-add.json") },
  );
}

async function fetchLog() {
  return h.worker.evaluate(() => globalThis.__reachFetchLog || []);
}

test("a MISP hit row offers Record sighting, and the click sends one POST to /sightings/add/<id> with source Reach, then re-reads the count", async (t) => {
  await shot(t, page, async () => {
    await installFetchSpy();
    const section = await openValuePopup(page, leaf("SHA256HashData"));
    const row = section.locator(".reach-enrich .reach-enrich__row", { hasText: "Self-hosted" });
    await row.waitFor({ state: "attached", timeout: 5000 });
    if (!(await row.isVisible())) await section.locator(".reach-enrich .reach-fold summary", { hasText: "Other sources" }).click();
    await row.waitFor({ state: "visible", timeout: 5000 });
    assert.deepEqual(await fetchLog(), [], "the row offering the lookup sends nothing on its own");

    await row.locator("button", { hasText: "Check on Self-hosted" }).click();
    const record = row.locator(".reach-enrich__action", { hasText: "Record sighting" });
    await record.waitFor({ timeout: SECTION_WAIT });
    assert.deepEqual(
      (await fetchLog()).map((f) => [f.url, f.method]),
      [[LOOKUP, "GET"]],
      "the lookup alone, as a GET, before the sighting button is clicked",
    );
    assert.match(await row.locator(".reach-row__body", { hasText: "sightings:" }).textContent(), /sightings: 2/);

    await record.click();
    await row.locator(".reach-row__body", { hasText: "Sighting recorded" }).waitFor({ timeout: SECTION_WAIT });
    const log = await fetchLog();
    assert.deepEqual(
      log.map((f) => [f.url, f.method]),
      [
        [LOOKUP, "GET"],
        [SIGHTING, "POST"],
        [LOOKUP, "GET"],
      ],
      "one POST for the sighting, then the same lookup again",
    );
    assert.equal(log[1].body, JSON.stringify({ source: "Reach" }));
    assert.match(await row.locator(".reach-row__body", { hasText: "sightings:" }).textContent(), /sightings: 3/);
  });
});
