// Startup parses the catalogue bundle and the field records of the
// containers this platform knows, nothing else: the enrichment bundles
// under app/data/enrich and the known corpus under app/data/known load on
// first use by an enabled module, once, and never at import or at
// catalogue.load().
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { stat } from "node:fs/promises";

const fetched = [];
const inner = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  fetched.push(String(url));
  return inner(url, opts);
};

const rel = (u) => u.replace(/^.*\/app\/(data|packs)\//, "app/$1/");
const dataFiles = () => fetched.map(rel).filter((p) => p.startsWith("app/data/") || p.startsWith("app/packs/"));

const catalogue = await import("../app/lib/catalogue.js");
const modules = await import("../app/lib/modules.js");
await import("../app/lib/popup-ui.js");
await import("../app/lib/enrich.js");
const known = await import("../app/lib/known.js");
const kev = await import("../app/lib/enrich/kev.js");
const loldrivers = await import("../app/lib/enrich/loldrivers.js");

test("importing the app's libraries fetches nothing", () => {
  assert.deepEqual(dataFiles(), []);
});

test("catalogue.load() parses the bundle only: no enrichment bundle, no known corpus", async () => {
  await catalogue.load();
  await modules.hydrate();
  const files = dataFiles();
  assert.ok(files.includes("app/packs/crowdstrike-falcon.fields.json"), files.join(", "));
  assert.deepEqual(
    files.filter((p) => p.startsWith("app/data/enrich/") || p.startsWith("app/data/known/")),
    [],
    `startup fetched: ${files.join(", ")}`,
  );
});

test("a bundled source loads its file on the first call and keeps it", async () => {
  const before = dataFiles().filter((p) => p === "app/data/enrich/kev.json").length;
  assert.equal(before, 0);
  await kev.call("CVE-2021-44228");
  await kev.call("CVE-2021-44228");
  assert.equal(dataFiles().filter((p) => p === "app/data/enrich/kev.json").length, 1, "one fetch for two calls");
  await loldrivers.call("ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436");
  assert.equal(dataFiles().filter((p) => p === "app/data/enrich/loldrivers.json").length, 1);
  assert.equal(dataFiles().filter((p) => p === "app/data/enrich/sigma.json").length, 0, "a source not asked stays unread");
});

test("the known corpus loads on the first verdict, not before", async () => {
  assert.equal(dataFiles().filter((p) => p.startsWith("app/data/known/")).length, 0);
  await known.verdict({ platform: "macos", os_version: "26.0", image_path: "/usr/libexec/contactsd" });
  assert.ok(dataFiles().some((p) => p.startsWith("app/data/known/")), "the corpus is read once a verdict asks");
});

// The number the report states: bytes of JSON a default Splunk install
// parses before the first click beyond the packs themselves, and what
// stays on disk until a module asks.
test("startup bytes on Splunk: the Falcon fields sidecar and nothing from enrich or known", async () => {
  const size = (await stat(fileURLToPath(new URL("../app/packs/crowdstrike-falcon.fields.json", import.meta.url)))).size;
  assert.ok(size > 3_000_000 && size < 3_300_000, `sidecar bytes ${size}`);
  assert.deepEqual(dataFiles().filter((p) => p.endsWith(".fields.json")), ["app/packs/crowdstrike-falcon.fields.json"], "one sidecar, fetched once");
});
