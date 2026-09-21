// app/lib/modules.js: every route, band, enrichment source, setting and
// key family in the code belongs to exactly one module; core modules take
// no toggle; a fresh install is on exactly where the tiers say; the
// platform-narrow entries mount only on their platform.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as modules from "../app/lib/modules.js";
import { ROUTES } from "../app/lib/router.js";
import * as enrich from "../app/lib/enrich.js";
import { source as kevSource } from "../app/lib/enrich/kev.js";
import { source as vtSource } from "../app/lib/enrich/virustotal.js";
import * as notebook from "../app/lib/notebook.js";
import * as benign from "../app/lib/benign.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as layer from "../app/lib/layer.js";
import * as discoverySweep from "../app/lib/discovery-sweep.js";
import * as recipe from "../app/lib/recipe.js";
import * as runbooksStore from "../app/lib/runbooks-store.js";
import * as searches from "../app/lib/searches.js";

const { MODULES, HEAD, SECTIONS, BANDS } = modules;
const itemId = (x) => (typeof x === "string" ? x : x.id);

function owners(list, id) {
  return MODULES.filter((m) => m[list].some((x) => itemId(x) === id)).map((m) => m.id);
}

test("module ids are unique and every tier is core, on or off", () => {
  const ids = MODULES.map((m) => m.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const m of MODULES) assert.ok(["core", "on", "off"].includes(m.tier), `${m.id}: tier ${m.tier}`);
  assert.deepEqual(
    MODULES.filter((m) => m.tier === "core").map((m) => m.id),
    ["shell", "catalogue", "pivots", "hold", "settings"],
  );
});

test("every router route belongs to exactly one module, and no module names a route the router lacks", () => {
  const routeIds = ROUTES.map((r) => r.route);
  for (const id of routeIds) assert.deepEqual(owners("routes", id).length, 1, `route ${id} owners: ${owners("routes", id)}`);
  for (const m of MODULES) for (const r of m.routes) assert.ok(routeIds.includes(itemId(r)), `${m.id} names route ${itemId(r)}`);
});

test("every band in HEAD and SECTIONS belongs to exactly one module, and BANDS carries each of them exactly once", () => {
  const union = new Set([...HEAD, ...SECTIONS]);
  assert.equal(BANDS.length, union.size);
  for (const b of BANDS) assert.ok(union.has(b), `BANDS carries ${b}, not in HEAD or SECTIONS`);
  for (const b of union) assert.ok(BANDS.includes(b), `${b} is in HEAD or SECTIONS but not drawn by BANDS`);
  for (const b of BANDS) assert.equal(owners("bands", b).length, 1, `band ${b} owners: ${owners("bands", b)}`);
  for (const m of MODULES) for (const b of m.bands) assert.ok(BANDS.includes(typeof b === "string" ? b : b.id), `${m.id} names band ${JSON.stringify(b)}`);
});

test("every enrichment source the code registers belongs to exactly one module", () => {
  for (const s of [kevSource, vtSource]) {
    try {
      enrich.register(s);
    } catch {
      /* already registered */
    }
  }
  const ids = enrich.all().map((s) => s.id);
  assert.ok(ids.length >= 12, `registered sources: ${ids.length}`);
  for (const id of ids) assert.equal(owners("sources", id).length, 1, `source ${id} owners: ${owners("sources", id)}`);
  for (const m of MODULES) for (const s of m.sources) assert.ok(ids.includes(itemId(s)), `${m.id} names source ${itemId(s)}`);
});

test("every setting key sits in exactly one module, under that module's own key families", () => {
  const seen = new Map();
  for (const m of MODULES) {
    const k = modules.keysOf(m.id);
    for (const s of m.settings) {
      assert.ok(k.chrome.includes(s.key), `${m.id}: setting ${s.key} is not in its chrome keys`);
      assert.ok(["toggle", "secret", "url", "select"].includes(s.kind), `${m.id}: setting kind ${s.kind}`);
    }
    for (const fam of ["chrome", "store", "storePrefix", "local", "session", "field"]) {
      for (const key of k[fam]) {
        const tag = `${fam}:${key}`;
        assert.ok(!seen.has(tag), `${tag} is owned by ${seen.get(tag)} and ${m.id}`);
        seen.set(tag, m.id);
      }
    }
  }
});

test("the store document names in the registry are the constants the stores export", () => {
  const stores = new Set(MODULES.flatMap((m) => modules.keysOf(m.id).store));
  for (const k of [notebook.KEY, benign.KEY, catalogue.USER_KEY, discoverySweep.KEY, recipe.WORKSPACES_KEY, layer.INDEX_KEY, modules.KEY, runbooksStore.KEY, searches.KEY]) {
    assert.ok(stores.has(k), `store key ${k} is in no module`);
  }
  assert.ok(MODULES.flatMap((m) => modules.keysOf(m.id).storePrefix).includes(layer.PREFIX));
});

test("a fresh install is on exactly where the tiers say, and core modules cannot be switched", async () => {
  modules.reset();
  await modules.hydrate();
  for (const m of MODULES) {
    const want = m.tier !== "off" && m.platforms.includes("splunk");
    assert.equal(modules.on(m.id, "splunk"), want, `${m.id} on splunk`);
  }
  assert.deepEqual(modules.enabled("splunk"), MODULES.filter((m) => m.tier !== "off").map((m) => m.id));
  await assert.rejects(() => modules.setEnabled("catalogue", false), /core/);
  await assert.rejects(() => modules.setEnabled("shell", false), /core/);
});

test("platform-narrow modules and entries are absent on the other platform, not off", async () => {
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("workflows", "splunk"), true);
  assert.equal(modules.on("workflows", "sentinel"), true);
  assert.equal(modules.routeStatus("workflow", "sentinel"), "on");
  assert.equal(modules.routeStatus("event", "sentinel"), "absent");
  assert.equal(modules.routeStatus("event", "splunk"), "on");
  assert.equal(modules.routeStatus("share", "splunk"), "off");
  assert.equal(modules.routeStatus("nosuchroute", "splunk"), "unknown");
  assert.ok(modules.sources("splunk").includes("escu"));
  assert.ok(!modules.sources("splunk").includes("sentinel-rules"));
  assert.ok(modules.sources("sentinel").includes("sentinel-rules"));
  assert.ok(!modules.sources("sentinel").includes("escu"));
  assert.ok(!modules.sources("splunk").includes("virustotal"), "an off module's source never offers");
  assert.ok(modules.routes("sentinel").includes("workflow"));
  assert.ok(!modules.routes("sentinel").includes("event"));
  assert.ok(!modules.routes("splunk").includes("share"));
  assert.ok(!modules.bands("splunk").includes("pattern"));
  assert.ok(!modules.bands("sentinel").includes("workflows"), "the popups' Workflows band stays Splunk's");
  assert.ok(modules.bands("splunk").includes("workflows"));
});

test("the enabled set round-trips through the store and an unknown id in it is ignored", async () => {
  modules.reset();
  await modules.hydrate();
  const res = await modules.setEnabled("share", true);
  assert.equal(res.ok, true);
  assert.equal(modules.on("share", "splunk"), true);
  assert.ok(modules.routes("splunk").includes("share"));
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("share", "splunk"), true, "the choice is read back from the store");
  const off = await modules.setEnabled("share", false);
  assert.equal(off.ok, true);
  assert.equal(modules.on("share", "splunk"), false);
  const store = await import("../app/lib/store.js");
  await store.set(modules.KEY, { enabled: { nosuch: true, verdicts: "yes", pattern: true } });
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("pattern", "splunk"), true);
  assert.equal(modules.on("verdicts", "splunk"), true, "a non-boolean choice falls back to the tier");
  await store.remove(modules.KEY);
});

test("every module carries a sends line and a one-line about", () => {
  for (const m of MODULES) {
    assert.ok(typeof m.sends === "string" && m.sends.length, `${m.id}: sends`);
    assert.ok(typeof m.about === "string" && m.about.length, `${m.id}: about`);
    assert.ok(!m.about.includes("\n"), `${m.id}: about is one line`);
  }
});

test("app.js keeps no hardcoded nav link to a route the registry gates", async () => {
  const src = await readFile(new URL("../app/app.js", import.meta.url), "utf8");
  assert.ok(!/h\("a", \{ href: "#\/share" \}/.test(src), "the nav draws from modules.routes()");
  assert.ok(src.includes("modules.routes("), "the router asks the registry");
});
