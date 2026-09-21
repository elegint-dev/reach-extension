// A Splunk popup loads the catalogue lazily: its load fetches the packs
// and no fields sidecar; a click in a container the Falcon sidecar
// describes fetches it, once; a click in a container no sidecar describes
// fetches nothing, so a tab on another feed never parses the Falcon
// catalogue.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";

const fetched = [];
const inner = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  fetched.push(String(url).replace(/^.*\/app\/packs\//, "app/packs/"));
  return inner(url, opts);
};
const sidecars = () => fetched.filter((p) => p.endsWith(".fields.json"));

const catalogue = await import("../app/lib/catalogue.js");
const fields = await import("../app/lib/pack-fields.js");
const { h } = await import("../app/components/h.js");
const { resolve } = await import("../app/lib/field-resolve.js");
const reachability = await import("../app/lib/reachability.js");
const modules = await import("../app/lib/modules.js");
const runbooks = await import("../app/lib/runbooks.js");
const runtime = await import("../app/lib/runtime.js");
const enrich = await import("../app/lib/enrich.js");
const packs = await import("../app/lib/packs.js");
const pivot = await import("../app/lib/pivot.js");
const workflows = await import("../app/lib/workflows.js");
const notebook = await import("../app/lib/notebook.js");
const pinned = await import("../app/lib/pinned.js");
const investigation = await import("../app/lib/investigation.js");
const store = await import("../app/lib/store.js");
const spl = await import("../app/lib/spl.js");
const fdrQueries = await import("../app/lib/fdr-queries.js");
const ui = await import("../app/lib/popup-ui.js");
const { KEYS } = await import("../app/lib/storage-keys.js");
const { clickContext } = await import("../app/lib/click-context.js");
const { sectionFor } = await import("../app/lib/click-section.js");
const splunkHooks = await import("../app/lib/click-splunk.js");

const restore = dom.install();
const settle = (ms = 10) => new Promise((r) => setTimeout(r, ms));
test.after(async () => {
  await settle(100);
  restore();
});

await catalogue.load({ fields: "lazy" });
await modules.hydrate();

const bridge = { apply: async () => ({ ok: true }), kqlReady: async () => false, read: async () => ({ ok: false, text: "" }) };
const lib = { catalogue, fields, resolve, ...reachability, modules, runbooks, keys: KEYS, runtime, enrich, packs, pivot, workflows, notebook, bridge, spl, fdrQueries, ui, h, live: null };
const splunk = splunkHooks.hooks(lib);

const el = (tag, attrs = {}, kids = []) => {
  const n = new dom.Node(tag);
  for (const [k, v] of Object.entries(attrs)) if (k === "class") n.className = v; else n.setAttribute(k, v);
  for (const k of kids) n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
  return n;
};

function splunkRow({ sourcetype, field, value, extra = [] }) {
  const fv = (name, v) => el("a", { class: "f-v", "data-field-name": name }, [v]);
  const clicked = fv(field, value);
  const links = [fv("host", "wk-1"), fv("source", "/x"), fv("sourcetype", sourcetype), fv("index", "main"), ...extra.map(([n, v]) => fv(n, v))];
  const row = el("tr", { class: "shared-eventsviewer-list-body-row" }, [el("td", {}, [el("table", {}, [el("tr", {}, [el("td", {}, [clicked])])]), el("table", { class: "fields" }, links)])]);
  document.body.replaceChildren(row);
  return clicked;
}

const ctxFor = (target) => clickContext("splunk", target, { discriminators: catalogue.discriminators(), runbooks: modules.on("runbooks", "splunk") });
const click = (target, name, value) => sectionFor({ platform: "splunk", click: { kind: "value", name, value }, ctx: ctxFor(target), lib, hooks: splunk });

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  pinned.clear();
  investigation.clear();
});

test("a lazy load fetches the packs and no fields sidecar", () => {
  assert.ok(fetched.includes("app/packs/index.json"));
  assert.deepEqual(sidecars(), []);
  assert.equal(fields.loaded(), false);
});

test("a click in a container no sidecar describes fetches nothing and still draws its section", async () => {
  const target = splunkRow({ sourcetype: "OktaIM2:log", field: "eventType", value: "user.session.start" });
  const out = await click(target, "eventType", "user.session.start");
  assert.ok(out && out.el);
  assert.deepEqual(sidecars(), []);
  assert.equal(fields.loaded(), false);
});

test("a click in a Falcon container fetches the sidecar once and the section reads its record", async () => {
  const target = splunkRow({ sourcetype: "crowdstrike:events:sensor", field: "TargetProcessId", value: "255667414", extra: [["event_simpleName", "ProcessRollup2"], ["aid", "a".repeat(32)]] });
  const out = await click(target, "TargetProcessId", "255667414");
  assert.deepEqual(sidecars(), ["app/packs/crowdstrike-falcon.fields.json"]);
  assert.ok(fields.loaded());
  assert.equal(fields.field("TargetProcessId").role, "process_id");
  assert.equal(dom.text(out.el.querySelector(".reach-scope")), "on crowdstrike:events:sensor · ProcessRollup2");
  await click(splunkRow({ sourcetype: "crowdstrike:events:sensor", field: "aid", value: "a".repeat(32), extra: [["event_simpleName", "ProcessRollup2"]] }), "aid", "a".repeat(32));
  assert.equal(sidecars().length, 1, "fetched once");
});
