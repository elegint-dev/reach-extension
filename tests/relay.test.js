// End-to-end over the extension's message relay, with the real files:
//   discovery.js  → chrome.runtime.sendMessage
//   background.js → chrome.tabs.sendMessage
//   discovery-agent.js → live-lookup.js → fetch (canned Splunk below)
// The browser tool cannot drive chrome-extension:// pages, so this is where
// the three hops are exercised. Splunk's responses are the shapes observed
// on 10.4.3 (tests/fixtures-ish, inline).

import "./_splunk.js"; // Splunk-only code under test: the FDR bundle, SPL packs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { fakeChrome } from "./_chrome.js";

const CONF_MACROS = JSON.parse(await readFile(new URL("./fixtures/conf-macros.json", import.meta.url), "utf8"));

// ---------------------------------------------------------------------------
// Fake chrome: one background listener set, one content-script listener set
// (the tab's), the worker's tabs.sendMessage delivering to the latter.

const EXT_ID = "test-ext";
const fake = fakeChrome({
  id: EXT_ID,
  getURL: (p) => pathToFileURL(new URL(`../${p}`, import.meta.url).pathname).href,
  tabs: ({ url }) => (url.startsWith("http://splunk.test/") ? [{ id: 7, title: "Search | Splunk" }] : []),
});
fake.chrome.permissions.contains = async () => true; // every host granted
const tabListeners = [];
fake.chrome.tabs.sendMessage = async (tabId, msg) => {
  assert.equal(tabId, 7);
  return fake.deliver(tabListeners, msg, { id: EXT_ID });
};
fake.install();
const { local: storage, bgListeners, connectListeners, registered: registeredScripts, deliver } = fake;
const onPermissionsAdded = (grant) => fake.permissionListeners.forEach((fn) => fn(grant));
storage.set("trustedOrigins", ["http://splunk.test"]);

// ---------------------------------------------------------------------------
// Canned Splunk behind fetch(): job dispatch, status, results, REST.

const dispatched = [];
const REST = {
  "data/props/fieldaliases": [{ name: "aws:cloudtrail : FIELDALIAS-x", acl: { app: "Splunk_TA_aws" }, content: { attribute: "FIELDALIAS-x", stanza: "aws:cloudtrail", type: "FIELDALIAS", value: "sourceIPAddress AS src_ip", "alias.0.sourceIPAddress": "src_ip" } }],
  "data/props/calcfields": [{ name: "aws:cloudtrail : EVAL-msg", acl: { app: "Splunk_TA_aws" }, content: { attribute: "EVAL-msg", stanza: "aws:cloudtrail", type: "EVAL", "field.name": "msg", value: 'coalesce(\'errorCode\',"success")' } }],
  "data/props/lookups": [{ name: "aws:cloudtrail : LOOKUP-oc", acl: { app: "Splunk_TA_aws" }, content: { attribute: "LOOKUP-oc", stanza: "aws:cloudtrail", type: "LOOKUP", transform: "aws_cloudtrail_eventname_lookup", value: "aws_cloudtrail_eventname_lookup eventName OUTPUTNEW object_category", "lookup.field.input.eventName": "", "lookup.field.output.0.object_category": "" } }],
  "data/props/extractions": [{ name: "aws:cloudtrail : REPORT-user", acl: { app: "Splunk_TA_aws" }, content: { attribute: "REPORT-user-for-aws-cloudtrail-acctmgmt", stanza: "aws:cloudtrail", type: "Uses transform", value: "user-for-aws-cloudtrail-acctmgmt" } }],
  "data/transforms/extractions": [{ name: "user-for-aws-cloudtrail-acctmgmt", acl: { app: "Splunk_TA_aws" }, content: { REGEX: "user\\/(?<iam_user>[^\"]+)", FORMAT: "user::$1" } }],
  "configs/conf-macros": CONF_MACROS,
  "configs/conf-props": [{ name: "aws:cloudtrail", acl: { app: "Splunk_TA_aws" }, content: { INDEXED_EXTRACTIONS: "json", KV_MODE: "none" } }],
};
const RESULTS = {
  tstats: [{ index: "main", sourcetype: "aws:cloudtrail", count: "60", first_seen: "1789636410", last_seen: "1789657870" }, { index: "main", sourcetype: "crowdstrike:events:sensor", count: "81", first_seen: "1", last_seen: "2" }],
  fieldsummary: [
    { field: "reach_total", count: "60", distinct_count: "1", is_exact: "1", numeric_count: "60", min: "1", max: "1", mean: "1", values: '[{"value":"1","count":60}]' },
    { field: "eventName", count: "60", distinct_count: "11", is_exact: "1", numeric_count: "0", values: '[{"value":"CreateUser","count":11},{"value":"AttachUserPolicy","count":8}]' },
    { field: "userIdentity.userName", count: "42", distinct_count: "3", is_exact: "1", numeric_count: "0", values: '[{"value":"alice","count":20}]' },
    { field: "punct", count: "60", distinct_count: "9", is_exact: "1", numeric_count: "0", values: "[]" },
  ],
  "stats count by": [{ eventName: "CreateUser", count: "11" }, { eventName: "AttachUserPolicy", count: "8" }],
  inputlookup: [{ eventName: "RunInstances", object_category: "instance" }, { eventName: "CreateUser", object_category: "user" }],
};
function resultsFor(spl) {
  for (const k of Object.keys(RESULTS)) if (spl.includes(k)) return RESULTS[k];
  return [];
}

globalThis.location = { origin: "http://splunk.test", pathname: "/en-US/app/search/search", port: "" };
globalThis.document = { cookie: "splunkweb_csrf_token_8000=tok123", querySelector: () => ({}) };
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  const ok = (json) => ({ ok: true, status: 200, json: async () => json, text: async () => JSON.stringify(json) });
  if (u.includes("/search/v2/jobs") && opts.method === "POST") {
    assert.equal(opts.headers["X-Splunk-Form-Key"], "tok123", "CSRF header from the page's cookie");
    const body = new URLSearchParams(opts.body);
    dispatched.push({ search: body.get("search"), earliest: body.get("earliest_time") });
    return ok({ sid: `sid${dispatched.length}` });
  }
  if (/\/jobs\/sid\d+\?/.test(u)) return ok({ entry: [{ content: { isDone: true, messages: [] } }] });
  if (/\/jobs\/sid\d+\/results/.test(u)) {
    const n = Number(/sid(\d+)/.exec(u)[1]);
    return ok({ results: resultsFor(dispatched[n - 1].search) });
  }
  if (opts.method === "DELETE") return ok({});
  for (const [path, entries] of Object.entries(REST)) if (u.includes(path)) return ok({ entry: entries });
  return { ok: false, status: 404, text: async () => "nope", json: async () => ({}) };
};

// ---------------------------------------------------------------------------
// Load the real scripts. background.js is a module worker; discovery-agent.js
// is a classic content script, evaluated in this context.

async function evalScript(rel) {
  const src = await readFile(new URL(`../${rel}`, import.meta.url), "utf8");
  // new Function, not vm: dynamic import() inside works without
  // --experimental-vm-modules, and the agent's import URL is absolute.
  new Function(src)();
}
await import("../background.js");
// The agent registers on the same chrome.runtime.onMessage; in the browser it
// lives in a different context (the tab). Swap the listener sink so its
// handlers become the tab's.
chrome.runtime.onMessage.addListener = (fn) => tabListeners.push(fn);
await evalScript("discovery-agent.js");
const discovery = await import("../app/lib/discovery.js");

// ---------------------------------------------------------------------------

test("environments() lists enabled origins with their open tabs", async () => {
  const envs = await discovery.environments();
  assert.deepEqual(envs, [{ origin: "http://splunk.test", tabs: 1, title: "Search | Splunk" }]);
});

test("a run naming an origin the relay does not list as enabled is refused before any tab is asked", async () => {
  await assert.rejects(() => discovery.inventory("http://elsewhere.test"), /http:\/\/elsewhere\.test is not an enabled Splunk instance/);
  await assert.rejects(() => discovery.provenance("http://elsewhere.test", "x"), /is not an enabled Splunk instance/);
});

test("a run on an enabled origin with no tab open fails with a clear message", async () => {
  const before = storage.get("trustedOrigins");
  storage.set("trustedOrigins", [...before, "http://closed.test"]);
  try {
    await assert.rejects(() => discovery.inventory("http://closed.test"), /No open Splunk tab on http:\/\/closed\.test/);
  } finally {
    storage.set("trustedOrigins", before);
  }
});

test("an origin known only by its registered content script counts as enabled, the same set the environment list shows", async () => {
  const listed = chrome.scripting.getRegisteredContentScripts;
  chrome.scripting.getRegisteredContentScripts = async () => [{ id: "reach-json-tree-http://registered.test" }, { id: "reach-sentinel-portal" }];
  try {
    const envs = await discovery.environments();
    assert.deepEqual(envs.map((e) => e.origin), ["http://splunk.test", "http://registered.test"]);
    await assert.rejects(() => discovery.inventory("http://registered.test"), /No open Splunk tab on http:\/\/registered\.test/);
  } finally {
    chrome.scripting.getRegisteredContentScripts = listed;
  }
});

// The sender shapes the worker sees: the side panel is an extension page
// outside any tab; the catalogue tab is a top-level document (frameId 0); a
// copy of index.html framed by a web page carries the host page's tab and a
// frameId above 0.
const PANEL = { id: EXT_ID };
const CATALOGUE_TAB = { id: EXT_ID, tab: { id: 12, windowId: 1 }, frameId: 0 };
const FRAMED = { id: EXT_ID, tab: { id: 7, windowId: 1 }, frameId: 3 };
const RUN = { type: "reach:discover:run", origin: "http://splunk.test", spl: "| tstats count where index=* by index, sourcetype", earliest: "-7d", latest: "now", app: "search" };
const REST_CALL = { type: "reach:discover:rest", origin: "http://splunk.test", path: "servicesNS/-/-/data/props/calcfields", count: 0 };

test("discovery from a framed extension page is refused before any tab is asked", async () => {
  const sent = chrome.tabs.sendMessage;
  let forwarded = 0;
  chrome.tabs.sendMessage = async (...args) => {
    forwarded++;
    return sent(...args);
  };
  try {
    for (const msg of [RUN, REST_CALL, { type: "reach:discover:tabs" }]) {
      const res = await deliver(bgListeners, msg, FRAMED);
      assert.deepEqual(res, { ok: false, error: "Discovery only runs from Reach's own page." });
    }
  } finally {
    chrome.tabs.sendMessage = sent;
  }
  assert.equal(forwarded, 0);
});

test("discovery from the side panel and from the catalogue tab is accepted", async () => {
  for (const sender of [PANEL, CATALOGUE_TAB]) {
    const tabs = await deliver(bgListeners, { type: "reach:discover:tabs" }, sender);
    assert.equal(tabs.ok, true);
    assert.deepEqual(tabs.origins.map((o) => o.origin), ["http://splunk.test"]);
    const run = await deliver(bgListeners, RUN, sender);
    assert.equal(run.ok, true, run.error);
    assert.ok(Array.isArray(run.rows));
    const rest = await deliver(bgListeners, REST_CALL, sender);
    assert.equal(rest.ok, true, rest.error);
  }
});

test("a selection from a subframe content script is still taken: the Sentinel blade sends from one", async () => {
  const res = await deliver(bgListeners, { type: "reach:selection", selection: { platform: "sentinel", kind: "field", name: "Computer", sourcetype: "SecurityEvent" } }, { id: EXT_ID, tab: { id: 20, windowId: 5 }, frameId: 4 });
  assert.deepEqual(res, { ok: true, panel: false });
});

test("inventory → three hops → tstats rows land in the discovered layer", async () => {
  const r = await discovery.inventory("http://splunk.test", { index: "*", earliest: "-7d" });
  assert.equal(dispatched.at(-1).search, "| tstats count, min(_time) as first_seen, max(_time) as last_seen where index=* by index, sourcetype");
  assert.equal(dispatched.at(-1).earliest, "-7d");
  const st = r.env.sourcetypes["aws:cloudtrail"];
  assert.deepEqual(st.indexes, ["main"]);
  assert.equal(st.count, 60);
  assert.equal(st.first_seen, 1789636410);
  assert.ok(storage.get("reach.catalogue.discovered.http://splunk.test").sourcetypes["crowdstrike:events:sensor"], "one storage key per environment");
});

test("profile: fill rate from reach_total, junk fields skipped, top values parsed", async () => {
  const r = await discovery.profile("http://splunk.test", "aws:cloudtrail", { index: "main", earliest: "-24h" });
  assert.equal(r.total, 60);
  const f = r.env.sourcetypes["aws:cloudtrail"].fields;
  assert.equal(f.punct, undefined);
  assert.equal(f.reach_total, undefined);
  assert.equal(f["userIdentity.userName"].profile.fill, 0.7);
  assert.equal(f["userIdentity.userName"].profile.distinct, 3);
  assert.deepEqual(f.eventName.profile.top[0], { value: "CreateUser", count: 11 });
});

test("recordTypes: values with counts, discriminator remembered", async () => {
  const r = await discovery.recordTypes("http://splunk.test", "aws:cloudtrail", "eventName", { index: "main" });
  assert.deepEqual(r.values, [{ value: "CreateUser", count: 11 }, { value: "AttachUserPolicy", count: 8 }]);
  assert.equal(r.env.sourcetypes["aws:cloudtrail"].discriminator, "eventName");
});

test("provenance: alias, calculated (with refs), lookup output/key, REPORT transform", async () => {
  const r = await discovery.provenance("http://splunk.test", "aws:cloudtrail");
  const f = r.env.sourcetypes["aws:cloudtrail"].fields;
  assert.equal(f.src_ip.provenance[0].kind, "alias");
  assert.equal(f.src_ip.provenance[0].from, "sourceIPAddress");
  assert.equal(f.msg.provenance[0].kind, "calculated");
  assert.deepEqual(f.msg.provenance[0].refs, ["errorCode"]);
  // Empty REST values (no AS in the stanza) fall back to the column name.
  assert.equal(f.object_category.provenance[0].kind, "lookup");
  assert.deepEqual(f.object_category.provenance[0].inputs, ["eventName"]);
  assert.equal(f.eventName.provenance.find((p) => p.kind === "lookup_key").transform, "aws_cloudtrail_eventname_lookup");
  assert.equal(f.iam_user.provenance[0].kind, "extracted");
  assert.equal(f.user.provenance[0].transform, "user-for-aws-cloudtrail-acctmgmt");
  assert.deepEqual(r.counts, { aliases: 1, calculated: 1, lookups: 1, extractions: 1 });
});

test("provenance macros: nothing is read when none are asked for", async () => {
  const plain = await discovery.provenance("http://splunk.test", "aws:cloudtrail");
  assert.equal(plain.macros, null);
  assert.equal(plain.env.macros, undefined, "no macros asked for: conf-macros is never read, and env.macros stays unset");
});

test("provenance macros: parameterised stanzas match by base name, an unlisted macro is never reported", async () => {
  const names = ["cs_index", "cs_trace_process", "cs_process_table", "cs_pid_lookup", "cs_process_events"];
  const r = await discovery.provenance("http://splunk.test", "crowdstrike:events:sensor", { macros: names });
  assert.deepEqual(r.macros.cs_index, { defined: true, definition: "index=crowdstrike_fdr", app: "TA_crowdstrike_fdr" });
  assert.equal(r.macros.cs_trace_process.defined, true, "cs_trace_process(3) matches cs_trace_process by base name");
  assert.equal(r.macros.cs_process_table.defined, false);
  assert.equal(r.macros.cs_pid_lookup.defined, false);
  assert.equal(r.macros.cs_process_events.defined, false);
  assert.deepEqual(Object.keys(r.macros).sort(), [...names].sort(), "some_other_macro, outside the allowlist, is never reported");
  assert.deepEqual(r.env.macros, r.macros, "stored at the environment, not folded into the sourcetype record");
  assert.equal(r.env.sourcetypes["crowdstrike:events:sensor"].macros, undefined);
});

test("decodes: single-key lookups read with inputlookup by lookup-side columns", async () => {
  const progress = [];
  const r = await discovery.decodes("http://splunk.test", "aws:cloudtrail", { onProgress: (p) => progress.push(p) });
  assert.equal(dispatched.at(-1).search, "| inputlookup aws_cloudtrail_eventname_lookup | head 2001 | table eventName object_category");
  assert.equal(r.tables, 1);
  assert.deepEqual(progress, [{ done: 1, total: 1, tables: 1 }]);
  // A second run skips tables already read unless forced.
  const again = await discovery.decodes("http://splunk.test", "aws:cloudtrail");
  assert.equal(again.candidates, 0);
  assert.equal(again.skipped, 1);
  const d = r.env.sourcetypes["aws:cloudtrail"].decodes.eventName;
  assert.equal(d.meaning_field, "object_category");
  assert.deepEqual(d.values, { RunInstances: "instance", CreateUser: "user" });
});

test("the catalogue reads the discovered layer: profile, provenance, decode, sourcetype", async () => {
  await import("./_bundle.js"); // data.js fetch stub is not installed above; catalogue.load needs the pack files
  // _bundle.js replaced globalThis.fetch for file URLs; the pack loads from disk.
  const catalogue = await import("../app/lib/catalogue.js");
  await catalogue.load();
  const st = catalogue.sourcetype("aws:cloudtrail");
  assert.deepEqual(st.sources, ["pack", "discovered"]); // the bundled CloudTrail pack, plus what discovery measured
  assert.deepEqual(st.indexes, ["main"]);
  assert.equal(st.discriminator, "eventName");
  const v = catalogue.fieldOn("aws:cloudtrail", "eventName");
  assert.equal(v.scope, "sourcetype"); // the pack places it there; discovery's numbers ride along
  assert.equal(v.profile.distinct, 11);
  assert.ok(v.provenance.some((p) => p.kind === "lookup_key"));
  assert.equal(v.decode.values.CreateUser, "user");
  assert.equal(v.decode.source, "discovered");
  assert.ok(catalogue.fieldsOn("aws:cloudtrail").includes("src_ip"));
  // Discovery's facts never become meanings; the description is the pack's.
  assert.equal(v.meaning.source, "pack");
  const unknown = catalogue.fieldOn("aws:cloudtrail", "src_ip");
  assert.equal(unknown.meaning.source, "pack"); // TA alias, described by the pack
});

// ---------------------------------------------------------------------------
// The side panel: a click's selection reaches the window's panel, and the
// reply tells the page whether one took it.

function fakePanelPort(windowId) {
  const received = [];
  const onMsg = [];
  const onDisc = [];
  const port = {
    name: "reach-panel",
    sender: { id: EXT_ID },
    onMessage: { addListener: (fn) => onMsg.push(fn) },
    onDisconnect: { addListener: (fn) => onDisc.push(fn) },
    postMessage: (m) => received.push(m),
  };
  for (const fn of connectListeners) fn(port);
  for (const fn of onMsg) fn({ type: "reach:panel:hello", windowId });
  return { received, disconnect: () => onDisc.forEach((fn) => fn()) };
}

const fromTab = (tabId, windowId) => ({ id: EXT_ID, tab: { id: tabId, windowId } });
const selection = { platform: "splunk", kind: "field", name: "aid", value: "", sourcetype: "crowdstrike:events:sensor", index: "main", discriminator: { field: "event_simpleName", value: "DnsRequest" } };

test("a selection with no panel open is kept, and the page is told no panel took it", async () => {
  const res = await deliver(bgListeners, { type: "reach:selection", selection }, fromTab(7, 1));
  assert.deepEqual(res, { ok: true, panel: false });
  // A panel connecting afterwards gets that last selection at once.
  const panel = fakePanelPort(1);
  assert.equal(panel.received.length, 1);
  assert.equal(panel.received[0].type, "reach:selection");
  assert.equal(panel.received[0].selection.name, "aid");
  assert.equal(panel.received[0].selection.tabId, 7);
  assert.equal(panel.received[0].replay, true, "a selection replayed on hello says so; a live click does not");
  panel.disconnect();
});

test("with a panel open in the window, the selection is forwarded to it and the page is told", async () => {
  const panel = fakePanelPort(2);
  assert.equal(panel.received.length, 0); // nothing clicked in window 2 yet
  const res = await deliver(bgListeners, { type: "reach:selection", selection: { ...selection, name: "aip", extra: "dropped" } }, fromTab(9, 2));
  assert.deepEqual(res, { ok: true, panel: true });
  assert.equal(panel.received.length, 1);
  const got = panel.received[0].selection;
  assert.equal(got.name, "aip");
  assert.equal(got.windowId, 2);
  assert.equal("replay" in panel.received[0], false, "a live click carries no replay flag");
  assert.equal("extra" in got, false); // only the fields the panel navigates on
  assert.deepEqual(got.discriminator, { field: "event_simpleName", value: "DnsRequest" });
  assert.deepEqual(got.event, {}, "no row fields sent: an empty map, never undefined");
  // The row's sibling fields for the verdict ride as short strings under plain names; anything else is dropped.
  const withRow = await deliver(bgListeners, { type: "reach:selection", selection: { ...selection, event: { SigningId: "com.apple.contactsd", TeamId: "-", CodeSigningFlags: 637618689, "bad key!": "x", nested: { a: 1 }, long: "y".repeat(600) } } }, fromTab(9, 2));
  assert.deepEqual(withRow, { ok: true, panel: true });
  const row = panel.received[1].selection.event;
  assert.deepEqual(Object.keys(row).sort(), ["SigningId", "TeamId", "long"]);
  assert.equal(row.long.length, 512);
  // Another window's click does not reach this panel.
  await deliver(bgListeners, { type: "reach:selection", selection }, fromTab(11, 3));
  assert.equal(panel.received.length, 2);
  panel.disconnect();
  const after = await deliver(bgListeners, { type: "reach:selection", selection }, fromTab(9, 2));
  assert.deepEqual(after, { ok: true, panel: false });
});

test("a selection from something that is not a tab, or with no name, is refused", async () => {
  assert.deepEqual(await deliver(bgListeners, { type: "reach:selection", selection }, { id: EXT_ID }), { ok: false, panel: false });
  assert.deepEqual(await deliver(bgListeners, { type: "reach:selection", selection: { kind: "field" } }, fromTab(7, 1)), { ok: false, panel: false });
});

// registerForGrant(): CIRCL's and EPSS's host permissions are fetch
// targets, the same reason virustotal.com and a self-hosted origin are
// excluded (tests/enrich-selfhosted-relay.test.js). hashlookup.circl.lu
// and api.first.org must never be registered as a Splunk/Sentinel page or
// land in trustedOrigins, or a click there would start offering Reach's
// own popup on CIRCL's or FIRST's own site.
test("registerForGrant excludes hashlookup.circl.lu and api.first.org, the same as virustotal.com", async () => {
  assert.ok(fake.permissionListeners.length, "the worker registered a permissions.onAdded listener");
  const before = registeredScripts.length;
  const splunkPattern = "https://splunk2.example.com/*";
  onPermissionsAdded({ origins: ["https://hashlookup.circl.lu/*", "https://api.first.org/*", splunkPattern] });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(registeredScripts.filter((s) => s.matches[0] === "https://hashlookup.circl.lu/*").length, 0, "CIRCL never gets a content script");
  assert.equal(registeredScripts.filter((s) => s.matches[0] === "https://api.first.org/*").length, 0, "EPSS never gets a content script");
  assert.ok(registeredScripts.length > before, "an ordinary Splunk origin in the same grant still registers");
  assert.ok(registeredScripts.some((s) => s.matches[0] === splunkPattern));
  const { trustedOrigins = [] } = await chrome.storage.local.get("trustedOrigins");
  assert.ok(!trustedOrigins.includes("https://hashlookup.circl.lu"), "CIRCL never lands in Splunk discovery");
  assert.ok(!trustedOrigins.includes("https://api.first.org"), "EPSS never lands in Splunk discovery");
  assert.ok(trustedOrigins.includes("https://splunk2.example.com"));
});
