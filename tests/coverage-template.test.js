// The Coverage page on the title block: the environment screen with Feeds
// (N) folded and Sourcetypes (N); the table screen with the sourcetype as
// its h1, Confirm all and All feeds as its actions and Fields (N) with the
// skipped columns folded under it; and the two empty states, each with the
// way to Discover on its action row.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as store from "../app/lib/store.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as layer from "../app/lib/layer.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";
import * as view from "../app/views/coverage.js";

const restore = dom.install();
assert.equal(store.backend(), "memory");
await catalogue.load();
const resolve = matcher();
const ORIGIN = "https://splunk.acme";
const ST = "acme:cloudtrail";

function prof(top) {
  return { count: 100, distinct: top.length, fill: 0.9, numeric: false, top: top.map((value, i) => ({ value, count: 10 - i })), sample: 100, measured_at: "2026-09-17T09:00:00Z", window: "-7d" };
}
const FIELDS = {
  EventName: { profile: prof(["ConsoleLogin", "AssumeRole", "GetObject"]) },
  EventSource: { profile: prof(["signin.amazonaws.com", "sts.amazonaws.com", "s3.amazonaws.com"]) },
  UserIdentityArn: { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:sts::123456789012:assumed-role/Admin/bob", "arn:aws:iam::123456789012:user/carol"]) },
  SourceIpAddress: { profile: prof(["10.0.0.1", "10.0.0.2", "203.0.113.9"]) },
  UserAgent: { profile: prof(["aws-cli/2.0", "console.amazonaws.com", "Boto3/1.0"]) },
  RecipientAccountId: { profile: prof(["123456789012", "210987654321", "111111111111"]) },
  SharedEventId: { profile: prof(["7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a01", "7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a02", "7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a03"]) },
  zz_custom_note: { profile: prof(["alpha", "beta", "gamma"]) },
};

const ctx = { catalogue, params: {}, setUrl() {}, navigate() {} };
const h2s = (el) => el.querySelectorAll("h2").map((n) => dom.text(n));
const ids = (el) => h2s(el).map((t) => (resolve(t) || { id: `unregistered: ${t}` }).id);
const isSubsequence = (seq, master) => {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
};
async function mount(params) {
  const el = view.render({ ...ctx, params });
  await el.afterMount();
  return el;
}

beforeEach(async () => {
  for (const k of Object.keys(await layer.readAll())) await layer.forget(k);
});

test("with nothing discovered the title block stands alone: Coverage, nothing to propose, and Discover on the action row", async () => {
  const el = await mount({});
  const title = el.children[0];
  assert.ok(title.classList.contains("r-title"), "the title block is first");
  assert.equal(dom.text(title.querySelector("h1")), "Coverage");
  assert.equal(dom.text(title.querySelector(".r-title__chips")), "nothing to propose");
  assert.deepEqual(title.querySelector(".r-actions").querySelectorAll("a").map((a) => a.getAttribute("href")), ["#/discover"]);
  assert.deepEqual(h2s(el), []);
});

test("the environment screen: the environment and its counts as the scope, the select as the action, Feeds (N) as h3 folds, then Sourcetypes (N)", async () => {
  await layer.update(ORIGIN, (e) => (e.sourcetypes[ST] = { indexes: ["aws"], count: 1000, profiled_at: "2026-09-17T09:00:00Z", fields: FIELDS }));
  const el = await mount({});
  const title = el.children[0];
  assert.equal(dom.text(title.querySelector("h1")), "Coverage");
  assert.match(dom.text(title.querySelector(".r-scope")), /^https:\/\/splunk\.acme · \d+ of \d+ concepts carried · \d+ proposed · \d+ gaps · 1 sourcetype$/);
  assert.ok(title.querySelector(".r-actions").querySelector("select"), "the environment select is the action");
  assert.ok(isSubsequence(ids(el), TOOL_ORDER), `${ids(el)}`);
  assert.ok(ids(el).every((id) => !id.startsWith("unregistered")), ids(el).join(", "));
  const feeds = el.querySelector(".r-cov__feeds");
  const bands = feeds.querySelectorAll("details");
  assert.equal(dom.text(feeds.querySelector("h2")), `Feeds (${bands.length})`);
  for (const band of bands) assert.ok(band.querySelector("summary").querySelector("h3"), "a feed is an h3 in its fold's summary");
  assert.equal(bands.filter((b) => b.hasAttribute("open")).length, bands.length === 1 ? 1 : 0, "folded unless it is the only feed");
  assert.ok(h2s(el).includes("Sourcetypes (1)"));
});

test("the table screen: the sourcetype as h1 with the coverage chip, feed and counts as the scope, Confirm all (N) and All feeds as actions, Fields (N) with Skipped fields folded under it", async () => {
  await layer.update(ORIGIN, (e) => (e.sourcetypes[ST] = { indexes: ["aws"], count: 1000, profiled_at: "2026-09-17T09:00:00Z", fields: FIELDS }));
  const el = await mount({ st: ST });
  const title = el.children[0];
  assert.equal(dom.text(title.querySelector("h1")), ST);
  assert.equal(dom.text(title.querySelector(".r-title__chips")), "coverage");
  assert.match(dom.text(title.querySelector(".r-scope")), /^.+ · \d+ bound.* · \d+ proposed · \d+ unbound$/);
  const actions = title.querySelector(".r-actions").children.map((n) => dom.text(n));
  assert.match(actions[0], /^Confirm all \(\d+\)$/);
  assert.equal(actions[1], "All feeds");
  assert.ok(h2s(el).some((t) => /^Fields \(\d+\)$/.test(t)), h2s(el).join(", "));
  assert.ok(isSubsequence(ids(el), TOOL_ORDER), `${ids(el)}`);
  assert.equal(el.querySelector(".r-cov__fields").querySelectorAll("tbody")[0].children.length, Object.keys(FIELDS).length, "one row per column");
  assert.equal(el.querySelector(".r-cov__aside"), null, "no skipped fold with nothing set aside");
});

test("a table no run profiled: its name as h1, the not profiled chip, run Discover first as the scope, Discover and All feeds as actions", async () => {
  await layer.update(ORIGIN, (e) => (e.sourcetypes[ST] = { indexes: ["aws"], count: 1000, profiled_at: "2026-09-17T09:00:00Z", fields: FIELDS }));
  const el = await mount({ st: "acme:unprofiled" });
  const title = el.children[0];
  assert.equal(dom.text(title.querySelector("h1")), "acme:unprofiled");
  assert.equal(dom.text(title.querySelector(".r-title__chips")), "not profiled");
  assert.match(dom.text(title.querySelector(".r-scope")), /run Discover on this sourcetype first/);
  assert.deepEqual(title.querySelector(".r-actions").querySelectorAll("a").map((a) => dom.text(a)), ["Discover", "All feeds"]);
  assert.deepEqual(h2s(el), []);
});

process.on("exit", restore);
