// The fleet baseline moved off Discover to the Falcon sourcetype page: a
// rendered Splunk Discover page carries no "fleet" text anywhere in it,
// and offers no control that measures one. The Sentinel side is
// discover-no-fleet-sentinel.test.js (platform.js reads REACH_PLATFORM
// once, on import).
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { render } from "../app/views/discover-splunk.js";

// Installed once, not restored: the view's own trailing draw (drawResults()
// is fired without an await inside refreshEnvs()) keeps touching this mock
// document after afterMount() resolves, as it does under the real one.
dom.install();
await catalogue.load();

const ORIGIN = "https://splunk.acme";
const c = fakeChrome({ answer: (msg) => (msg.type === "reach:discover:tabs" ? { origins: [{ origin: ORIGIN, tabs: 1 }] } : { rows: [] }) });
c.install();

function everyTitle(el) {
  return dom.walk(el, (n) => Boolean(n.attributes && n.attributes.title)).map((n) => n.attributes.title);
}

test("Splunk Discover, with an enabled instance and a full render, carries no 'fleet' text or title anywhere, and offers no fleet control", async () => {
  const ctx = { params: {}, catalogue, fields, modules, navigate() {}, href: () => "#", setUrl() {}, goBack() {} };
  const el = render(ctx);
  await el.afterMount();
  assert.doesNotMatch(dom.text(el), /fleet/i);
  for (const title of everyTitle(el)) assert.doesNotMatch(title, /fleet/i);
  const buttons = el.querySelectorAll("button").map((b) => dom.text(b));
  assert.ok(!buttons.some((t) => /fleet/i.test(t)), `a button names the fleet: ${buttons.join(", ")}`);
});
