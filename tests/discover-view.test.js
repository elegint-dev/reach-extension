// The Splunk Discover view arms its buttons only on an origin the
// extension lists as enabled: ?env= in the URL is a prefill, and one the
// list does not carry falls back to the first enabled origin, or to none.

import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { pickOrigin, splunkOrigins } from "../app/views/discover-splunk.js";

const enabled = [{ origin: "https://splunk.acme", tabs: 1 }, { origin: "https://splunk.eu.acme", tabs: 0 }];

test("pickOrigin keeps the wanted origin only when it is enabled, else the first enabled one, else none", () => {
  assert.equal(pickOrigin("https://splunk.eu.acme", enabled), "https://splunk.eu.acme");
  assert.equal(pickOrigin("https://attacker.example", enabled), "https://splunk.acme");
  assert.equal(pickOrigin(null, enabled), "https://splunk.acme");
  assert.equal(pickOrigin("https://splunk.acme", []), null);
  assert.equal(pickOrigin(null, []), null);
});

test("the Azure portal, enabled for Sentinel, is never the Splunk instance the buttons arm on, whatever order it is listed in", () => {
  const mixed = [{ origin: "https://portal.azure.com", tabs: 1 }, { origin: "http://192.168.64.1:8001", tabs: 1 }, { origin: "https://security.microsoft.com", tabs: 0 }];
  assert.equal(pickOrigin(null, mixed), "http://192.168.64.1:8001");
  assert.equal(pickOrigin("https://portal.azure.com", mixed), "http://192.168.64.1:8001", "asking for the portal is not honoured on the Splunk page");
  assert.deepEqual(splunkOrigins(mixed).map((o) => o.origin), ["http://192.168.64.1:8001"]);
  assert.equal(pickOrigin(null, [{ origin: "https://portal.azure.com", tabs: 1 }]), null, "a portal alone leaves nothing to run SPL on");
});
