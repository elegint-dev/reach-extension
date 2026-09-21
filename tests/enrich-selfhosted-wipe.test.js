// app/lib/wipe.js's ENRICH_SETTING_KEYS carries the three self-hosted
// enrichment keys (origin, token, provider), and "Clear all Reach data"
// removes them from chrome.storage.local along with everything else it
// already covers, the same guarantee tests/wipe.test.js holds for the
// keys that landed before this one.

import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as wipe from "../app/lib/wipe.js";
import { fakeChrome } from "./_chrome.js";

test("ENRICH_SETTING_KEYS names all three self-hosted enrichment keys", () => {
  assert.ok(wipe.ENRICH_SETTING_KEYS.includes("reach.enrich.selfhosted.origin"));
  assert.ok(wipe.ENRICH_SETTING_KEYS.includes("reach.enrich.selfhosted.token"));
  assert.ok(wipe.ENRICH_SETTING_KEYS.includes("reach.enrich.selfhosted.provider"));
  assert.ok(wipe.ENRICH_SETTING_KEYS.includes("reach.enrich.selfhosted.writes"), "the writes toggle is wiped with the rest");
});

test("run() removes the self-hosted keys from chrome.storage.local", async () => {
  const fake = fakeChrome();
  const { local } = fake;
  local.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  local.set("reach.enrich.selfhosted.token", "secret");
  local.set("reach.enrich.selfhosted.provider", "misp");
  const restore = fake.install();
  let res;
  try {
    res = await wipe.run({ revokeHosts: false });
  } finally {
    restore();
  }
  assert.ok(res.storage.includes("reach.enrich.selfhosted.origin"));
  assert.ok(res.storage.includes("reach.enrich.selfhosted.token"));
  assert.ok(res.storage.includes("reach.enrich.selfhosted.provider"));
  assert.equal(local.has("reach.enrich.selfhosted.origin"), false);
  assert.equal(local.has("reach.enrich.selfhosted.token"), false);
  assert.equal(local.has("reach.enrich.selfhosted.provider"), false);
});
