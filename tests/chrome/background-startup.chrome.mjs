// it_88b661de part 5: background.js's startup path
// (restoreTrustedOrigins, chrome.runtime.onStartup/onInstalled), driven
// through a real service worker, not by hand-firing fake.startupListeners
// the way tests/relay.test.js's enrich-selfhosted-relay.test.js does.
//
// onStartup fires only when the browser itself starts, never on a worker
// respawn from idle, so the only real trigger is a genuine browser
// restart: relaunch() (tests/chrome/harness.mjs) closes the context and
// launches a fresh one on the same staged extension directory (same id)
// and the same profile directory (same chrome.storage.local), so the new
// worker's onStartup is a real one, not simulated.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, relaunch, SPLUNK_ORIGIN } from "./harness.mjs";

let h;
before(async () => {
  h = await launch();
});
after(async () => {
  if (h) await h.close();
});

test("restoreTrustedOrigins, run for real by a genuine browser restart, drops an origin whose permission is no longer granted and unregisters its content script", async (t) => {
  const bogusOrigin = "https://revoked.example.com";
  const bogusId = "reach-json-tree-" + bogusOrigin;
  await h.worker.evaluate(
    async ({ granted, bogus, bogusId }) => {
      await chrome.storage.local.set({ trustedOrigins: [granted, bogus] });
      await chrome.scripting.registerContentScripts([{ id: bogusId, matches: [`${bogus}/*`], js: ["json-tree-fields.js"], runAt: "document_idle" }]);
    },
    { granted: SPLUNK_ORIGIN, bogus: bogusOrigin, bogusId },
  );
  const seeded = await h.worker.evaluate(() => chrome.storage.local.get("trustedOrigins"));
  assert.deepEqual(seeded.trustedOrigins.sort(), [SPLUNK_ORIGIN, bogusOrigin].sort(), "seeded before the restart");

  h = await relaunch(h);
  // restoreTrustedOrigins runs once off onStartup, itself several
  // sequential storage/scripting/permissions awaits; poll rather than a
  // fixed wait.
  let trustedOrigins;
  for (let i = 0; i < 30; i++) {
    ({ trustedOrigins = [] } = await h.worker.evaluate(() => chrome.storage.local.get("trustedOrigins")));
    if (!trustedOrigins.includes(bogusOrigin)) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.deepEqual(trustedOrigins.sort(), [SPLUNK_ORIGIN].sort(), "the ungranted origin was dropped by the real startup path, the still-granted one kept");

  const registered = await h.worker.evaluate(() => chrome.scripting.getRegisteredContentScripts());
  const ids = registered.map((r) => r.id);
  assert.ok(!ids.includes(bogusId), "the ungranted origin's content script was never re-registered");
  assert.ok(ids.some((id) => id.endsWith(SPLUNK_ORIGIN)), "the still-granted origin's content script survived the restart");
});

test(
  "registerForGrant is not driven live: it only runs off chrome.permissions.onAdded, which only fires from chrome.permissions.request()'s native prompt (established undrivable headless in tests/chrome/extension-only-actions.chrome.mjs)",
  { skip: "no way to fire a real permissions grant headless; the branch is covered in tests/relay.test.js, now against the macrotask-resolving fake (part 1)" },
  () => {},
);
