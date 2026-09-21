// app/lib/onboarding.js's cardModel() on the Sentinel side: the enable
// step names the Logs blade and the portal's own button, not Splunk's.
import "./_sentinel.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { cardModel } from "../app/lib/onboarding.js";

test("cardModel(): the Sentinel step names the Logs blade and Enable in the Azure portal", () => {
  const model = cardModel();
  assert.match(model.steps[0], /Open the Sentinel Logs blade/);
  assert.match(model.steps[0], /Enable in the Azure portal/);
  assert.doesNotMatch(model.steps[0], /Splunk/);
});
