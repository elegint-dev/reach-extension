// enrich.enabledIds(ask): the one live read value.js, value-popup.js and
// sentinel-grid.js all make before offersFor(), replacing a hard-coded
// ["virustotal"] (or nothing at all, for CIRCL/EPSS/the self-hosted relay)
// with the status background.js actually holds. A fake ask() stands in
// for chrome.runtime.sendMessage; each status shape below is copied from
// background.js's own reply for that message type (virusTotal(),
// enrichLookup(), selfHosted()), not uniform (virustotal and selfhosted
// answer "configured", circl and epss answer "enabled").

import { test } from "node:test";
import assert from "node:assert/strict";
import * as enrich from "../app/lib/enrich.js";

function fakeAsk(on) {
  return async (msg) => {
    if (msg.type === "reach:vt:status") return { ok: true, configured: on.has("virustotal"), permitted: on.has("virustotal") };
    if (msg.type === "reach:enrich:status" && msg.source === "circl") return { ok: true, enabled: on.has("circl"), permitted: on.has("circl") };
    if (msg.type === "reach:enrich:status" && msg.source === "epss") return { ok: true, enabled: on.has("epss"), permitted: on.has("epss") };
    if (msg.type === "reach:selfhosted:status") return { ok: true, configured: on.has("selfhosted"), permitted: on.has("selfhosted"), provider: "misp", origin: on.has("selfhosted") ? "https://misp.example.org" : "" };
    throw new Error(`unexpected message: ${msg.type}`);
  };
}

test("enabledIds: nothing on returns an empty list", async () => {
  assert.deepEqual(await enrich.enabledIds(fakeAsk(new Set())), []);
});

test("enabledIds: each source lights up on its own, none of the others", async () => {
  for (const id of ["virustotal", "circl", "epss", "selfhosted"]) {
    assert.deepEqual(await enrich.enabledIds(fakeAsk(new Set([id]))), [id]);
  }
});

test("enabledIds: every source on returns all four, in registration order", async () => {
  assert.deepEqual(await enrich.enabledIds(fakeAsk(new Set(["virustotal", "circl", "epss", "selfhosted"]))), ["virustotal", "circl", "epss", "selfhosted"]);
});

test("enabledIds: configured but not permitted (host permission revoked) still counts as off", async () => {
  const ask = async (msg) => {
    if (msg.type === "reach:vt:status") return { ok: true, configured: true, permitted: false };
    if (msg.type === "reach:enrich:status") return { ok: true, enabled: true, permitted: false };
    if (msg.type === "reach:selfhosted:status") return { ok: true, configured: true, permitted: false, provider: "misp", origin: "https://misp.example.org" };
    return null;
  };
  assert.deepEqual(await enrich.enabledIds(ask), []);
});

test("enabledIds: a null or failed answer (chrome.runtime.lastError, ok:false) is treated as off, not thrown", async () => {
  const ask = async () => null;
  assert.deepEqual(await enrich.enabledIds(ask), []);
  const askFalse = async () => ({ ok: false });
  assert.deepEqual(await enrich.enabledIds(askFalse), []);
});
