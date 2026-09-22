// A bitmask concept's decode lives on the concept, not a container binding
// (values.js decodeBitmask takes decode + value, nothing platform-shaped),
// so the five newly-sourced Falcon bit tables read the same way under
// Sentinel. ReachCrowdStrike_CL, the seeded sample table, carries none of
// the 27 raw FDR bitmask columns (the capture is a curated Windows LSASS
// dump with the FALCON_CONCEPTS column set plus DesiredAccess,
// TemplateDisposition and the code-signing columns only; ProcessParameterFlags
// and its siblings are not among them), so this is the one route Sentinel
// has to these tables today: the same pack concept, read with PLATFORM
// pinned to sentinel, with no live container binding to prove instead.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as packs from "../app/lib/packs.js";
import * as values from "../app/lib/values.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { PLATFORM } from "../app/lib/platform.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

test("the Falcon fields sidecar is Splunk-only: no bundle to fetch on Sentinel", () => {
  assert.equal(fields.field("ProcessParameterFlags"), null);
});

test("process_parameter_flags decodes 24577 the same way under Sentinel, a container-independent read", () => {
  const concept = packs.pack("crowdstrike-falcon").concepts.process_parameter_flags;
  assert.equal(
    values.decodeBitmask(concept.decode, "24577"),
    "RTL_USER_PROC_PARAMS_NORMALIZED | RTL_USER_PROC_APP_MANIFEST_PRESENT | RTL_USER_PROC_IMAGE_KEY_MISSING",
  );
});
