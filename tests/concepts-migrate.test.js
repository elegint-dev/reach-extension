// First load on the concept model: a version-1 user layer already in the
// store is read as version 2 and its bound notes move onto their concepts.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as store from "../app/lib/store.js";

const V1 = {
  version: 1,
  updated_at: "2026-08-01T00:00:00Z",
  sourcetypes: {
    "ReachCloudTrail_CL": { fields: { PrincipalArn: { description: "Written in the portal, before the concept model.", updated_at: "2026-07-01T00:00:00Z" } } },
    "aws:cloudtrail": { description: "Our trail.", updated_at: "2026-07-02T00:00:00Z", fields: { "userIdentity.arn": { description: "older, from Splunk", updated_at: "2026-06-01T00:00:00Z" }, unbound_thing: { description: "stays by pair" } } },
    "acme:widgets": { fields: { w: { description: "unbound feed" } } },
  },
};
await store.set("catalogue.user", JSON.parse(JSON.stringify(V1)));
const catalogue = await import("../app/lib/catalogue.js");
await catalogue.load();

test("a version-1 layer is read as version 2 and saved back, with no copy kept", async () => {
  assert.equal(await store.get("catalogue.user.v1"), undefined);
  const u = catalogue.userLayer();
  assert.equal(u.version, 2);
  assert.equal((await store.get(catalogue.USER_KEY)).version, 2, "saved back");
});

test("bound notes move onto the concept, newest wins, labelled with where they were written", () => {
  const u = catalogue.userLayer();
  const note = u.concepts["aws-cloudtrail/principal_arn"];
  assert.equal(note.description, "Written in the portal, before the concept model.");
  assert.deepEqual(note.written_on, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "PrincipalArn" });
  assert.equal(u.sourcetypes.ReachCloudTrail_CL, undefined, "nothing left under the table");
  const v = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(v.meaning.source, "user");
  assert.deepEqual(v.meaning.writtenOn, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "PrincipalArn" });
});

test("unbound notes and sourcetype-level notes stay where they were", () => {
  const u = catalogue.userLayer();
  assert.equal(u.sourcetypes["aws:cloudtrail"].description, "Our trail.");
  assert.equal(u.sourcetypes["aws:cloudtrail"].fields.unbound_thing.description, "stays by pair");
  assert.equal(u.sourcetypes["aws:cloudtrail"].fields["userIdentity.arn"], undefined);
  assert.equal(catalogue.fieldOn("acme:widgets", "w").meaning.description, "unbound feed");
  assert.deepEqual(catalogue.noteCount(), { notes: 3, sourcetypes: 2, concepts: 1, bindings: 0, setAside: 0 });
});
