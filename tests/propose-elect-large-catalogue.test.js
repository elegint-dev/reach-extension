// The feed election on a catalogue of a hundred containers: a vendor
// spelling that a sibling pack also binds narrows the field to those
// packs instead of losing its vote, and the feed that explains more of
// the columns (or spells them identically) is elected. The small case
// keeps its distinct-only reading, and a column set every sibling
// explains alike stays unrecognised.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as propose from "../app/lib/propose.js";

const bind = (container, column) => ({ platform: "splunk", container, column, alias_of: null, cim: null });

// The feed under test: eight concepts spelled the vendor's way on a
// Splunk sourcetype and the connector's way on a Sentinel table.
function feedConcepts() {
  const pairs = [
    ["event_name", "record_type", "eventName", "EventName"],
    ["event_source", "text", "eventSource", "EventSource"],
    ["principal_arn", "principal", "userIdentity.arn", "UserIdentityArn"],
    ["source_ip", "source_ip", "sourceIPAddress", "SourceIpAddress"],
    ["user_agent", "user_agent", "userAgent", "UserAgent"],
    ["recipient_account_id", "account_id", "recipientAccountId", "RecipientAccountId"],
    ["shared_event_id", "event_id", "sharedEventID", "SharedEventId"],
    ["request_parameters", "text", "requestParameters", "RequestParameters"],
  ];
  return pairs.map(([id, type, splunk, sentinel]) => ({ key: `ct/${id}`, id, label: id, type, decode: null, cim: null, bindings: [bind("ct:events", splunk), bind("CtEvents", sentinel)] }));
}

// A sibling pack binding six of the same vendor spellings on its own
// container: the same schema through another transport.
function siblingConcepts() {
  const shared = [["event_name", "record_type", "eventName"], ["event_source", "text", "eventSource"], ["principal_arn", "principal", "userIdentity.arn"], ["source_ip", "source_ip", "sourceIPAddress"], ["user_agent", "user_agent", "userAgent"], ["recipient_account_id", "account_id", "recipientAccountId"]];
  return shared.map(([id, type, column]) => ({ key: `ct-lake/${id}`, id, label: id, type, decode: null, cim: null, bindings: [bind("ct:lake", column)] }));
}

// A hundred more containers over twenty-five packs. Each pack owns a
// record-type spelling and a marker of its own, every fourth binds
// userAgent and eventName too (a vendor name that recurs across
// unrelated feeds), and every pack binds the same four generic spellings
// that mean something different on each.
function crowdConcepts() {
  const out = [];
  for (let p = 0; p < 25; p++) {
    const packId = `vendor${p}`;
    const containers = [`v${p}:audit`, `v${p}:events`, `v${p}:inventory`, `v${p}:alerts`];
    const columns = ["object_attrs", "change_type", "object_category", "object_path", `v${p}Kind`, `v${p}Marker`];
    if (p % 4 === 0) columns.push("userAgent", "eventName");
    for (const column of columns) {
      const id = column.toLowerCase().replace(/[^a-z0-9]+/g, "_");
      const type = column === "eventName" || column === `v${p}Kind` ? "record_type" : "text";
      out.push({ key: `${packId}/${id}`, id, label: id, type, decode: null, cim: null, bindings: containers.map((c) => bind(c, column)) });
    }
  }
  return out;
}

function containersOf(concepts) {
  return new Set(concepts.flatMap((c) => c.bindings.map((b) => b.container)));
}

const SENTINEL_SPELLED = ["EventName", "EventSource", "UserIdentityArn", "SourceIpAddress", "UserAgent", "RecipientAccountId", "SharedEventId", "zz_note"];
const VENDOR_SPELLED = ["eventName", "eventSource", "userIdentity.arn", "sourceIPAddress", "userAgent", "recipientAccountId"];

test("the small catalogue elects from distinct spellings alone", () => {
  const vocabulary = propose.vocabulary({ concepts: feedConcepts(), learned: [] });
  const r = propose.electFeed("acme:ct", SENTINEL_SPELLED, { vocabulary });
  assert.equal(r.feedPackId, "ct");
  assert.equal(r.basis, "names");
  assert.equal(r.shared, undefined, "no second reading needed");
  assert.ok(r.votes.ct >= 5);
});

test("a hundred containers loaded: the feed is still elected from names when a sibling binds the same spellings", () => {
  const concepts = [...feedConcepts(), ...siblingConcepts(), ...crowdConcepts()];
  assert.ok(containersOf(concepts).size >= 100, `${containersOf(concepts).size} containers`);
  const vocabulary = propose.vocabulary({ concepts, learned: [] });
  const r = propose.electFeed("acme:ct", SENTINEL_SPELLED, { vocabulary });
  assert.equal(r.feedPackId, "ct");
  assert.equal(r.basis, "names");
  assert.ok(r.votes.ct >= 5, JSON.stringify(r.votes));
  assert.ok(r.votes.ct > r.votes["ct-lake"], "the feed explains a column the sibling does not");
  // The same columns spelled the vendor's way: the feed still wins on the
  // column the sibling does not bind.
  const vendor = propose.electFeed("acme:ct2", [...VENDOR_SPELLED, "sharedEventID"], { vocabulary });
  assert.equal(vendor.feedPackId, "ct");
  // Only the six spellings both packs bind identically: a tie between the
  // two, not a pick by position.
  const tie = propose.electFeed("acme:ct3", VENDOR_SPELLED, { vocabulary });
  assert.equal(tie.feedPackId, null, JSON.stringify(tie.votes));
  // A column set explained only by spellings many packs bind alike is
  // nobody's feed, however many of them match.
  const generic = propose.electFeed("acme:change", ["object_attrs", "change_type", "object_category", "object_path", "userAgent", "eventName"], { vocabulary });
  assert.equal(generic.feedPackId, null, JSON.stringify(generic.votes));
});

test("shared names elect only behind an owned anchor: a pack's own record type plus the generic set is its feed, the generic set plus a marker is not", () => {
  const concepts = [...feedConcepts(), ...siblingConcepts(), ...crowdConcepts()];
  const vocabulary = propose.vocabulary({ concepts, learned: [] });
  const generic = ["object_attrs", "change_type", "object_category", "object_path"];
  const anchored = propose.electFeed("v3:custom", ["v3Kind", "v3Marker", ...generic], { vocabulary });
  assert.equal(anchored.feedPackId, "vendor3", JSON.stringify(anchored.votes));
  assert.equal(anchored.shared, true, "the second reading, since the generic four are nobody's alone");
  const unanchored = propose.electFeed("v3:other", ["v3Marker", ...generic, "userAgent"], { vocabulary });
  assert.equal(unanchored.feedPackId, null, JSON.stringify(unanchored.votes));
});
