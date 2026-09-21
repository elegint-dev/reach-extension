// A field's route paragraph is composed from its route class and its own
// data (routeExplain), not stored per field: for every distinct paragraph
// the bundle shipped, the field the fixture names composes it byte for
// byte. A record the composer cannot reproduce keeps its own explain.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as fields from "../app/lib/pack-fields.js";
import * as catalogue from "../app/lib/catalogue.js";
import { routeExplain, ROUTE_ORDER } from "../app/lib/reachability.js";

await catalogue.load();

const EXPLAIN = JSON.parse(readFileSync(new URL("./fixtures/fdr-route-explain.json", import.meta.url), "utf8"));
const sourcetypeOf = (ev) => (fields.event(ev) || {}).sourcetype || null;

test("every distinct route paragraph composes from the field's route data", () => {
  assert.equal(Object.keys(EXPLAIN).length, 324);
  const kept = [];
  for (const [name, text] of Object.entries(EXPLAIN)) {
    const rec = fields.field(name);
    assert.ok(rec, name);
    assert.equal(rec.route.explain, text, name);
    const { explain, ...route } = rec.route;
    if (routeExplain(route, sourcetypeOf) === text) continue;
    kept.push(name);
    assert.match(text, /^This field is computed by the TA from \S+ \(TA intermediates or fields not in any catalogue\)/, name);
  }
  // The residue: a derived field whose source is a TA intermediate no
  // catalogue names, so the name lives only in its paragraph (20 distinct
  // paragraphs over 32 fields).
  assert.equal(kept.length, 20, kept.join(", "));
});

test("a mixed field's histogram names the classes in route order", () => {
  const route = { summary: "mixed", by_event: { A: { route: "host_only" }, B: { route: "one_hop" }, C: { route: "direct_anchor" }, D: { route: "one_hop" } } };
  assert.equal(routeExplain(route), "The route depends on which event you are looking at (1 direct_anchor, 2 one_hop, 1 host_only); check by_event for the event in hand.");
  assert.deepEqual(ROUTE_ORDER.slice(0, 2), ["direct_anchor", "one_hop"]);
});

test("a host-only field whose events are all detection summaries reads as external-only", () => {
  const on = (ev) => (ev === "Event_X" ? "crowdstrike:events:external" : "crowdstrike:events:sensor");
  assert.match(routeExplain({ summary: "host_only", by_event: { Event_X: { route: "host_only" } } }, on), /^This field rides only on detection summary events/);
  assert.match(routeExplain({ summary: "host_only", by_event: { Event_X: { route: "host_only" }, DnsRequest: { route: "host_only" } } }, on), /^The events carrying this field have NO process handle/);
});

test("a derived field names its sources, a constant names none", () => {
  assert.equal(routeExplain({ summary: "derived", derived_from: ["LocalPort", "RemotePort"] }), "This field is computed by the TA from LocalPort, RemotePort, so see LocalPort's route; a process route belongs to the raw source, not to the derived field.");
  assert.equal(routeExplain({ summary: "derived", derived_from: [] }), "This field is a constant the TA sets by EVAL, so there is no raw source and no process route.");
  assert.equal(routeExplain({ summary: "derived", derived_from: [], explain: "kept" }), "kept");
});
