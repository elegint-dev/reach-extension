import { test } from "node:test";
import assert from "node:assert/strict";
import * as navstack from "../app/lib/navstack.js";

test("a fresh stack can move neither back nor forward", () => {
  const s = navstack.initial("#/");
  assert.equal(navstack.canGoBack(s), false);
  assert.equal(navstack.canGoForward(s), false);
});

test("advancing to a new hash makes back possible and forward not", () => {
  const s = navstack.advance(navstack.initial("#/"), "#/catalogue");
  assert.equal(navstack.canGoBack(s), true);
  assert.equal(navstack.canGoForward(s), false);
});

test("moving back then forward returns to the same position", () => {
  let s = navstack.initial("#/");
  s = navstack.advance(s, "#/catalogue");
  s = navstack.advance(s, "#/discover");
  s = navstack.moveBack(s);
  assert.equal(navstack.canGoBack(s), true);
  assert.equal(navstack.canGoForward(s), true);
  s = navstack.moveForward(s);
  assert.equal(navstack.canGoForward(s), false);
});

test("advancing from a position with forward history drops it, like a browser tab", () => {
  let s = navstack.initial("#/");
  s = navstack.advance(s, "#/catalogue");
  s = navstack.advance(s, "#/discover");
  s = navstack.moveBack(s); // now at #/catalogue, with #/discover ahead
  s = navstack.advance(s, "#/packs"); // a fresh navigation from here
  assert.equal(navstack.canGoForward(s), false);
});

test("advancing to the hash already at the current position is not a move", () => {
  const s0 = navstack.advance(navstack.initial("#/"), "#/catalogue");
  const s1 = navstack.advance(s0, "#/catalogue");
  assert.equal(s1, s0);
});

test("moving back or forward past an end is a no-op", () => {
  const s = navstack.initial("#/");
  assert.equal(navstack.moveBack(s), s);
  assert.equal(navstack.moveForward(s), s);
});

test("relabelling the current entry (a router.replace(), no new history entry) does not add a step back", () => {
  let s = navstack.initial("#/");
  s = navstack.advance(s, "#/catalogue");
  s = navstack.relabel(s, "#/");
  assert.equal(navstack.canGoBack(s), true); // still one step back, to #/catalogue's predecessor
  assert.equal(navstack.canGoForward(s), false);
  s = navstack.moveBack(s);
  assert.equal(navstack.canGoBack(s), false); // exactly one real entry behind, not two
});

test("relabelling to the hash already at the current position is not a move", () => {
  const s0 = navstack.advance(navstack.initial("#/"), "#/catalogue");
  const s1 = navstack.relabel(s0, "#/catalogue");
  assert.equal(s1, s0);
});

// The trail: entries carry what the page read as, the mirror survives a
// reload, and the cursor never depends on history.length.

const A = "#/f/RawProcessId?st=crowdstrike:events:sensor&value=936";
const B = "#/f/TargetProcessId?st=crowdstrike:events:sensor&on=ProcessHandleOpDetectInfo&value=5497396";
const C = "#/v/936";

function walked() {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = navstack.label(navstack.advance(s, A), { kind: "field", name: "RawProcessId", value: "936" });
  s = navstack.label(navstack.advance(s, B), { kind: "field", name: "TargetProcessId", value: "5497396" });
  return s;
}

const names = (s) => navstack.trail(s).map((e) => e.value || e.name);

test("a click after a back is a new hop that replaces what was ahead: the trail keeps the page just left and forward goes dead", () => {
  let s = walked();
  s = navstack.moveBack(s);
  assert.deepEqual(names(s), ["Reach", "936"]);
  s = navstack.label(navstack.advance(s, C), { kind: "value", name: "936", value: "936" });
  assert.deepEqual(names(s), ["Reach", "936", "936"]);
  assert.equal(navstack.canGoForward(s), false);
  assert.equal(navstack.current(s).hash, C);
  s = navstack.moveBack(s);
  assert.equal(navstack.current(s).hash, A, "one back returns to the page the click was made from");
  assert.equal(navstack.canGoForward(s), true);
  assert.equal(navstack.moveForward(s).stack.length, 3, "B is gone for good");
});

test("relabelling after setUrl keeps the entry's chip and position: a sel= write adds no hop and back still works", () => {
  let s = walked();
  s = navstack.relabel(s, `${B}&sel=row3`);
  assert.equal(s.stack.length, 3);
  assert.equal(navstack.current(s).hash, `${B}&sel=row3`);
  assert.equal(navstack.current(s).value, "5497396", "the chip survives the relabel");
  assert.deepEqual(names(s), ["Reach", "936", "5497396"]);
  s = navstack.moveBack(s);
  assert.equal(navstack.current(s).hash, A);
  assert.equal(navstack.canGoForward(s), true);
});

test("a traversal to a stamped entry moves the cursor there when the hash agrees, and is refused when it does not", () => {
  const s = walked();
  const back2 = navstack.moveTo(s, 0, "#/");
  assert.equal(back2.pos, 0);
  assert.equal(navstack.canGoBack(back2), false);
  assert.equal(navstack.canGoForward(back2), true);
  assert.equal(navstack.moveTo(s, 0, C), null, "a stale stamp is not a traversal");
  assert.equal(navstack.moveTo(s, 7, "#/"), null);
  assert.equal(navstack.moveTo(s, 2, B), s, "already there");
});

test("the trail is the last three entries up to the cursor, oldest first, and never empty", () => {
  let s = walked();
  s = navstack.label(navstack.advance(s, C), { kind: "value", name: "936", value: "936" });
  assert.deepEqual(names(s), ["936", "5497396", "936"]);
  assert.deepEqual(navstack.trail(s, 2).map((e) => e.hash), [B, C]);
  assert.deepEqual(navstack.trail(navstack.initial("#/")).map((e) => e.hash), ["#/"]);
});

test("the mirror round-trips through text and comes back on the same hash with the cursor where it was", () => {
  const s = navstack.moveBack(walked());
  const text = navstack.serialize(s);
  const back = navstack.restore(text, A);
  assert.deepEqual(back, s);
  assert.equal(navstack.current(back).name, "RawProcessId");
  assert.equal(navstack.canGoForward(back), true);
});

test("the mirror on a different hash starts a fresh trail unless the document was replaced by the platform switch", () => {
  const s = walked();
  const fresh = navstack.restore(navstack.serialize(s), C);
  assert.deepEqual(fresh, navstack.initial(C));
  const switched = navstack.restore(navstack.serialize(s, { switch: true }), C);
  assert.equal(switched.stack.length, 3);
  assert.equal(navstack.current(switched).hash, C, "the platform switch relabels the current entry");
  assert.equal(navstack.canGoBack(switched), true);
});

test("a document resumes its trail on the same hash or after the platform switch, and a fresh document on any other hash does not", () => {
  const s = navstack.label(navstack.advance(navstack.initial(A), B), { name: "b" });
  assert.equal(navstack.resumes(navstack.serialize(s), B), true, "a reload keeps the hash");
  assert.equal(navstack.resumes(navstack.serialize(s, { switch: true }), C), true, "the platform switch replaced the document");
  assert.equal(navstack.resumes(navstack.serialize(s), C), false, "a link opened in a new tab");
  assert.equal(navstack.resumes(navstack.serialize(s), ""), false, "a fresh panel with no hash");
  assert.equal(navstack.resumes(null, B), false, "no mirror at all");
  assert.equal(navstack.resumes("{not json", B), false);
});

test("a mirror that is not a trail is ignored", () => {
  for (const bad of [null, "", "nope", "{}", JSON.stringify({ stack: [], pos: 0 }), JSON.stringify({ stack: [{ nohash: 1 }], pos: 0 }), JSON.stringify({ stack: [{ hash: "#/" }], pos: "1" })]) {
    assert.deepEqual(navstack.restore(bad, "#/"), navstack.initial("#/"), String(bad));
  }
});

test("labelling never changes the entry's hash", () => {
  const s = navstack.label(navstack.initial("#/x"), { hash: "#/y", kind: "page", name: "X" });
  assert.equal(navstack.current(s).hash, "#/x");
  assert.equal(navstack.current(s).name, "X");
});

// Hops, not clicks: an entry carries the row its click came from, and the
// app lands a click from the same row by relabel (router.replace()), any
// other by advance (app.js showSelection).

const ROW1 = "splunk|crowdstrike:events:sensor|ProcessHandleOpDetectInfo|1|row1";
const ROW2 = "splunk|crowdstrike:events:sensor|ProcessRollup2|1|row2";
const PIVOT = "splunk|crowdstrike:events:sensor|ProcessHandleOpDetectInfo|2|row1";
const hashOf = (field, value) => `#/f/${field}?st=crowdstrike:events:sensor&value=${value}`;

function click(s, field, value, hop) {
  const hash = hashOf(field, value);
  const next = navstack.sameHop(s, hop) ? navstack.relabel(s, hash) : navstack.advance(s, hash, hop);
  return navstack.label(next, { kind: "field", name: field, field, value, st: "crowdstrike:events:sensor" });
}

test("fifteen value clicks on one row are one chip whose value follows the click, and back returns to the page before the row", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  for (let i = 1; i <= 15; i++) s = click(s, `Field${i}`, String(1000 + i), ROW1);
  assert.equal(s.stack.length, 2, "the start page and one hop");
  assert.deepEqual(names(s), ["Reach", "1015"]);
  assert.equal(navstack.current(s).hash, hashOf("Field15", "1015"));
  assert.equal(navstack.current(s).hop, ROW1, "the entry keeps its row through the relabels");
  s = navstack.moveBack(s);
  assert.equal(navstack.current(s).hash, "#/", "back is the page before the row, not the previous click");
  assert.equal(navstack.canGoBack(s), false);
});

test("a click in another row adds a chip, and back returns to the previous hop's page with its last value", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = click(s, "RawProcessId", "936", ROW1);
  s = click(s, "TargetProcessId", "5497396", ROW1);
  s = click(s, "SHA256HashData", "8ae6", ROW2);
  s = click(s, "ImageFileName", "/usr/bin/ssh", ROW2);
  assert.deepEqual(names(s), ["Reach", "5497396", "/usr/bin/ssh"]);
  s = navstack.moveBack(s);
  assert.equal(navstack.current(s).hash, hashOf("TargetProcessId", "5497396"), "the previous hop's page as it was last left");
  assert.equal(navstack.current(s).value, "5497396");
  assert.equal(navstack.canGoForward(s), true);
});

test("a pivot run's results are another hop: its search text is in the key, so the same event clicked there does not share the chip", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = click(s, "RawProcessId", "936", ROW1);
  s = click(s, "TargetProcessId", "5497396", PIVOT);
  assert.deepEqual(names(s), ["Reach", "936", "5497396"]);
  assert.equal(navstack.sameHop(s, PIVOT), true);
  assert.equal(navstack.sameHop(s, ROW1), false);
  assert.equal(navstack.sameHop(s, null), false, "a page with no row never takes a click in place");
  s = navstack.advance(s, "#/w/ioc?value=936"); // a workflow opened with the value: no hop
  assert.equal(navstack.current(s).hop, undefined);
  assert.equal(navstack.sameHop(s, PIVOT), false, "the click after a page the panel reached itself is a new hop");
});

test("the same page reached again from another row keeps one entry and takes the new row, so the next click there updates it in place", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = click(s, "aid", "f07", ROW1);
  assert.equal(navstack.advance(s, hashOf("aid", "f07"), ROW2), s, "the browser does not move on the same hash, so neither does the stack");
  const other = navstack.label(s, { hop: ROW2 });
  assert.equal(other.stack.length, 2);
  assert.equal(navstack.sameHop(other, ROW2), true);
  assert.equal(navstack.sameHop(other, ROW1), false);
});

test("the mirror keeps each hop's row, and the platform switch hands the new document the row its click came from", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = click(s, "RawProcessId", "936", ROW1);
  const back = navstack.restore(navstack.serialize(s), navstack.current(s).hash);
  assert.equal(navstack.current(back).hop, ROW1);
  const SENT = "sentinel|ReachCrowdStrike_CL|ProcessRollup2|1|row9";
  const switched = navstack.restore(navstack.serialize(s, { switch: true, hop: SENT }), "#/f/Aid?st=ReachCrowdStrike_CL&value=f07");
  assert.equal(navstack.current(switched).hop, SENT);
  assert.equal(switched.stack.length, 2);
});

test("the stack keeps a tool page's entry like any other, and back from it returns to the entity page before it", () => {
  let s = navstack.label(navstack.initial("#/"), { kind: "page", name: "Reach" });
  s = navstack.label(navstack.advance(s, "#/f/RawProcessId?value=936"), { kind: "field", name: "RawProcessId", value: "936", entity: true });
  s = navstack.label(navstack.advance(s, "#/share"), { kind: "page", name: "Share" }); // a tool page: no entity flag, same as any other entry
  assert.equal(s.stack.length, 3, "the tool page is its own stack entry");
  assert.equal(navstack.canGoBack(s), true);
  const back = navstack.moveBack(s);
  assert.equal(navstack.current(back).hash, "#/f/RawProcessId?value=936");
  assert.equal(navstack.current(back).entity, true);
});
