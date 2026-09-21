// The enrichment row's write actions (app/lib/popup-ui.js enrichSourceRow):
// a result's actions draw as buttons after it; an action marked held
// draws only for a value already in the notebook, and a click on it
// reads the pin's reason and never records a pin (only Hold, Attach, the
// Holding add form and an unpin transfer write the held store). The
// chooser step draws the choices and sends on Send alone.

import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const { enrichBlock } = await import("../app/lib/popup-ui.js");

dom.install();
const settle = () => new Promise((r) => setTimeout(r, 5));
const VALUE = "evil-c2.example.net";
const hold = { field: "query", value: VALUE, container: "crowdstrike:events:sensor", platform: "splunk", scope: null, event: null, search: null };
const buttons = (el) => el.querySelectorAll(".reach-enrich__action").map((b) => dom.text(b));
const pins = () => (notebook.current() ? notebook.current().entries.filter((e) => e.kind === "pin") : []);

// A fetch-mode source whose call() answers a canned result with actions.
function sourceWith(result, calls) {
  return {
    id: "selfhosted",
    label: "Self-hosted (MISP / IntelOwl)",
    kinds: ["domain"],
    mode: "fetch",
    recipients: ["your own server"],
    call: async () => result,
    linkFor: () => null,
    calls,
  };
}
async function rowFor(result) {
  const source = sourceWith(result);
  const el = enrichBlock({ value: VALUE, offers: [{ source, kind: "domain", id: VALUE, allowed: true }], ask: async () => null, settingsUrl: "options.html#selfhosted", hold });
  const run = el.querySelector(".reach-run-btn--live");
  dom.fire(run, "click");
  await settle();
  return el;
}

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("a result's actions draw as one button each after the result, with the action's title", async () => {
  const el = await rowFor({ status: "ok", lines: ["1 matching attribute across 1 event.", "sightings: 2"], actions: [{ id: "sighting", label: "Record sighting", title: "One write, on this click.", run: async () => ({ status: "ok", lines: ["done"] }) }] });
  assert.deepEqual(buttons(el), ["Record sighting"]);
  assert.equal(el.querySelector(".reach-enrich__action").getAttribute("title"), "One write, on this click.");
  assert.equal(el.querySelector(".reach-enrich__action").dataset.action, "sighting");
});

test("an action marked held draws only once the value is in the notebook", async () => {
  const propose = { id: "propose", label: "Propose to MISP", held: true, run: async () => ({ status: "ok", lines: ["sent"] }) };
  const notHeld = await rowFor({ status: "empty", lines: ["Nothing on record for this value in MISP."], actions: [propose] });
  assert.deepEqual(buttons(notHeld), [], "no pin, no Propose button");

  await notebook.record({ field: "query", value: VALUE, from: { platform: "splunk", container: "crowdstrike:events:sensor" }, reason: "seen in DNS from the T1003.001 host" });
  const held = await rowFor({ status: "empty", lines: ["Nothing on record for this value in MISP."], actions: [propose] });
  assert.deepEqual(buttons(held), ["Propose to MISP"]);
});

test("a click on a held action carries the pin's reason to run() and never records a pin; the result draws in the row", async () => {
  await notebook.record({ field: "query", value: VALUE, from: { platform: "splunk", container: "crowdstrike:events:sensor" }, reason: "seen in DNS from the T1003.001 host" });
  const seen = [];
  const el = await rowFor({ status: "empty", lines: ["Nothing on record."], actions: [{ id: "propose", label: "Propose to MISP", held: true, run: async (ctx) => { seen.push(ctx); return { status: "ok", lines: ["Proposed as domain (attribute 8, to_ids false)."] }; } }] });
  assert.equal(pins().length, 1);
  dom.fire(el.querySelector(".reach-enrich__action"), "click");
  await settle();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].reason, "seen in DNS from the T1003.001 host");
  assert.equal(seen[0].pin.value, VALUE);
  assert.equal(pins().length, 1, "the click recorded no second pin");
  assert.equal(dom.text(el.querySelector('[data-line="headline"]')), "Proposed as domain (attribute 8, to_ids false).");
});

test("a synthetic click on an action runs nothing", async () => {
  let ran = 0;
  const el = await rowFor({ status: "ok", lines: ["hit"], actions: [{ id: "sighting", label: "Record sighting", run: async () => { ran += 1; return { status: "ok", lines: ["x"] }; } }] });
  dom.fire(el.querySelector(".reach-enrich__action"), "click", { isTrusted: false });
  await settle();
  assert.equal(ran, 0);
});

test("a choose result draws the prompt, the choices and Send; Send submits the picked id and the answer replaces the result; Cancel sends nothing", async () => {
  const submitted = [];
  const choose = { status: "choose", prompt: "Propose to which event?", choices: [{ id: "2", label: "Reach write-back check (2026-09-20)" }, { id: "1", label: "Reach demo (2026-09-19)" }], submit: async (id) => { submitted.push(id); return { status: "ok", lines: [`sent to ${id}`] }; } };
  const el = await rowFor({ status: "empty", lines: ["Nothing on record."], actions: [{ id: "propose", label: "Propose to MISP", run: async () => choose }] });
  dom.fire(el.querySelector(".reach-enrich__action"), "click");
  await settle();
  const chooser = el.querySelector(".reach-enrich__choose");
  assert.ok(chooser, "the chooser drew");
  assert.match(dom.text(chooser), /Propose to which event\?/);
  assert.deepEqual(chooser.querySelectorAll("option").map((o) => o.value), ["2", "1"]);
  assert.deepEqual(submitted, []);

  dom.fire(chooser.querySelector(".reach-enrich__cancel"), "click");
  assert.equal(el.querySelector(".reach-enrich__choose"), null, "Cancel removes the chooser");
  assert.deepEqual(buttons(el), ["Propose to MISP"], "Cancel puts the action back");
  assert.deepEqual(submitted, [], "Cancel sends nothing");

  dom.fire(el.querySelector(".reach-enrich__action"), "click");
  await settle();
  const again = el.querySelector(".reach-enrich__choose");
  again.querySelector("select").value = "1";
  dom.fire(again.querySelector(".reach-enrich__send"), "click");
  await settle();
  assert.deepEqual(submitted, ["1"]);
  assert.equal(dom.text(el.querySelector('[data-line="headline"]')), "sent to 1");
  assert.equal(pins().length, 0, "nothing in this flow held the value");
});
