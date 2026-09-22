// A view returns an element with unmount (or { el, unmount }); the shell
// calls it before the next view replaces the element, and the view's
// subscriptions end there: an event after unmount never redraws it.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";

dom.install();
const ORIGIN = "https://splunk.acme";
const c = fakeChrome({
  answer: (msg) => {
    if (msg.type === "reach:discover:tabs") return { origins: [{ origin: ORIGIN, tabs: 1 }] };
    throw new Error("no relay in this test");
  },
});
c.install();

const store = await import("../app/lib/store.js");
const fields = await import("../app/lib/pack-fields.js");
const catalogue = await import("../app/lib/catalogue.js");
await catalogue.load();
const modules = await import("../app/lib/modules.js");
const notebook = await import("../app/lib/notebook.js");
const sweep = await import("../app/lib/discovery-sweep.js");
const notebookView = await import("../app/views/notebook.js");
const discoverView = await import("../app/views/discover-splunk.js");
const fieldView = await import("../app/views/field.js");

// Several macrotask hops, not one: the fake's storage now answers on a
// real task, and a subscribed read-then-render chains more than one.
const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
};
const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr", search: { text: "index=fdr", sid: "1" } };

test("the notebook view stops redrawing on notebook changes once unmounted; a mounted one still does", async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  await notebook.start({ title: "one", from });
  const live = notebookView.render({ params: {}, navigate() {} });
  const gone = notebookView.render({ params: {}, navigate() {} });
  await settle();
  assert.equal(typeof gone.unmount, "function", "the view carries unmount");
  const liveTitle = live.children[0];
  const goneTitle = gone.children[0];
  gone.unmount();
  await notebook.note("a note after the page left");
  await settle();
  assert.notEqual(live.children[0], liveTitle, "the mounted view redrew");
  assert.equal(gone.children[0], goneTitle, "the unmounted view did not");
  live.unmount();
});

test("the Splunk discover view stops following the sweep once unmounted; a mounted one reflects the run", async () => {
  const ctx = { params: {}, catalogue, modules, navigate() {}, setUrl() {} };
  const live = discoverView.render(ctx);
  const gone = discoverView.render(ctx);
  await live.afterMount();
  await gone.afterMount();
  const progressOf = (el) => dom.text(el.querySelectorAll("p").find((p) => p.attributes["aria-live"] === "polite" && p.classList.contains("r-secondary") && /Full discovery/.test(dom.text(p))) || { textContent: "" });
  gone.unmount();
  await sweep.start(ORIGIN);
  await settle();
  assert.match(progressOf(live), /Full discovery finished/, "the mounted view shows the run");
  assert.equal(progressOf(gone), "", "the unmounted view heard nothing");
  live.unmount();
});

test("the field page's unmount ends its layer subscription: a discovered-layer change no longer refills its drawer", async () => {
  const layer = await import("../app/lib/layer.js");
  const fills = [];
  const ctx = { fields, catalogue, params: { name: "SHA256HashData", st: "crowdstrike:events:sensor", on: "ProcessRollup2" }, drawer: { fill: (q) => fills.push(q), fail() {} }, setUrl: () => "", navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
  const el = fieldView.render(ctx);
  document.body.replaceChildren(el);
  const row = dom.walk(el, (n) => n.attributes["data-row-id"] && n.attributes.tabindex === "0" && n.closest("[data-band-id]") && n.closest("[data-band-id]").attributes["data-band-id"] !== "here")[0];
  assert.ok(row, "an FDR ledger row");
  dom.fire(row, "click");
  await settle();
  const before = fills.length;
  assert.ok(before > 0, "the row filled the drawer");
  await layer.update(ORIGIN, (env) => ({ ...(env || {}), sourcetypes: {}, macros: { cs_index: "index=main" } }));
  await settle();
  assert.ok(fills.length > before, "a layer change refills the mounted page");
  const seen = fills.length;
  el.unmount();
  el.unmount();
  await layer.update(ORIGIN, (env) => ({ ...(env || {}), macros: { cs_index: "index=other" } }));
  await settle();
  assert.equal(fills.length, seen, "no refill after unmount");
  await layer.forget(ORIGIN);
});
