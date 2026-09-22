// A held value can be released from where it was held: the popup's Hold
// row (hold-and-benign.js, shared by the in-page popups and the field and
// value pages) and the Holding rail (holding.js). Release removes the
// notebook pin (notebook.removeEntry, the same model the notebook page's
// own × control uses) rather than leaving it around under a soft state.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
const { holdBlock } = await import("../app/lib/bands/hold-and-benign.js");
const { holding, heldPins } = await import("../app/components/holding.js");

const restore = dom.install();
test.after(() => restore());

const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  investigation.clear();
});

test("the popup's Hold row reads Held with a Release once the value is held, and Release un-holds it", async () => {
  const released = [];
  const block = holdBlock({
    field: "SHA256HashData",
    value: "8ae6",
    container: "crowdstrike:events:sensor",
    onHeld: (pin) => investigation.set(pin.field, pin.value),
    onReleased: (e) => released.push(e.field),
  });
  const btn = dom.walk(block, (n) => n.tagName === "BUTTON" && dom.text(n).trim() === "Hold")[0];
  btn.click();
  await flush();
  await flush();
  assert.equal(investigation.get("SHA256HashData"), "8ae6");
  const status = dom.walk(block, (n) => n.className === "reach-hold__status")[0];
  assert.match(dom.text(status), /^Held · .* · Release$/);
  const rel = dom.walk(block, (n) => n.tagName === "BUTTON" && dom.text(n).trim() === "Release")[0];
  assert.ok(rel, "a Release control is drawn once held");
  rel.click();
  await flush();
  await flush();
  assert.equal(dom.text(btn).trim(), "Hold", "the button returns to Hold once released");
  const inv = notebook.current();
  assert.deepEqual(inv.entries, [], "the pin is gone from the notebook's investigation");
  assert.deepEqual(released, ["SHA256HashData"], "the caller's onReleased ran so the tab fact clears too");
});

test("a chip on the Holding rail carries a release control that removes the pin from the notebook", async () => {
  const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr" };
  await notebook.record({ field: "SHA256HashData", value: "8ae6", from });
  investigation.set("SHA256HashData", "8ae6");
  const el = holding();
  await flush();
  assert.equal(el.count(), 1);
  const rel = el.querySelector(".r-holding__act--rm");
  assert.equal(rel.getAttribute("aria-label"), "Release SHA256HashData=8ae6");
  assert.equal(rel.getAttribute("title"), "Release from this investigation");
  dom.fire(rel, "click");
  await flush();
  assert.equal(el.count(), 0, "the rail's own count drops");
  assert.deepEqual(heldPins(), [], "the notebook holds nothing for the field once released");
});

test("the opened rail draws Holding once: the collapsed line, not a repeated header in the body", async () => {
  const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr" };
  await notebook.record({ field: "SHA256HashData", value: "8ae6", from });
  const el = holding();
  await flush();
  const line = el.querySelector(".r-holding__line");
  dom.fire(line, "click");
  const headings = dom.walk(el, (n) => dom.text(n).trim() === "Holding" || /^Holding\b/.test(dom.text(n).trim()));
  const words = headings.filter((n) => n.className && String(n.className).includes("r-holding__word"));
  assert.equal(words.length, 1, "only the collapsed line's own word draws \"Holding\"");
  const heldLabel = [...el.querySelectorAll(".r-holding__label")].find((n) => dom.text(n).trim() === "Held");
  assert.equal(heldLabel.parentElement.querySelector(".r-holding__addtoggle"), el.querySelector(".r-holding__addtoggle"), "Add rides the Held label's row, not a title of its own");
});

test("the opened rail is one block: header first, body (with the notebook line) last, so the closing line always falls after it", async () => {
  const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "fdr" };
  await notebook.record({ field: "SHA256HashData", value: "8ae6", from });
  const el = holding();
  await flush();
  const elements = el.children.filter((c) => c.tagName !== "#TEXT");
  assert.equal(elements[0].className, "r-holding__line", "the header is the rail's first child");
  const body = elements[elements.length - 1];
  assert.ok(body.classList.contains("r-holding__body"), "the body is the rail's last child, so the CSS closing line on it falls after everything, never between header and body");
  assert.ok(body.classList.contains("r-fold__body"), "the body carries the shared fold-body class the closing line keys on");
  const nbLink = el.querySelector(".r-holding__notebook");
  assert.ok(body.contains(nbLink), "the notebook line is inside the body the closing line is drawn on, so the line falls after it");
});

process.on("exit", restore);
