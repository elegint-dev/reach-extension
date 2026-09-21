// benignBlock's state machine (app/lib/popup-ui.js): unmarked, marked with
// a reason and an expiry, marked with neither, and unmark. No DOM lib: a
// fake element carries just enough of Element (createElement,
// createTextNode, appendChild, replaceChildren, hidden) for h.js and the
// block's own status line to run.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const benign = await import("../app/lib/benign.js");
const notebook = await import("../app/lib/notebook.js");
const { benignBlock } = await import("../app/lib/popup-ui.js");

assert.equal(store.backend(), "memory");

class FakeNode {}
function fakeElement(tag) {
  return Object.assign(new FakeNode(), {
    tag,
    tagName: String(tag).toUpperCase(),
    className: "",
    dataset: {},
    style: {},
    hidden: false,
    attrs: {},
    value: "",
    children: [],
    setAttribute(k, v) {
      this.attrs[k] = v;
    },
    addEventListener(type, fn) {
      (this.listeners ||= {})[type] = fn;
    },
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    append(...items) {
      for (const item of items) this.appendChild(item);
    },
    replaceChildren(...items) {
      this.children = [];
      for (const item of items) this.appendChild(item);
    },
  });
}

// The text a real browser would show: replaceChildren stringifies a
// non-Node, non-string argument (including a bare null) instead of
// dropping it, so this walk reproduces that rather than hiding it.
function shown(el) {
  if (el instanceof FakeNode) {
    if (el.children && el.children.length) return el.children.map(shown).join("");
    return el.textContent !== undefined ? String(el.textContent) : "";
  }
  return String(el);
}

function click(el) {
  return el.listeners && el.listeners.click && el.listeners.click();
}

beforeEach(async () => {
  globalThis.document = {
    createElement: fakeElement,
    createTextNode: (text) => Object.assign(new FakeNode(), { textContent: String(text) }),
  };
  globalThis.Node = FakeNode;
  await store.remove(benign.KEY);
  await benign.load({ force: true });
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("unmarked: the bar (button, reason, expiry) is drawn and the status line is empty", () => {
  const root = benignBlock({ field: "ImageFileName", value: "svchost.exe", container: "crowdstrike:events:sensor", platform: "splunk" });
  const [bar, status] = root.children;
  assert.equal(bar.hidden, false);
  assert.equal(shown(status), "");
});

test("marked with a reason and an expiry: one status line, no raw null, Unmark at the end", async () => {
  const root = benignBlock({ field: "ImageFileName", value: "svchost.exe", container: "crowdstrike:events:sensor", platform: "splunk" });
  const [bar, status] = root.children;
  const [btn, reasonEl, expiry] = bar.children;
  reasonEl.value = "fleet standard binary";
  expiry.value = "30";
  await click(btn);
  assert.equal(bar.hidden, true, "the input and the expiry select collapse once a mark exists");
  const text = shown(status);
  assert.doesNotMatch(text, /\bnull\b/, "no raw null in the collapsed row");
  assert.match(text, /^Known benign · fleet standard binary · expires \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC · marked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
  const un = status.children[status.children.length - 1];
  assert.equal(shown(un), "Unmark", "Unmark is the last element on the line");
});

test("marked with no reason and no expiry: 'no reason given' and 'no expiry', not null", async () => {
  const root = benignBlock({ field: "ImageFileName", value: "rundll32.exe", container: "crowdstrike:events:sensor", platform: "splunk" });
  const [bar, status] = root.children;
  const [btn] = bar.children;
  await click(btn);
  const text = shown(status);
  assert.doesNotMatch(text, /\bnull\b/);
  assert.match(text, /^Known benign · no reason given · no expiry · marked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
});

test("unmark: the bar returns, the status line clears, and marking again works", async () => {
  const root = benignBlock({ field: "ImageFileName", value: "conhost.exe", container: "crowdstrike:events:sensor", platform: "splunk" });
  const [bar, status] = root.children;
  const [btn, reasonEl, expiry] = bar.children;
  reasonEl.value = "gold image binary";
  expiry.value = "30";
  await click(btn);
  const un = status.children[status.children.length - 1];
  await click(un);
  assert.equal(bar.hidden, false, "the reason input and the expiry select return only after Unmark");
  assert.deepEqual([reasonEl.value, expiry.value], ["", "0"], "Unmark clears the reason and resets the expiry so a fresh mark starts blank");
  assert.equal(shown(status), "");
  assert.equal(benign.list({ field: "ImageFileName", container: "crowdstrike:events:sensor" }).length, 0);
});
