// The verdict's fourth line before any environment has measured a fleet
// baseline: "No fleet baseline yet · run it", linking to the Falcon
// sourcetype page. Once one environment has, the usual fleet line (from
// fleetLine/prevalenceOf, org-corpus.test.js) draws instead.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import * as layer from "../app/lib/layer.js";
import * as known from "../app/lib/known.js";
import { verdictBlock } from "../app/lib/popup-ui.js";

await catalogue.load();

const CONTACTSD = {
  event_platform: "Mac",
  event_simpleName: "ProcessRollup2",
  aid: "c26d2f327b6a49eebc1432e094ee4a84",
  ImageFileName: "/System/Library/Frameworks/Contacts.framework/Support/contactsd",
  SHA256HashData: "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9",
  SigningId: "com.apple.contactsd",
  TeamId: "-",
  CodeSigningFlags: "637618689",
  CsValidationCategory: "1",
};

// A DOM stand-in with just enough of the real API (h.js only needs
// createElement/createTextNode, setAttribute, appendChild/replaceChildren)
// for verdictBlock to draw into, and enough to walk back out of.
class FakeNode {}
function fakeElement(tag) {
  const attrs = {};
  return Object.assign(new FakeNode(), {
    tagName: String(tag).toUpperCase(),
    className: "",
    dataset: {},
    style: {},
    hidden: false,
    children: [],
    setAttribute(k, v) { attrs[k] = v; },
    getAttribute(k) { return attrs[k]; },
    addEventListener() {},
    appendChild(child) { this.children.push(child); return child; },
    append(...items) { for (const item of items) this.appendChild(item); },
    replaceChildren(...items) { this.children = []; for (const item of items) this.appendChild(item); },
  });
}

function find(node, className) {
  if (!node || !node.children) return null;
  for (const c of node.children) {
    if (c.className === className) return c;
    const found = find(c, className);
    if (found) return found;
  }
  return null;
}

function findTag(node, tag) {
  if (!node || !node.children) return null;
  for (const c of node.children) {
    if (c.tagName === tag) return c;
    const found = findTag(c, tag);
    if (found) return found;
  }
  return null;
}

function textOf(node) {
  if (!node) return "";
  if (!node.children || !node.children.length) return node.textContent || "";
  return node.children.map(textOf).join("");
}

async function draw(fn) {
  const savedDocument = globalThis.document;
  const savedNode = globalThis.Node;
  globalThis.Node = FakeNode;
  globalThis.document = { createElement: fakeElement, createTextNode: (text) => Object.assign(new FakeNode(), { textContent: String(text) }) };
  try {
    return await fn();
  } finally {
    globalThis.document = savedDocument;
    globalThis.Node = savedNode;
  }
}

test("the verdict's fleet line says no fleet baseline yet, linking to the Falcon sourcetype page, when no environment has measured one", async () => {
  await draw(async () => {
    const root = verdictBlock({
      field: "SHA256HashData",
      value: CONTACTSD.SHA256HashData,
      container: "crowdstrike:events:sensor",
      platform: "splunk",
      event: CONTACTSD,
      catalogue,
      appUrl: (hash) => `index.html?platform=splunk${hash}`,
    });
    // 80ms, not 30: the fleet line's read chains through the fake's
    // macrotask-resolving storage/permissions (tests/_chrome.js).
    await new Promise((resolve) => setTimeout(resolve, 80));
    const fleet = find(root, "reach-verdict__fleet");
    assert.ok(fleet, "a fleet line is drawn even with no baseline");
    assert.match(textOf(fleet), /^No fleet baseline yet · run it$/);
    const link = findTag(fleet, "A");
    assert.ok(link, "the line links to run one");
    assert.equal(link.getAttribute("href"), "index.html?platform=splunk#/st/crowdstrike%3Aevents%3Asensor");
  });
});

test("the verdict's fleet line says no fleet baseline yet with no link when the caller gives no appUrl", async () => {
  await draw(async () => {
    const root = verdictBlock({ field: "SHA256HashData", value: CONTACTSD.SHA256HashData, container: "crowdstrike:events:sensor", platform: "splunk", event: CONTACTSD, catalogue });
    await new Promise((resolve) => setTimeout(resolve, 80));
    const fleet = find(root, "reach-verdict__fleet");
    assert.match(textOf(fleet), /^No fleet baseline yet · run it$/);
    assert.ok(!findTag(fleet, "A"), "no appUrl, no link");
  });
});

test("the verdict's fleet line reads the corpus once an environment has measured one, not the no-baseline text", async () => {
  const origin = "https://splunk.fleet-baseline-test.example";
  const doc = known.projectOrgCorpus(
    [{ sha256: CONTACTSD.SHA256HashData, path: CONTACTSD.ImageFileName, signing_id: CONTACTSD.SigningId, platform: "Mac", hosts: 5, events: 10, first_seen: "2026-09-01T00:00:00Z", last_seen: "2026-09-10T00:00:00Z" }],
    { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk" },
  );
  await layer.update(origin, (e) => { e.org_corpus = doc; });
  try {
    await draw(async () => {
      const root = verdictBlock({ field: "SHA256HashData", value: CONTACTSD.SHA256HashData, container: "crowdstrike:events:sensor", platform: "splunk", event: CONTACTSD, catalogue, appUrl: (hash) => hash });
      await new Promise((resolve) => setTimeout(resolve, 80));
      const fleet = find(root, "reach-verdict__fleet");
      assert.match(textOf(fleet), /^Seen on 5 of your hosts, first 2026-09-01$/);
    });
  } finally {
    await layer.forget(origin);
  }
});
