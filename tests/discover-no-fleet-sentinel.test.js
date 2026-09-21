// The fleet baseline moved off Discover to the Falcon table's sourcetype
// page: a rendered Sentinel Discover page carries no "fleet" text
// anywhere in it, and lists no fleet baseline step among its queries.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as modules from "../app/lib/modules.js";
import { render } from "../app/views/discover-sentinel.js";

await catalogue.load();

function everyTitle(el) {
  return dom.walk(el, (n) => Boolean(n.attributes && n.attributes.title)).map((n) => n.attributes.title);
}

test("Sentinel Discover, with a known workspace and a full render, carries no 'fleet' text or title anywhere, and lists no fleet baseline step", async () => {
  const restoreDom = dom.install();
  try {
    const ctx = { params: {}, catalogue, modules, navigate() {}, href: () => "#", setUrl() {}, goBack() {} };
    const el = render(ctx);
    await el.afterMount();
    assert.doesNotMatch(dom.text(el), /fleet/i);
    for (const title of everyTitle(el)) assert.doesNotMatch(title, /fleet/i);
  } finally {
    restoreDom();
  }
});
