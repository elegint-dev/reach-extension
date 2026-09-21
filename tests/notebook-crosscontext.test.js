// Two separate contexts on the same chrome.storage.local document: a
// popup's content script and the app page, each its own module instance of
// notebook.js (two import specifiers of the same file, the way Node's
// module cache stands in for two JS realms), sharing one fake store whose
// onChanged fires asynchronously, the way real chrome.storage does. A write
// queued in one context before the other's write is delivered must not
// erase it: every write rereads the document instead of mutating a cached
// copy. The fake is installed before store.js loads, so this file runs
// alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { fakeChrome } from "./_chrome.js";

fakeChrome({ deferChanges: true }).install();

const base = pathToFileURL(path.resolve("app/lib/notebook.js")).href;
const popup = await import(base + "?ctx=popup");
const app = await import(base + "?ctx=app");
assert.notEqual(popup, app, "two distinct module instances, like two JS realms");

const from = { platform: "splunk", container: "crowdstrike:events:sensor", scope: "main", event: { id: "ev-1", time: 1_758_204_115_000 }, search: { text: "index=main sourcetype=crowdstrike:events:sensor" } };

test("a write from one context does not erase an entry another context recorded first", async () => {
  await app.load();
  const inv = await app.start({ title: "test", trigger: "idk" });

  await popup.load(); // reads the "test" investigation as current, same as the app
  assert.equal(popup.currentId(), inv.id);
  const pin = await popup.record({ field: "ImageFileName", value: "powershell.exe", from, reason: "idk" });

  // The app has not yet been delivered the popup's onChanged event (it is
  // queued, not synchronous); it writes now anyway, from its own view of
  // the document, the way naming the investigation or setting the trigger
  // does from the notebook page.
  await app.setTrigger(inv.id, "idk, still");

  await new Promise((r) => setTimeout(r, 10)); // let both onChanged deliveries land

  assert.equal(app.get(inv.id).entries.length, 1, "the popup's pin survives the app's later write");
  assert.equal(app.get(inv.id).entries[0].id, pin.id);
  assert.match(app.exportMarkdown(inv.id), /Pinned `ImageFileName` = `powershell\.exe`/);
  assert.equal(popup.get(inv.id).entries.length, 1, "and the popup itself still sees it after the app's write is delivered back");
});
