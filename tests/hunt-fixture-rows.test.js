// The Splunk fixture page carries rows the mac signing hunt keeps and rows
// it excludes, and tests/fixtures/hunt-rows.json is what the hunt's
// namespace search makes of the page: the search block of the SPL the
// pack renders, applied term by term to every event row's JSON tree, then
// the stats line's grouping and values. Neither fixture is regenerated
// from the code under test; the SPL is.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as workflows from "../app/lib/workflows.js";
import * as pivot from "../app/lib/pivot.js";
import { searchBlock } from "../app/lib/editor-bridge.js";

await catalogue.load();

const PAGE = readFileSync(new URL("./fixtures/pages/splunk-search.html", import.meta.url), "utf8");
const GOLDEN = JSON.parse(readFileSync(new URL("./fixtures/hunt-rows.json", import.meta.url), "utf8"));

const unescape = (s) => s.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

// Every event row on the page as { _time, sourcetype, ...leaves }.
function pageEvents() {
  const out = [];
  for (const row of PAGE.match(/<tr data-cid="[^"]*" version="2" class="shared-eventsviewer-list-body-row"[\s\S]*?<\/tr>/g)) {
    const ev = { _time: /data-time-iso="([^"]*)"/.exec(row)[1] };
    for (const m of row.matchAll(/<span class="key-name">\s*([^<]*?)\s*<\/span>\s*:\s*<span class="t \w+" data-path="[^"]*">\s*([^<]*?)\s*<\/span>/g)) ev[unescape(m[1])] = unescape(m[2]);
    const st = /data-field-name="sourcetype" title="([^"]*)"/.exec(row);
    ev.sourcetype = st ? st[1] : "";
    out.push(ev);
  }
  return out;
}

// The rendered search's block as terms: field=value (a * wildcard, quotes
// off), NOT ( ... ) groups, and field IN ( ... ) lists. Time bounds are
// not a page row's to answer and are skipped; index is not on a row.
function terms(block) {
  const out = [];
  const re = /NOT\s*\(([^)]*)\)|(\w+)\s+IN\s*\(([^)]*)\)|(\w+)=("(?:[^"\\]|\\.)*"|\S+)/g;
  for (const m of block.matchAll(re)) {
    if (m[1] !== undefined) out.push({ not: terms(m[1]) });
    else if (m[2]) out.push({ field: m[2], any: m[3].match(/"(?:[^"\\]|\\.)*"|[^\s,]+/g).map(unquote) });
    else if (!["earliest", "latest", "index"].includes(m[4])) out.push({ field: m[4], value: unquote(m[5]) });
  }
  return out;
}
const unquote = (v) => (v.startsWith('"') ? v.slice(1, -1).replace(/\\(.)/g, "$1") : v);
const like = (pattern, v) => new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`).test(v);
const holds = (t, ev) => (t.not ? !t.not.every((x) => holds(x, ev)) : t.any ? t.any.some((p) => like(p, ev[t.field] || "")) : like(t.value, ev[t.field] || ""));

const ctime = (iso) => {
  const d = new Date(iso);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}/${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
};

// The stats line as the SPL states it: count, min and max of _time, the
// values() columns, the by keys; one row per group, newest last_seen first.
function stats(spl, events) {
  const line = spl.slice(spl.indexOf("| stats"), spl.indexOf("| convert"));
  const by = /by\s+([^|]+)/.exec(line)[1].split(",").map((s) => s.trim());
  const values = [...line.matchAll(/values\((\w+)\) as (\w+)/g)].map((m) => [m[1], m[2]]);
  const groups = new Map();
  for (const ev of events) {
    const key = by.map((k) => ev[k]).join("\0");
    if (!groups.has(key)) groups.set(key, { evs: [] });
    groups.get(key).evs.push(ev);
  }
  return [...groups.values()]
    .map(({ evs }) => {
      const times = evs.map((e) => e._time).sort();
      const row = Object.fromEntries(by.map((k) => [k, evs[0][k]]));
      row.events = String(evs.length);
      row.first_seen = ctime(times[0]);
      row.last_seen = ctime(times[times.length - 1]);
      for (const [f, as] of values) {
        const set = [...new Set(evs.map((e) => e[f]).filter(Boolean))].sort();
        row[as] = set.length === 1 ? set[0] : set;
      }
      return row;
    })
    .sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1));
}

function rendered(result) {
  const def = workflows.get("hunt_mac_signing", { params: {} });
  const r = def.results({}).find((x) => x.id === result);
  return pivot.generate(r.pivot.edge, { index: "main", ...r.params }, { pack: packs.pack("crowdstrike-falcon") }).spl;
}

test("the page carries both the rows the namespace search excludes (Apple's own contactsd) and rows it keeps, and hunt-rows.json is the stats it makes of them", () => {
  const spl = rendered("namespace");
  const { start, end } = searchBlock(spl, "spl");
  const ts = terms(spl.slice(start, end));
  assert.ok(ts.some((t) => t.field === "sourcetype" && t.value === "crowdstrike:events:sensor"));
  assert.ok(ts.some((t) => t.not), "the signer test is a NOT group");
  const events = pageEvents();
  assert.equal(events.length, 11);
  const kept = events.filter((ev) => ts.every((t) => holds(t, ev)));
  const excluded = events.filter((ev) => ev.event_platform === "Mac" && !kept.includes(ev));
  assert.deepEqual([...new Set(excluded.map((e) => e.SigningId))].sort(), ["com.apple.contactsd", "com.evil.contactsd"]);
  const apple = excluded.filter((e) => e.SigningId === "com.apple.contactsd");
  assert.ok(apple.length && apple.every((e) => e.CsValidationCategory === "1" && e.TeamId === "-"), "the excluded Apple rows are Apple's own signature");
  assert.deepEqual(kept.map((e) => e.SigningId), ["com.apple.finder", "com.apple.finder", "com.apple.notasystemd"]);
  assert.deepEqual(stats(spl, kept), GOLDEN);
});

test("the path search keeps the /usr/libexec row and the row claiming Apple's contactsd path under another signer, and no Windows or Apple-signed contactsd row", () => {
  const spl = rendered("path");
  const { start, end } = searchBlock(spl, "spl");
  const ts = terms(spl.slice(start, end));
  const inList = ts.find((t) => t.field === "ImageFileName" && t.any);
  assert.ok(inList && inList.any.includes("/usr/libexec/*"), "the pack's Apple path list, as prefixes");
  const kept = pageEvents().filter((ev) => ts.every((t) => holds(t, ev)));
  assert.deepEqual(kept.map((e) => e.ImageFileName), ["/usr/libexec/notasystemd", "/System/Library/Frameworks/Contacts.framework/Support/contactsd"]);
  assert.deepEqual(stats(spl, kept), [GOLDEN[1], {
    aid: "0123456789abcdef0123456789abcdef",
    ComputerName: "mac-lab-01.example",
    ImageFileName: "/System/Library/Frameworks/Contacts.framework/Support/contactsd",
    events: "1",
    first_seen: "09/17/2026 16:11:40",
    last_seen: "09/17/2026 16:11:40",
    signing_id: "com.evil.contactsd",
    team_id: "ABCDE12345",
    validation_category: "4",
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  }]);
});
