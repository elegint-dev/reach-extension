// settings-contract.md §7, S1 through S15, one assertion group per row,
// against the same moduleList() element options.html and the panel's
// Settings fold both draw.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import { moduleList } from "../app/components/moduleList.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

const shared = fakeChrome({ storage: false });
shared.install();
await modules.hydrate();

function rows(list) {
  return dom.walk(list, (n) => n.attributes && n.attributes["data-module"]);
}
function classed(node, cls) {
  return dom.walk(node, (n) => n.classList && n.classList.contains(cls));
}
function pillOf(row) {
  return classed(row, "r-module__pill")[0] || null;
}
function foldOf(row) {
  return classed(row, "r-module__fold")[0] || null;
}
function sendsOf(row) {
  return classed(row, "r-module__sends")[0];
}
function whyOf(row) {
  return classed(row, "r-module__why")[0] || null;
}

const WHY = {
  shell: "The frame every other page draws inside",
  catalogue: "What everything else here means",
  pivots: "The edges every pivot walks",
  hold: "Where held values and the investigation live",
  settings: "This page: a settings page cannot switch off its own controls",
};

const SENDS_TABLE = {
  splunk: { nothing: ["shell", "catalogue", "hold", "settings", "verdicts", "enrich-bundled", "coverage", "runbooks", "benign", "share"], "own-siem": ["pivots", "discovery", "workflows", "pattern", "advisor"], "third-party": ["virustotal", "circl", "epss", "selfhosted"] },
  sentinel: { nothing: ["shell", "catalogue", "hold", "settings", "verdicts", "enrich-bundled", "coverage", "runbooks", "benign", "share", "pivots", "discovery", "workflows", "pattern", "advisor"], "third-party": ["virustotal", "circl", "epss", "selfhosted"] },
};

for (const context of ["panel", "options"]) {
  for (const platform of ["splunk", "sentinel"]) {
    test(`S1 (${context}, ${platform}): Core and Modules resolve as data-heading h2s`, () => {
      const list = moduleList({ platform, context });
      const byHeading = Object.fromEntries(dom.walk(list, (n) => n.tagName === "H2").map((n) => [n.dataset.heading, dom.text(n)]));
      assert.equal(byHeading.core, "Core");
      assert.equal(byHeading.modules, "Modules");
    });

    test(`S2 (${context}, ${platform}): every optional row's pill reads exactly On or Off at rest`, () => {
      const list = moduleList({ platform, context });
      for (const row of rows(list)) {
        const entry = modules.get(row.attributes["data-module"]);
        if (entry.tier === "core") continue;
        const pill = pillOf(row);
        assert.ok(pill, `${entry.id}: no pill`);
        assert.match(dom.text(pill), /^(On|Off)$/, `${entry.id}: pill text`);
      }
    });

    test(`S3 (${context}, ${platform}): every Core row's fixed marker and why line`, () => {
      const list = moduleList({ platform, context });
      for (const row of rows(list)) {
        const entry = modules.get(row.attributes["data-module"]);
        if (entry.tier !== "core") continue;
        assert.equal(classed(row, "r-module__fixed").length, 1, `${entry.id}: fixed marker`);
        assert.equal(dom.text(classed(row, "r-module__fixed")[0]), "Always on");
        assert.equal(dom.text(whyOf(row)), WHY[entry.id], `${entry.id}: why line`);
        assert.equal(pillOf(row), null, `${entry.id}: no pill`);
      }
    });

    test(`S4 (${context}, ${platform}): every row's sends indicator matches the table, at rest`, () => {
      const list = moduleList({ platform, context });
      const table = SENDS_TABLE[platform];
      for (const row of rows(list)) {
        const id = row.attributes["data-module"];
        const sends = sendsOf(row);
        const hit = Object.entries(table).find(([, ids]) => ids.includes(id));
        assert.ok(hit, `${id}: not in the sends table for ${platform}`);
        const kind = hit[0];
        assert.equal(sends.dataset.sends, kind, `${id}: data-sends`);
        const text = dom.text(sends);
        if (kind === "nothing") assert.equal(text, "Sends: nothing", id);
        else if (kind === "own-siem") assert.equal(text, "Sends: your own Splunk, on your click", id);
        else if (id === "selfhosted") assert.equal(text, "Sends: the origin you set, on your click", id);
        else assert.match(text, /^Sends: /, id);
      }
    });

    test(`S12 (${context}, ${platform}): the pill and the sends indicator are never inside a fold`, () => {
      const list = moduleList({ platform, context });
      for (const row of rows(list)) {
        const fold = foldOf(row);
        if (!fold) continue;
        const inside = (el) => {
          for (let p = el && el.parentNode; p; p = p.parentNode) if (p === fold) return true;
          return false;
        };
        assert.equal(inside(pillOf(row)), false, `${row.attributes["data-module"]}: pill inside fold`);
        assert.equal(inside(sendsOf(row)), false, `${row.attributes["data-module"]}: sends inside fold`);
      }
    });

    test(`S13 (${context}, ${platform}): no checkbox or disabled attribute represents on/off or fixed state`, () => {
      const list = moduleList({ platform, context });
      for (const row of rows(list)) {
        const entry = modules.get(row.attributes["data-module"]);
        if (entry.tier === "core") {
          assert.equal(classed(row, "r-module__fixed")[0].tagName, "SPAN");
        } else {
          const pill = pillOf(row);
          assert.equal(pill.tagName, "BUTTON");
          assert.equal(pill.attributes.disabled, undefined, `${entry.id}: pill disabled`);
        }
      }
    });

    test(`S14 (${context}, ${platform}): data-module and data-tier are present on all nineteen sections`, () => {
      const list = moduleList({ platform, context });
      const expected = modules.MODULES.filter((m) => m.platforms.includes(platform));
      const seen = rows(list);
      assert.equal(seen.length, expected.length, `${platform}: row count`);
      for (const row of seen) {
        assert.ok(row.attributes["data-module"]);
        assert.ok(row.attributes["data-tier"]);
      }
    });
  }
}

test("S10: the seven on-tier rows are present but not asserted off (companion to S8/S9)", () => {
  const list = moduleList({ platform: "splunk" });
  const onTier = ["verdicts", "enrich-bundled", "discovery", "coverage", "workflows", "runbooks", "benign"];
  for (const id of onTier) assert.ok(rows(list).some((r) => r.attributes["data-module"] === id), id);
});

test("S8, S9: on a fresh profile every off-tier pill reads Off, none of the four third-party rows is On", async () => {
  modules.reset();
  const fresh = fakeChrome({ storage: false });
  const r = fresh.install();
  try {
    await modules.hydrate();
    const list = moduleList({ platform: "splunk" });
    const offTier = ["virustotal", "circl", "epss", "selfhosted", "pattern", "advisor", "share"];
    for (const id of offTier) {
      const row = rows(list).find((x) => x.attributes["data-module"] === id);
      assert.equal(dom.text(pillOf(row)), "Off", id);
    }
    for (const id of ["virustotal", "circl", "epss", "selfhosted"]) {
      const row = rows(list).find((x) => x.attributes["data-module"] === id);
      assert.notEqual(dom.text(pillOf(row)), "On", id);
    }
  } finally {
    r();
    modules.reset();
    shared.install();
    await modules.hydrate();
  }
});

test("S5, S6, S7: the VirusTotal round trip (Splunk)", async () => {
  modules.reset();
  const fresh = fakeChrome({ storage: false });
  const r = fresh.install();
  try {
    await modules.hydrate();
    const list = moduleList({ platform: "splunk" });
    const row = rows(list).find((x) => x.attributes["data-module"] === "virustotal");
    const pill = pillOf(row);
    const fold = foldOf(row);

    // S5: click while Off opens the fold only; no other row's fold opens.
    dom.fire(pill, "click");
    await new Promise((res) => setTimeout(res, 0));
    assert.equal(dom.text(pill), "Off");
    assert.equal(fold.open, true);
    const input = classed(row, "r-field__input").find((n) => n.tagName === "INPUT");
    assert.ok(input, "the API key input");
    const saveBtn = classed(row, "r-btn").find((n) => dom.text(n) === "Save");
    assert.ok(saveBtn, "a Save button");
    for (const other of rows(list)) if (other !== row) { const f = foldOf(other); if (f) assert.equal(f.open, false, other.attributes["data-module"]); }

    // S6: Save with a well-formed placeholder key turns the pill On.
    // 60ms, not 20: chrome.permissions (still present with storage: false)
    // now answers on the fake's macrotask, and Save chains more than one.
    input.value = "a".repeat(64);
    const status = classed(row, "r-module__status")[0];
    dom.fire(saveBtn, "click");
    await new Promise((res) => setTimeout(res, 60));
    assert.equal(dom.text(pill), "On");
    assert.match(dom.text(status), /Saved/);

    // S7: clicking the pill while On is the off/wipe path; the key is gone.
    dom.fire(pill, "click");
    await new Promise((res) => setTimeout(res, 60));
    assert.equal(dom.text(pill), "Off");
    assert.equal(input.value, "");
  } finally {
    r();
    modules.reset();
    shared.install();
    await modules.hydrate();
  }
});

test("S11: the Sentinel gate on the Splunk base URL row", () => {
  const has = (platform) => {
    const list = moduleList({ platform });
    return dom.walk(list, (n) => n.tagName === "SPAN" && dom.text(n) === "Splunk base URL").length;
  };
  assert.equal(has("sentinel"), 0);
  assert.equal(has("splunk"), 1);
});

test("S15: the panel fold and options.html produce the same groups and row order, at a fixed storage state", () => {
  for (const platform of ["splunk", "sentinel"]) {
    const groupsOf = (context) => {
      const list = moduleList({ platform, context });
      return {
        headings: dom.walk(list, (n) => n.tagName === "H2").map((n) => n.dataset.heading),
        ids: rows(list).map((n) => n.attributes["data-module"]),
      };
    };
    const panel = groupsOf("panel");
    const options = groupsOf("options");
    assert.deepEqual(panel.headings, options.headings, `${platform}: heading order`);
    assert.deepEqual(panel.ids, options.ids, `${platform}: row order`);
  }
});

test.after(() => restore());
