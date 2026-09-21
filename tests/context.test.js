import { test } from "node:test";
import assert from "node:assert/strict";
import { contextFor, pageSourcetypes, searchStringTerm, rowEvent } from "../app/lib/context.js";

// Minimal DOM double: just enough of Element for context.js, closest(),
// querySelector[All]() by a [data-field-name="…"] attribute selector and by
// the class selectors context.js uses, textContent, dataset.
class El {
  constructor(tag, { classes = [], fieldName = null, text = "", children = [], attrs = {} } = {}) {
    this.tag = tag;
    this.classes = new Set(classes);
    this.fieldName = fieldName;
    this.text = text;
    this.children = children;
    this.attrs = attrs;
    this.parent = null;
    for (const c of children) c.parent = this;
  }
  get textContent() {
    return this.text || this.children.map((c) => c.textContent).join("");
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }
  get title() {
    return "";
  }
  matchesSimple(sel) {
    // "tag.cls:not(.other)": :not() with one class, tag optional
    const notM = /^([a-z]*)(\.[\w-]+)?:not\((\.[\w-]+)\)$/.exec(sel);
    if (notM) {
      if (notM[1] && this.tag !== notM[1]) return false;
      if (notM[2] && !this.classes.has(notM[2].slice(1))) return false;
      return !this.classes.has(notM[3].slice(1));
    }
    const tagCls = /^([a-z]+)(\.[\w-]+)$/.exec(sel);
    if (tagCls) return this.tag === tagCls[1] && this.classes.has(tagCls[2].slice(1));
    // ".cls[data-field-name=\"x\"]" or either part alone
    const m = /^(\.[\w-]+)?(?:\[data-field-name="([^"]+)"\])?$/.exec(sel);
    if (m && (m[1] || m[2])) {
      if (m[1] && !this.classes.has(m[1].slice(1))) return false;
      if (m[2] && this.fieldName !== m[2]) return false;
      return true;
    }
    return this.tag === sel;
  }
  // Comma list of simple selectors, or "ancestor descendant" pairs.
  matches(selector) {
    return selector.split(",").some((sel) => {
      const parts = sel.trim().split(/\s+/);
      if (!this.matchesSimple(parts[parts.length - 1])) return false;
      if (parts.length === 1) return true;
      let n = this.parent;
      while (n) {
        if (n.matchesSimple(parts[0])) return true;
        n = n.parent;
      }
      return false;
    });
  }
  closest(selector) {
    let n = this;
    while (n) {
      if (n.matches(selector)) return n;
      n = n.parent;
    }
    return null;
  }
  querySelectorAll(selector) {
    const out = [];
    const walk = (n) => {
      for (const c of n.children) {
        if (c.matches(selector)) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}
globalThis.CSS = { escape: (s) => s };

const fv = (name, text) => new El("a", { classes: ["f-v"], fieldName: name, text });

function eventRow({ sourcetype, index, disc, discValue, extra = [] }) {
  const fields = [fv("host", "wk-1"), fv("source", "/tmp/x"), sourcetype ? fv("sourcetype", sourcetype) : null, index ? fv("index", index) : null, disc ? fv(disc, discValue) : null, ...extra].filter(Boolean);
  const clicked = fv("SomeField", "42");
  const inner = new El("tr", { children: [new El("td", { children: [clicked] })] }); // a nested table cell, as in the JSON tree
  const row = new El("tr", { classes: ["shared-eventsviewer-list-body-row"], children: [new El("td", { children: [inner, new El("table", { classes: ["fields"], children: fields })] })] });
  return { row, clicked };
}

const doc = (rows) => new El("body", { children: rows });

test("search string is read from the ACE editor's lines and the URL q=, not the ACE textarea", () => {
  const aceInput = new El("textarea", { classes: ["ace_text-input"] });
  aceInput.value = "\u0001\u0001";
  const line1 = new El("div", { classes: ["ace_line"], text: "index=crowdstrike sourcetype=crowdstrike:events:sensor" });
  const editor = new El("div", { classes: ["ace_editor"], children: [aceInput, line1] });
  const body = doc([new El("div", { classes: ["search-bar"], children: [editor] })]);
  assert.equal(searchStringTerm("index", body), "crowdstrike");
  assert.equal(searchStringTerm("sourcetype", body), "crowdstrike:events:sensor");

  const empty = doc([]);
  empty.defaultView = { location: { search: "?q=search%20index%3Dmain%20sourcetype%3Daws%3Acloudtrail" } };
  assert.equal(searchStringTerm("index", empty), "main");
  assert.equal(searchStringTerm("sourcetype", empty), "aws:cloudtrail");
});

test("reads sourcetype and discriminator off the clicked event's row, not the nested table", () => {
  const { row, clicked } = eventRow({ sourcetype: "crowdstrike:events:sensor", disc: "event_simpleName", discValue: "ProcessRollup2" });
  const body = doc([row]);
  const ctx = contextFor(clicked, { discriminators: { "crowdstrike:events:sensor": "event_simpleName" }, doc: body });
  assert.equal(ctx.sourcetype, "crowdstrike:events:sensor");
  assert.equal(ctx.basis.sourcetype, "row");
  assert.deepEqual(ctx.discriminator, { field: "event_simpleName", value: "ProcessRollup2" });
  assert.equal(ctx.index, null);
  assert.equal(ctx.container, row);
});

test("discriminator is only read once the sourcetype is known", () => {
  const { row, clicked } = eventRow({ sourcetype: "aws:cloudtrail", disc: "event_simpleName", discValue: "Bogus" });
  const ctx = contextFor(clicked, { discriminators: { "crowdstrike:events:sensor": "event_simpleName" }, doc: doc([row]) });
  assert.equal(ctx.sourcetype, "aws:cloudtrail");
  assert.equal(ctx.discriminator, null);
});

test("another row's sourcetype never leaks into this one", () => {
  const a = eventRow({ sourcetype: "aws:cloudtrail" });
  const b = eventRow({ sourcetype: "crowdstrike:events:sensor" });
  const body = doc([a.row, b.row]);
  assert.equal(contextFor(a.clicked, { doc: body }).sourcetype, "aws:cloudtrail");
  assert.equal(contextFor(b.clicked, { doc: body }).sourcetype, "crowdstrike:events:sensor");
});

test("falls back to the search string, and says so", () => {
  const bar = new El("textarea", { classes: ["search-field"] });
  bar.value = 'index=main sourcetype="aws:cloudtrail" eventName=CreateUser';
  const { row, clicked } = eventRow({});
  const body = doc([row, new El("div", { classes: ["search-bar"], children: [bar] })]);
  const ctx = contextFor(clicked, { doc: body });
  assert.equal(ctx.sourcetype, "aws:cloudtrail");
  assert.equal(ctx.basis.sourcetype, "search");
  assert.equal(ctx.index, "main");
  assert.equal(ctx.basis.index, "search");
  assert.equal(searchStringTerm("sourcetype", body), "aws:cloudtrail");
});

test("a wildcard in the search string is not a sourcetype", () => {
  const bar = new El("textarea", { classes: ["search-field"] });
  bar.value = "index=* sourcetype=crowdstrike:*";
  const body = doc([new El("div", { classes: ["search-bar"], children: [bar] })]);
  assert.equal(searchStringTerm("sourcetype", body), null);
  assert.equal(searchStringTerm("index", body), null);
});

test("a field-NAME link in the sidebar is never read as a value", () => {
  const a = eventRow({ sourcetype: "aws:cloudtrail" });
  const sidebarName = new El("a", { fieldName: "sourcetype", text: "sourcetype" }); // no .f-v
  const body = doc([new El("div", { classes: ["sidebar"], children: [sidebarName] }), a.row]);
  assert.deepEqual(pageSourcetypes(body), ["aws:cloudtrail"]);
  assert.equal(contextFor(sidebarName, { doc: body }).sourcetype, null);
});

test("pageSourcetypes: distinct values across the page", () => {
  const a = eventRow({ sourcetype: "aws:cloudtrail" });
  const b = eventRow({ sourcetype: "crowdstrike:events:sensor" });
  const c = eventRow({ sourcetype: "aws:cloudtrail" });
  assert.deepEqual(pageSourcetypes(doc([a.row, b.row, c.row])), ["aws:cloudtrail", "crowdstrike:events:sensor"]);
  assert.deepEqual(pageSourcetypes(doc([])), []);
});

// Splunk's own time cell ("formated-time") splits the date and the time
// across sibling <span>s with a <br> between: reading it as plain
// textContent runs them together with no separator.
test("rowEvent reads the time cell's data-time-iso attribute, not its concatenated text", () => {
  const cell = new El("span", { classes: ["formated-time"], attrs: { "data-time-iso": "2022-07-27T10:42:41.056+00:00" }, children: [new El("span", { text: "7/27/22" }), new El("br"), new El("span", { text: "10:42:41.056 AM" })] });
  const row = new El("tr", { classes: ["shared-eventsviewer-list-body-row"], children: [cell] });
  assert.equal(rowEvent(row).time, "2022-07-27T10:42:41.056+00:00");
});

test("rowEvent joins the time cell's own text with a space when it carries no data-time-iso", () => {
  const cell = new El("span", { classes: ["formated-time"], children: [new El("span", { text: "7/27/22" }), new El("br"), new El("span", { text: "10:42:41.056 AM" })] });
  const row = new El("tr", { classes: ["shared-eventsviewer-list-body-row"], children: [cell] });
  assert.equal(rowEvent(row).time, "7/27/22 10:42:41.056 AM");
});
