// The editor bridge: read the query the page's search editor holds, and
// put a term or a stage into it. The pattern builder and, later, the
// benign cache and the advisor all insert through here; nothing here runs
// a search.
//
//   place(query, text, { mode, form, field, platform }) -> { text, how, found }   pure
//       mode append   a term joins the search block (SPL: before the first top-level
//                     pipe, implicit AND; KQL: a new | where stage at the end); a
//                     stage goes on the end of the pipeline
//       mode replace  the field's existing term in the search block is swapped for
//                     the text; with none there, append (found: false says so)
//       mode set      the text is the whole query
//       form          term | stage, as ladder.js labels a rung
//   searchBlock(query, platform) -> { start, end }   the first top-level pipe segment
//   findTerm(block, field, platform) -> { start, end, text } | null
//   where() -> "page" | "tab" | "clipboard"   what apply() can reach from here
//   read() -> { ok, text, cursor } | { ok: false, reason }
//   set(text, mode?) -> { ok }               mode set | insert (at the cursor) | append
//   readKql() / setKql(text, mode?) / kqlReady()   the same over the Logs blade's Monaco,
//       through sentinel-editor-inject.js; setKql answers { ok, reason } since the
//       inject refuses an editor without a size (Simple mode hides one)
//   apply({ text, form, field, mode, platform, origin, trace }) -> { ok, how, notice }
//       every apply writes one search-history entry (app/lib/searches.js) for
//       the text handed on, whichever editor or the clipboard took it; trace
//       { origin, source, container, name, value } says which surface wrote it
//       Splunk on the search page: the Ace bar, through search-history-inject.js
//       (main world; the events are documented there). Sentinel in the Logs
//       blade frame: Monaco, through sentinel-editor-inject.js, with the
//       clipboard when the editor refuses. The app in the side panel or a
//       tab: the same request relayed to the active tab's content script as
//       a runtime message (APPLY_MESSAGE), then, with `origin` (a Splunk
//       instance the page named), to the search pages open on it; no
//       content script anywhere, or a served page: the text goes to the
//       clipboard with a notice.
//   onMessage(msg) -> Promise<result> | null   the content-script side of that relay
//   readFromTab() -> Promise<{ ok, text, cursor } | { ok: false, reason }> | null
//       the read counterpart of applyViaTab: the side panel or a served page
//       relays reach:editor:read to the active tab's content script; null
//       with no runtime, no active tab, or no content script there.
//   onReadMessage(msg) -> Promise<result> | null   the content-script side of that relay
//
// DOM and chrome.* are touched only inside the runtime functions; the
// placement is pure so it can be tested.

import * as searches from "./searches.js";

export const APPLY_MESSAGE = "reach:editor:apply";
export const READ_MESSAGE = "reach:editor:read";
export const INJECT_ID = "reach-history-inject";
export const INJECT_SRC = "search-history-inject.js";
export const KQL_INJECT_ID = "reach-editor-inject";
export const KQL_INJECT_SRC = "sentinel-editor-inject.js";
// The same size gate as sentinel-context.js queryText and the inject: a
// smaller Monaco is Simple mode's hidden one.
const KQL_MIN_WIDTH = 120;
const KQL_MIN_HEIGHT = 20;
const READ_TIMEOUT_MS = 1500;
const INJECT_TIMEOUT_MS = 4000;

// ---------------------------------------------------------------------------
// Placement (pure)

function normPlatform(p) {
  return p === "kql" || p === "sentinel" ? "kql" : "spl";
}

// Top-level positions of every pipe: outside double quotes (backslash
// escapes inside), outside [subsearches] and (parentheses). A KQL query has
// no subsearch brackets but the same rule reads it fine.
export function pipePositions(query) {
  const out = [];
  let quote = false;
  let depth = 0;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === "\\") i += 1;
      else if (c === '"') quote = false;
      continue;
    }
    if (c === '"') quote = true;
    else if (c === "[" || c === "(") depth += 1;
    else if (c === "]" || c === ")") depth = Math.max(0, depth - 1);
    else if (c === "|" && depth === 0) out.push(i);
  }
  return out;
}

// The search block: what comes before the first top-level pipe. A query
// that opens with a pipe (| tstats, | inputlookup, a KQL table name never
// does) has no search block.
export function searchBlock(query, platform) {
  const q = String(query || "");
  const pipes = pipePositions(q);
  const end = pipes.length ? pipes[0] : q.length;
  if (normPlatform(platform) === "kql") return { start: 0, end: pipes.length ? pipes[0] : q.length, empty: true };
  const head = q.slice(0, end);
  if (!head.trim() || head.trim().startsWith("|")) return { start: 0, end, empty: true };
  return { start: 0, end, empty: false };
}

function escapeField(field) {
  return String(field).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const QUOTED = '"(?:[^"\\\\]|\\\\.)*"';

// The field's existing term inside one block of the query: SPL field=v,
// field!=v, field IN (...), with a TERM(...) that precedes the field test
// taken along; KQL field <op> "v" or field in (...). The first match wins.
export function findTerm(block, field, platform) {
  const f = escapeField(field);
  const text = String(block || "");
  const res = normPlatform(platform) === "kql"
    ? [new RegExp(`(?:^|(?<=[\\s(]))${f}\\s*(?:==|=~|!=|!~|!?has_any|!?has|!?startswith|!?endswith|!?contains|matches\\s+regex|!?in~?)\\s*(?:${QUOTED}|\\((?:[^()"]|${QUOTED})*\\))`, "i")]
    : [
        new RegExp(`(?:^|(?<=\\s))(?:TERM\\((?:[^()"]|${QUOTED})*\\)\\s+)?(?:NOT\\s+)?${f}\\s*(?:=|!=)\\s*(?:${QUOTED}|\\S+)`),
        new RegExp(`(?:^|(?<=\\s))(?:NOT\\s+)?${f}\\s+IN\\s*\\((?:[^()"]|${QUOTED})*\\)`, "i"),
      ];
  let best = null;
  for (const re of res) {
    const m = re.exec(text);
    if (m && (!best || m.index < best.start)) best = { start: m.index, end: m.index + m[0].length, text: m[0] };
  }
  return best;
}

function topLevelOr(text) {
  let quote = false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === "\\") i += 1;
      else if (c === '"') quote = false;
      continue;
    }
    if (c === '"') quote = true;
    else if (c === "[" || c === "(") depth += 1;
    else if (c === "]" || c === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && text.startsWith("OR", i) && i > 0 && /\s/.test(text[i - 1]) && /\s/.test(text[i + 2] || "")) return true;
  }
  return false;
}

function joinEnd(query, piece) {
  const q = String(query || "");
  if (!q.trim()) return piece.replace(/^\s*\n/, "");
  return q.replace(/\s+$/, "") + "\n" + piece.replace(/^\s*\n?/, "");
}

export function place(query, text, { mode = "append", form = "term", field = "", platform = "spl" } = {}) {
  const q = String(query || "");
  const t = String(text || "");
  const kql = normPlatform(platform) === "kql";
  if (mode === "set") return { text: t, how: "set", found: null };
  if (!q.trim()) return { text: t, how: "set", found: null };
  if (mode === "replace" && form === "term" && field) {
    const block = searchBlock(q, platform);
    if (kql) {
      // Every | where stage is a place the column can be tested.
      const hit = findTerm(q, field, platform);
      if (hit) return { text: q.slice(0, hit.start) + t + q.slice(hit.end), how: "replaced", found: true };
    } else if (!block.empty) {
      const head = q.slice(block.start, block.end);
      const hit = findTerm(head, field, platform);
      if (hit) return { text: q.slice(0, block.start) + head.slice(0, hit.start) + t + head.slice(hit.end) + q.slice(block.end), how: "replaced", found: true };
    }
    const out = place(q, t, { mode: "append", form, field, platform });
    return { ...out, found: false };
  }
  if (mode === "cursor") return { text: t, how: "inserted", found: null };
  // append
  if (form === "stage") return { text: joinEnd(q, t.startsWith("|") ? t : `| ${t}`), how: "appended", found: null };
  if (kql) return { text: joinEnd(q, t.startsWith("|") ? t : `| where ${t}`), how: "appended", found: null };
  const block = searchBlock(q, platform);
  if (block.empty) {
    // No search block to join: a generating command opens the query, so
    // the term becomes a | search stage after it.
    return { text: joinEnd(q, `| search ${t}`), how: "appended", found: null };
  }
  let head = q.slice(block.start, block.end);
  const trailing = head.match(/\s*$/)[0];
  head = head.slice(0, head.length - trailing.length);
  const kw = head.match(/^\s*search\s+/i);
  const prefix = kw ? kw[0] : "";
  let body = head.slice(prefix.length);
  if (topLevelOr(body)) body = `(${body})`;
  const joined = `${prefix}${body} ${t}${trailing.includes("\n") ? trailing : trailing ? " " : ""}`;
  return { text: q.slice(0, block.start) + joined + q.slice(block.end), how: "appended", found: null };
}

// ---------------------------------------------------------------------------
// Runtime

function doc() {
  return typeof document !== "undefined" ? document : null;
}

function hasSearchBar() {
  const d = doc();
  return Boolean(d && d.querySelector && d.querySelector(".search-bar-input"));
}

// A Monaco with real size in this document: the Logs blade frame in KQL
// mode. The inject decides which instance a request lands in; this only
// says whether there is one to try.
function hasKqlEditor() {
  const d = doc();
  if (!d || !d.querySelectorAll) return false;
  for (const el of d.querySelectorAll(".monaco-editor")) {
    const r = typeof el.getBoundingClientRect === "function" ? el.getBoundingClientRect() : null;
    if (r && r.width >= KQL_MIN_WIDTH && r.height >= KQL_MIN_HEIGHT) return true;
  }
  return false;
}

function runtime() {
  const c = globalThis.chrome;
  return c && c.runtime && typeof c.runtime.getURL === "function" ? c : null;
}

export function where() {
  if (hasSearchBar() || hasKqlEditor()) return "page";
  const c = runtime();
  if (c && c.tabs && typeof c.tabs.sendMessage === "function" && typeof c.tabs.query === "function") return "tab";
  return "clipboard";
}

let injectReady = null;

// The main-world script is loaded once per page; search-history.js may
// have loaded it already, in which case the ready mark is on <html>.
export function ensureInjected() {
  const d = doc();
  if (!d) return Promise.reject(new Error("no document"));
  if (d.documentElement.dataset.reachSearchBridge === "1") return Promise.resolve();
  if (!injectReady) {
    injectReady = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the search bar bridge did not load")), INJECT_TIMEOUT_MS);
      d.addEventListener("reach-history-bridge-ready", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
      if (!d.getElementById(INJECT_ID)) {
        const c = runtime();
        if (!c) {
          clearTimeout(timer);
          reject(new Error("not an extension page"));
          return;
        }
        const s = d.createElement("script");
        s.id = INJECT_ID;
        s.src = c.runtime.getURL(INJECT_SRC);
        (d.head || d.documentElement).appendChild(s);
      }
    }).catch((err) => {
      injectReady = null;
      throw err;
    });
  }
  return injectReady;
}

let readSeq = 0;

export async function read() {
  if (!hasSearchBar()) return { ok: false, reason: "no search bar on this page", text: "", cursor: null };
  await ensureInjected();
  const d = doc();
  const id = `r${++readSeq}`;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      d.removeEventListener("reach-history-search-text", onReply);
      resolve({ ok: false, reason: "the search bar did not answer", text: "", cursor: null });
    }, READ_TIMEOUT_MS);
    function onReply(e) {
      if (!e.detail || e.detail.id !== id) return;
      clearTimeout(timer);
      d.removeEventListener("reach-history-search-text", onReply);
      resolve(e.detail.ok ? { ok: true, text: String(e.detail.text || ""), cursor: e.detail.cursor || null } : { ok: false, reason: "no editor behind the search bar", text: "", cursor: null });
    }
    d.addEventListener("reach-history-search-text", onReply);
    d.dispatchEvent(new CustomEvent("reach-history-read-search", { detail: { id } }));
  });
}

export async function set(text, mode = "set") {
  if (!hasSearchBar()) return { ok: false, reason: "no search bar on this page" };
  await ensureInjected();
  doc().dispatchEvent(new CustomEvent("reach-history-set-search", { detail: { text: String(text), mode } }));
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Sentinel: the Logs blade's Monaco, over sentinel-editor-inject.js

const kqlInjectReady = new WeakMap(); // per document: one load, one answer

// Resolves true once the inject is up, false when it cannot load (the
// page refused the script, or the ready mark never came). A failure is
// kept, so a blade where the bridge cannot load pays the wait once, not
// on every click.
export function ensureKqlInjected() {
  const d = doc();
  if (!d) return Promise.resolve(false);
  if (d.documentElement.dataset.reachEditorBridge === "1") return Promise.resolve(true);
  if (!kqlInjectReady.has(d)) {
    kqlInjectReady.set(d, new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), INJECT_TIMEOUT_MS);
      d.addEventListener("reach-editor-bridge-ready", () => {
        clearTimeout(timer);
        resolve(true);
      }, { once: true });
      let s = d.getElementById(KQL_INJECT_ID);
      if (!s) {
        const c = runtime();
        if (!c) {
          clearTimeout(timer);
          resolve(false);
          return;
        }
        s = d.createElement("script");
        s.id = KQL_INJECT_ID;
        s.src = c.runtime.getURL(KQL_INJECT_SRC);
        (d.head || d.documentElement).appendChild(s);
      }
      if (typeof s.addEventListener === "function") {
        s.addEventListener("error", () => {
          clearTimeout(timer);
          resolve(false);
        }, { once: true });
      }
    }));
  }
  return kqlInjectReady.get(d);
}

// One request to the inject and its reply, matched by id.
function askKql(request, replyName, detail, onTimeout) {
  const d = doc();
  const id = `k${++readSeq}`;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      d.removeEventListener(replyName, onReply);
      resolve(onTimeout);
    }, READ_TIMEOUT_MS);
    function onReply(e) {
      if (!e.detail || e.detail.id !== id) return;
      clearTimeout(timer);
      d.removeEventListener(replyName, onReply);
      resolve(e.detail);
    }
    d.addEventListener(replyName, onReply);
    d.dispatchEvent(new CustomEvent(request, { detail: { id, ...detail } }));
  });
}

const NO_BRIDGE = "the query editor bridge did not load";

export async function readKql() {
  if (!hasKqlEditor()) return { ok: false, reason: "no query editor on this page", text: "", cursor: null };
  if (!(await ensureKqlInjected())) return { ok: false, reason: NO_BRIDGE, text: "", cursor: null };
  const r = await askKql("reach-editor-read-kql", "reach-editor-kql-text", {}, { ok: false, reason: "the query editor did not answer" });
  return r.ok ? { ok: true, text: String(r.text || ""), cursor: r.cursor || null } : { ok: false, reason: r.reason || "no query editor behind the page", text: "", cursor: null };
}

export async function setKql(text, mode = "set") {
  if (!hasKqlEditor()) return { ok: false, reason: "no query editor on this page" };
  if (!(await ensureKqlInjected())) return { ok: false, reason: NO_BRIDGE };
  const r = await askKql("reach-editor-set-kql", "reach-editor-kql-set", { text: String(text), mode }, { ok: false, reason: "the query editor did not answer" });
  return r.ok ? { ok: true } : { ok: false, reason: r.reason || "the query editor refused" };
}

// Whether an insert would land: a sized Monaco here, the inject loaded and
// answering. The builder shows Insert only on true. One event round trip
// once the inject is up; nothing at all once it has failed to load.
export async function kqlReady() {
  if (!hasKqlEditor()) return false;
  try {
    const r = await readKql();
    return Boolean(r.ok);
  } catch {
    return false;
  }
}

async function toClipboard(text) {
  const nav = globalThis.navigator;
  if (!nav || !nav.clipboard || typeof nav.clipboard.writeText !== "function") return false;
  try {
    await nav.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

const HOW_WORD = { appended: "Added to the search", replaced: "Term replaced", inserted: "Inserted at the cursor", set: "Search bar set" };

// The request, applied to the page's own editor. Only called where the
// search bar is.
export async function applyHere(req) {
  const { text, form = "term", field = "", mode = "append", platform = "splunk" } = req || {};
  if (mode === "cursor") {
    const r = await set(text, "insert");
    return r.ok ? { ok: true, how: "inserted", notice: HOW_WORD.inserted } : { ok: false, how: null, notice: r.reason };
  }
  if (mode === "set") {
    const r = await set(text, "set");
    return r.ok ? { ok: true, how: "set", notice: HOW_WORD.set } : { ok: false, how: null, notice: r.reason };
  }
  const cur = await read();
  if (!cur.ok) return { ok: false, how: null, notice: cur.reason };
  const out = place(cur.text, text, { mode, form, field, platform });
  const r = await set(out.text, "set");
  if (!r.ok) return { ok: false, how: null, notice: r.reason };
  const notice = out.found === false ? `No ${field} term in the search to replace: added instead` : HOW_WORD[out.how] || "Done";
  return { ok: true, how: out.how, notice };
}

// The request, applied to the Logs blade's own editor. Only called where a
// sized Monaco is.
export async function applyHereKql(req) {
  const { text, form = "term", field = "", mode = "append", platform = "sentinel" } = req || {};
  if (mode === "cursor") {
    const r = await setKql(text, "insert");
    return r.ok ? { ok: true, how: "inserted", notice: HOW_WORD.inserted } : { ok: false, how: null, notice: r.reason };
  }
  if (mode === "set") {
    const r = await setKql(text, "set");
    return r.ok ? { ok: true, how: "set", notice: "Query set" } : { ok: false, how: null, notice: r.reason };
  }
  const cur = await readKql();
  if (!cur.ok) return { ok: false, how: null, notice: cur.reason };
  const out = place(cur.text, text, { mode, form, field, platform });
  // An append that only adds to the end goes in as the added part: the
  // cursor and the rest of the text stay where they were. A query with
  // trailing whitespace is re-set whole, since the placement trims it.
  const r = out.text.startsWith(cur.text) ? await setKql(out.text.slice(cur.text.length), "append") : await setKql(out.text, "set");
  if (!r.ok) return { ok: false, how: null, notice: r.reason };
  const notice = out.found === false ? `No ${field} term in the query to replace: added instead` : HOW_WORD[out.how] || "Done";
  return { ok: true, how: out.how, notice };
}

async function sendToTab(c, tab, req) {
  if (!tab || !Number.isInteger(tab.id)) return null;
  try {
    const res = await c.tabs.sendMessage(tab.id, { type: APPLY_MESSAGE, ...req });
    return res && typeof res === "object" ? res : null;
  } catch {
    return null; // no content script in that tab: not a Splunk page Reach is enabled on
  }
}

// The active tab first (the side panel sits beside it). With req.origin,
// a Splunk instance the page named, the app's own tab is active when it
// runs as a tab, so the search pages open on that origin are tried next,
// the last used first; the first one with a search bar takes the text.
async function applyViaTab(req) {
  const c = runtime();
  const { origin, ...msg } = req || {};
  const tabs = await c.tabs.query({ active: true, lastFocusedWindow: true }).catch(() => []);
  const active = tabs && tabs[0];
  let res = await sendToTab(c, active, msg);
  if ((res && res.ok) || !origin) return res;
  const others = (await c.tabs.query({ url: `${origin}/*` }).catch(() => [])).filter((t) => t && t.id !== (active && active.id)).sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
  for (const t of others) {
    const r = await sendToTab(c, t, msg);
    if (r && r.ok) return r;
    if (r && !res) res = r;
  }
  return res;
}

export async function apply(req) {
  const { text, platform = "splunk" } = req || {};
  const sentinel = platform === "sentinel" || platform === "kql";
  const trace = (req && req.trace) || {};
  await searches
    .record({ text, platform: sentinel ? "sentinel" : "splunk", source: trace.source || "insert", origin: trace.origin || "pattern", field: req && req.field, container: trace.container, name: trace.name, value: trace.value })
    .catch(() => null);
  const copied = async (why) => {
    const ok = await toClipboard(text);
    return { ok, how: ok ? "copied" : null, notice: ok ? why : "Could not reach the clipboard; select the text and copy it" };
  };
  if (sentinel) {
    if (!hasKqlEditor()) return copied("Copied. Paste it into the Logs editor");
    const res = await applyHereKql(req).catch((err) => ({ ok: false, how: null, notice: err && err.message ? err.message : String(err) }));
    if (res.ok) return res;
    return copied(res.notice ? `${res.notice}; copied instead` : "Copied. Paste it into the Logs editor");
  }
  const spot = where();
  if (spot === "page") return applyHere(req);
  if (spot === "tab") {
    const res = await applyViaTab(req);
    if (res && res.ok) return res;
    return copied(res && res.notice ? `${res.notice}; copied instead` : "Copied. No Splunk search bar in the active tab; paste it there");
  }
  return copied("Copied. Paste it into the search bar");
}

// The content-script side of the relay: value-popup.js hands runtime
// messages here and replies with what comes back. Null for any other
// message, so the caller's other listeners keep their turn.
export function onMessage(msg) {
  if (!msg || msg.type !== APPLY_MESSAGE) return null;
  if (!hasSearchBar()) return Promise.resolve({ ok: false, how: null, notice: "no search bar on this page" });
  return applyHere(msg).catch((err) => ({ ok: false, how: null, notice: err && err.message ? err.message : String(err) }));
}

// read()'s tab relay: the side panel has no search bar in its own
// document, so a click there asks the active tab's content script for
// what its search bar holds right now. Null with no runtime, no active
// tab, or no content script listening there (a tab Reach is not enabled
// on); the caller falls back to whatever text it already had.
export async function readFromTab() {
  const c = runtime();
  if (!c || !c.tabs || typeof c.tabs.query !== "function" || typeof c.tabs.sendMessage !== "function") return null;
  const tabs = await c.tabs.query({ active: true, lastFocusedWindow: true }).catch(() => []);
  const tab = tabs && tabs[0];
  if (!tab || !Number.isInteger(tab.id)) return null;
  try {
    const res = await c.tabs.sendMessage(tab.id, { type: READ_MESSAGE });
    return res && typeof res === "object" ? res : null;
  } catch {
    return null; // no content script in that tab: not a Splunk page Reach is enabled on
  }
}

// The content-script side of the read relay: value-popup.js's sibling to
// onMessage. Null for any other message, so it can share a listener.
export function onReadMessage(msg) {
  if (!msg || msg.type !== READ_MESSAGE) return null;
  if (!hasSearchBar()) return Promise.resolve({ ok: false, reason: "no search bar on this page", text: "", cursor: null });
  return read().catch((err) => ({ ok: false, reason: err && err.message ? err.message : String(err), text: "", cursor: null }));
}

export default {
  place,
  pipePositions,
  searchBlock,
  findTerm,
  where,
  read,
  set,
  readKql,
  setKql,
  kqlReady,
  apply,
  applyHere,
  applyHereKql,
  onMessage,
  readFromTab,
  onReadMessage,
  ensureInjected,
  ensureKqlInjected,
  APPLY_MESSAGE,
  READ_MESSAGE,
  INJECT_ID,
  INJECT_SRC,
  KQL_INJECT_ID,
  KQL_INJECT_SRC,
};
