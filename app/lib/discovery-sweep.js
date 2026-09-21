// Full discovery: every sourcetype the inventory knows, through the same
// per-sourcetype searches the Discover page runs one click at a time
// (discovery.js: profile, recordTypes, provenance, decodes). One click on
// "Full discovery" authorises the whole batch: it is listed before it
// starts (plan), runs one sourcetype at a time, can be cancelled between
// steps, and stops itself after three relay failures in a row (no Splunk
// tab, a session that expired). Nothing here is scheduled; the page has
// to be open and the user has to have clicked.
//
// Each step is the existing per-sourcetype function with the arguments
// the row buttons pass, so the record a sweep writes is the record those
// buttons would have written. No concept logic: what the sweep learns,
// catalogue.js and the Coverage page read as they read any discovery.
//
//   plan(env, { skipFresh, skipMissing, now })  → { run: [sourcetype], skipped: [{ sourcetype, reason }] }   pure
//   remaining(names, env, since)                → the names not profiled since `since` (resume)             pure
//   isRelayError(err)                           → true for a failure of the relay, not of one search       pure
//   start(origin, { index, earliest, discriminatorFor, macrosFor, skipFresh, skipMissing, resume, timeoutMs })
//                                               → the final state; rejects only if one is already running
//   cancel()                                    → stop before the next step; the job in flight finishes
//   state()                                     → the live state, a copy
//   subscribe(fn)                               → fn(state) after every change; returns unsubscribe
//   load(origin)                                → the persisted record for a reopened page, or null
//   incomplete(rec)                             → true when a persisted sweep stopped short
//   progressLine(st)                            → "3 of 20: aws:cloudtrail (provenance), 2 skipped, 1 failed"
//                                                 with "; storage: <notice>" appended when the layer dropped something
//
// State: { running, origin, index, window, started_at, finished_at, total,
//          done, current: { sourcetype, step } | null, skipped, errors:
//          [{ sourcetype, step, error }], notices: [string], cancelled,
//          abort: string | null }
//
// The state lives in this module (a hash navigation does not stop a
// sweep) and is mirrored to store key "catalogue.discovery.sweep", per
// origin, after every sourcetype, so a page opened later can say
// "stopped after n of N" and offer to resume. On completion the discovered
// layer gets env.sweep = { at, total, done } (discovery.markSweep).
//
// No DOM.

import * as store from "./store.js";
import * as layer from "./layer.js";
import * as discovery from "./discovery.js";

export const KEY = "catalogue.discovery.sweep";
export const FRESH_SECONDS = 7 * 86400;
export const RELAY_FAILURES_MAX = 3;
export const STEP_TIMEOUT_MS = 180000;
export const DECODE_CONCURRENCY = 2;
export const STEPS = Object.freeze(["profile", "structure", "provenance", "decodes"]);

// ---------------------------------------------------------------------------
// Planning

// Which sourcetypes a sweep over `env` (one origin's discovered record)
// would run, sorted, and which it leaves out and why:
//   fresh     profiled within FRESH_SECONDS (skipFresh, the default)
//   missing   the latest inventory did not return it (skipMissing)
export function plan(env, { skipFresh = true, skipMissing = true, now = Date.now() } = {}) {
  const run = [];
  const skipped = [];
  const names = Object.keys((env && env.sourcetypes) || {}).sort((a, b) => a.localeCompare(b));
  for (const name of names) {
    const rec = env.sourcetypes[name] || {};
    if (skipMissing && rec.missing_since) {
      skipped.push({ sourcetype: name, reason: "missing" });
      continue;
    }
    if (skipFresh && rec.profiled_at && now - new Date(rec.profiled_at).getTime() < FRESH_SECONDS * 1000) {
      skipped.push({ sourcetype: name, reason: "fresh" });
      continue;
    }
    run.push(name);
  }
  return { run, skipped };
}

// Resume: a sourcetype profiled since the sweep started was done by it.
export function remaining(names, env, since) {
  const t = since ? new Date(since).getTime() : 0;
  return names.filter((name) => {
    const rec = env && env.sourcetypes ? env.sourcetypes[name] : null;
    return !(rec && rec.profiled_at && new Date(rec.profiled_at).getTime() >= t);
  });
}

// A relay failure is the path to Splunk being gone, not one search being
// wrong: no tab, no agent, the worker down, or a session Splunk refuses.
// The next search would fail the same way, so the sweep stops after a few.
const RELAY_TEXT = /No open Splunk tab|No Reach agent answered|Background relay failed|No answer from the extension|session needs a refresh|Could not establish connection|Extension context invalidated/;
export function isRelayError(err) {
  if (!err) return false;
  if (err.status === 401 || err.status === 403) return true;
  return RELAY_TEXT.test(String(err.message || err));
}

// ---------------------------------------------------------------------------
// State

function fresh() {
  return { running: false, origin: null, index: "*", window: "-7d", started_at: null, finished_at: null, total: 0, done: 0, current: null, skipped: 0, errors: [], notices: [], cancelled: false, abort: null };
}

let st = fresh();
let cancelFlag = false;
const listeners = new Set();

export function state() {
  return { ...st, errors: st.errors.slice(), notices: (st.notices || []).slice(), current: st.current ? { ...st.current } : null };
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify() {
  const snap = state();
  for (const fn of listeners) {
    try {
      fn(snap);
    } catch (err) {
      console.error(err);
    }
  }
}

function set(patch) {
  Object.assign(st, patch);
  notify();
}

// The persisted mirror: the state without `running` (a page opened later
// has no runner) and with the snapshot a resume needs.
function record() {
  const rec = state();
  delete rec.running;
  return rec;
}

// Own write chain, as discovery.js has: one store key, several origins.
let writes = Promise.resolve();
function persist() {
  const origin = st.origin;
  const rec = record();
  const next = writes.then(async () => {
    const all = (await store.get(KEY)) || {};
    all[origin] = rec;
    await store.set(KEY, all);
  });
  writes = next.catch(() => {});
  return next;
}

export async function load(origin) {
  await writes;
  const all = (await store.get(KEY)) || {};
  return all[origin] || null;
}

export function incomplete(rec) {
  if (!rec || !rec.started_at) return false;
  return Boolean(rec.cancelled || rec.abort || rec.done < rec.total || !rec.finished_at);
}

export function progressLine(s) {
  if (!s || !s.started_at) return "";
  const head = s.current ? `${s.done} of ${s.total}: ${s.current.sourcetype ? `${s.current.sourcetype} (${s.current.step})` : s.current.step}` : `${s.done} of ${s.total}`;
  const tail = [`${s.skipped} skipped`, `${s.errors.length} failed`];
  const notices = (s.notices || []).map((n) => String(n).replace(/\.$/, ""));
  return `${head}, ${tail.join(", ")}${notices.length ? `; storage: ${notices.join("; ")}` : ""}`;
}

// A notice the layer returned (something the byte budget dropped) is
// kept once, however many steps repeat it.
function noteLayer(out) {
  if (!out || !out.notice || st.notices.includes(out.notice)) return;
  st.notices.push(out.notice);
  notify();
}

// ---------------------------------------------------------------------------
// The runner

export function cancel() {
  if (!st.running) return;
  cancelFlag = true;
  set({ cancelled: true });
}

function errorText(err) {
  return err && err.message ? err.message : String(err);
}

// One sourcetype's steps, in order, each in its own try/catch. Returns
// false when the sweep has to stop (cancelled, or the relay is gone).
async function sweepOne(origin, name, { index, earliest, discriminatorFor, macrosFor, timeoutMs, relay }) {
  const step = async (label, fn) => {
    if (cancelFlag) return "stop";
    set({ current: { sourcetype: name, step: label } });
    try {
      const out = await fn();
      relay.failures = 0;
      noteLayer(out);
      return out;
    } catch (err) {
      st.errors.push({ sourcetype: name, step: label, error: errorText(err) });
      if (isRelayError(err) && ++relay.failures >= RELAY_FAILURES_MAX) {
        set({ abort: `Stopped after ${relay.failures} relay failures in a row: ${errorText(err)}` });
        return "stop";
      }
      notify();
      return null;
    }
  };
  const known = await layer.read(origin);
  const rec = (known && known.sourcetypes[name]) || {};
  // The row buttons' arguments: the sourcetype's own indexes when the
  // inventory named them, else the page's index box; the catalogue's
  // discriminator when it has one; decodes forced only on a re-read.
  const idx = rec.indexes && rec.indexes.length ? rec.indexes : index;
  const opts = { index: idx, earliest, timeoutMs };

  let r = await step("profile", () => discovery.profile(origin, name, { ...opts, sample: 5000 }));
  if (r === "stop") return false;
  const disc = discriminatorFor ? discriminatorFor(name) : null;
  if (disc) {
    r = await step("structure", () => discovery.recordTypes(origin, name, disc, opts));
    if (r === "stop") return false;
  }
  const macroNames = macrosFor ? macrosFor(name) : [];
  r = await step("provenance", () => discovery.provenance(origin, name, { macros: macroNames }));
  if (r === "stop") return false;
  const lookups = r && r.env && r.env.sourcetypes[name] ? r.env.sourcetypes[name].lookups || [] : [];
  if (lookups.length) {
    r = await step("decodes", () => discovery.decodes(origin, name, { force: Boolean(rec.decodes_at), concurrency: DECODE_CONCURRENCY, timeoutMs }));
    if (r === "stop") return false;
  }
  return true;
}

export async function start(origin, { index = "*", earliest = "-7d", discriminatorFor = null, macrosFor = null, skipFresh = true, skipMissing = true, resume = false, timeoutMs = STEP_TIMEOUT_MS } = {}) {
  if (st.running) throw new Error("A full discovery is already running.");
  if (!origin) throw new Error("origin is required");
  const prev = resume ? await load(origin) : null;
  const now = new Date().toISOString();
  cancelFlag = false;
  st = fresh();
  set({
    running: true,
    origin,
    index: prev && prev.index ? prev.index : index,
    window: prev && prev.window ? prev.window : earliest,
    started_at: prev && prev.started_at ? prev.started_at : now,
  });
  const relay = { failures: 0 };
  // The inventory first, every time: the list is what Splunk carries now.
  try {
    set({ current: { sourcetype: null, step: "inventory" } });
    noteLayer(await discovery.inventory(origin, { index: st.index, earliest: st.window, timeoutMs }));
    relay.failures = 0;
  } catch (err) {
    st.errors.push({ sourcetype: null, step: "inventory", error: errorText(err) });
    if (isRelayError(err)) relay.failures++;
    notify();
  }
  const env = (await layer.read(origin)) || { sourcetypes: {} };
  const planned = plan(env, { skipFresh, skipMissing });
  let names = planned.run;
  let skipped = planned.skipped.length;
  let done = 0;
  if (prev) {
    // Picking up where it stopped: whatever this sweep already profiled
    // counts as done (it is fresh now, but it is not a skip), and the
    // rest is the list.
    const all = plan(env, { skipFresh: false, skipMissing }).run;
    const left = new Set(remaining(all, env, st.started_at));
    const finished = all.filter((n) => !left.has(n));
    done = finished.length;
    names = planned.run.filter((n) => left.has(n));
    skipped = planned.skipped.filter((x) => !finished.includes(x.sourcetype)).length;
  }
  set({ total: done + names.length, done, skipped, current: null });
  await persist();
  const stepOpts = { index: st.index, earliest: st.window, discriminatorFor, macrosFor, timeoutMs, relay };
  for (const name of names) {
    if (cancelFlag || st.abort) break;
    const ok = await sweepOne(origin, name, stepOpts);
    if (!ok) {
      // Stopped mid-sourcetype: its record holds whatever steps finished;
      // the count stays honest and the persisted `current` says where.
      await persist();
      break;
    }
    set({ done: st.done + 1, current: null });
    await persist();
  }
  // The stamp lands before the state says finished, so a page redrawing
  // on that change already sees it. A sweep with nothing to run (every
  // sourcetype fresh, or no inventory at all) computed nothing and does
  // not move the stamp.
  const finished_at = new Date().toISOString();
  const complete = !cancelFlag && !st.abort && st.total > 0 && st.done >= st.total;
  if (complete) noteLayer(await discovery.markSweep(origin, { at: finished_at, total: st.total, done: st.done }));
  set({ running: false, finished_at, current: cancelFlag || st.abort ? st.current : null });
  await persist();
  return state();
}

export default { KEY, FRESH_SECONDS, RELAY_FAILURES_MAX, STEP_TIMEOUT_MS, DECODE_CONCURRENCY, STEPS, plan, remaining, isRelayError, start, cancel, state, subscribe, load, incomplete, progressLine };
