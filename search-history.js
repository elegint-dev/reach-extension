// Injects a "History" button next to Splunk's own SPL/SPL2 control on the
// Search page (".left-container", which already holds the "SPL ▾" mode
// select and, once a query exists, "Convert to SPL2"), cloning that
// button's own classes so it reads as one more control in the same row.
//
// Splunk's native "SPL Search History" panel lives only on this page and
// only above the results; the button here opens the same history (same
// source, same filters) as a dropdown, so it is reachable without leaving
// wherever you're scrolled to. The rows come straight from Splunk's own
// `| history` generating command (verified against what the native panel
// itself dispatches), run through a normal reporting search. Nothing
// scrapes a log or a private endpoint.
//
// Local-only until opened: the dropdown is empty and no request is made
// until an explicit, isTrusted click opens it. That click is the trusted
// gesture live-lookup.js requires before it will touch the network.

(function () {
  if (!document.querySelector('link[href*="/static/@"], script[src*="/static/@"]')) return;

  const BUTTON_ID = "reach-history-btn";
  const STYLE_ID = "reach-history-style";
  const AUTORUN_KEY = "historyAutoRun";
  const TIMEMODE_KEY = "historyTimeMode";
  const TIME_MODES = {
    none: "Leave current time range alone",
    range: "Nearest Splunk preset for the same span, ending now",
    exact: "Exact original range (stays live if it originally ran to \"now\")",
    relative: "Same offset from now (shifts the whole window forward to today)",
  };

  // Splunk's own relative-time presets, read directly off this instance's
  // time-range picker ("Presets" panel, Relative/Other columns:
  // data-earliest/data-latest on each option), not computed generically.
  // Splunk's own snap units aren't uniform (Last 4 hours snaps to the
  // minute, Last 24 hours to the hour, Last 30 days to the day), so
  // reproducing them by formula would drift from what the picker offers;
  // baked in here rather than re-read at runtime since they're fixed
  // product presets, not per-instance config.
  const RANGE_PRESETS = [
    { earliest: "-15m", seconds: 900 },
    { earliest: "-60m@m", seconds: 3600 },
    { earliest: "-4h@m", seconds: 14400 },
    { earliest: "-24h@h", seconds: 86400 },
    { earliest: "-7d@h", seconds: 604800 },
    { earliest: "-30d@d", seconds: 2592000 },
  ];

  // The closest of Splunk's own presets to a given duration, never an
  // arbitrary "-12345s" (accurate to the second, but not a range a person
  // would recognize or would have picked themselves). Longer than the
  // largest bounded preset falls to "All time" rather than extrapolating
  // past it.
  function nearestRangePreset(durationSec) {
    const last = RANGE_PRESETS[RANGE_PRESETS.length - 1];
    if (durationSec > last.seconds) return { earliest: "0", latest: "now" };
    let best = RANGE_PRESETS[0];
    for (const p of RANGE_PRESETS) {
      if (Math.abs(p.seconds - durationSec) < Math.abs(best.seconds - durationSec)) best = p;
    }
    return { earliest: best.earliest, latest: "now" };
  }

  // Same search Splunk's own "SPL Search History" panel runs (read off its
  // dispatched job on this same build), excludes searches the UI itself
  // generates (this command, SPL2 recursion, table editor / pivot / dataset
  // scaffolding) so the list matches what a person actually typed.
  const HISTORY_SPL =
    '| history' +
    ' | search NOT search="| history*" AND NOT search="*metadata*" AND NOT search="*loadjob*"' +
    ' AND NOT savedsearch_name="*" AND NOT search="search" AND NOT search="*from sid*"' +
    ' AND NOT search="| eventcount summarize=false index=* index=_**" AND NOT provenance="UI:LocateData"' +
    ' AND NOT provenance="UI:TableEditor" AND NOT provenance="UI:DataModel" AND NOT provenance="UI:Pivot"' +
    ' AND NOT provenance="UI:Dataset" AND NOT search="| @spl2*"' +
    ' | dedup search | sort - _time | head 200';

  const STYLE = `
.reach-history-panel{position:fixed;z-index:100000;width:520px;max-height:60vh;display:flex;flex-direction:column;background:#1c1730;border:1px solid #332a55;border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.45);font:12px -apple-system,"Segoe UI",sans-serif;color:#cbd5e1}
.reach-history-panel[hidden]{display:none}
.reach-history-panel__head{display:flex;gap:6px;align-items:center;padding:8px;border-bottom:1px solid #332a55;flex:none}
.reach-history-panel__head input{flex:1;background:#0e1013;border:1px solid #2b3036;border-radius:3px;color:#dfe3e8;font:inherit;padding:4px 6px}
.reach-history-panel__iconbtn{background:none;border:1px solid #3d4552;border-radius:4px;color:#cbd5e1;cursor:pointer;font:inherit;padding:3px 8px;flex:none}
.reach-history-panel__iconbtn:hover{background:#241f3a}
.reach-history-panel__iconbtn.is-on{background:#332a55;border-color:#a78bfa;color:#efe9fc}
.reach-history-panel__iconbtn.is-on:hover{background:#3a2f63}
.reach-history-panel__timerow{display:flex;gap:6px;align-items:center;padding:0 8px 8px;border-bottom:1px solid #332a55;flex:none;font-size:10.5px;color:#9099a3}
.reach-history-panel__timerow[hidden]{display:none}
.reach-history-panel__timerow select{flex:1;background:#0e1013;border:1px solid #2b3036;border-radius:3px;color:#dfe3e8;font:inherit;font-size:10.5px;padding:3px 4px}
.reach-history-panel__cols{display:flex;gap:8px;padding:4px 10px;font-size:10.5px;color:#9099a3;border-bottom:1px solid #332a55;flex:none}
.reach-history-panel__cols button{background:none;border:0;color:inherit;font:inherit;cursor:pointer;padding:0}
.reach-history-panel__cols button:hover{color:#dfe3e8}
.reach-history-panel__colsearch{flex:1}
.reach-history-panel__colmode{width:52px;flex:none}
.reach-history-panel__coltime{width:64px;flex:none;text-align:right}
.reach-history-panel__body{overflow:auto;flex:1 1 auto}
.reach-history-row{display:flex;gap:8px;align-items:baseline;padding:6px 10px;border-bottom:1px solid #241f3a;cursor:pointer}
.reach-history-row:hover{background:#241f3a}
.reach-history-row__search{flex:1;font-family:monospace;font-size:11px;color:#dfe3e8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.reach-history-row__mode{color:#9099a3;font-size:10.5px;width:52px;flex:none}
.reach-history-row__time{color:#9099a3;font-size:10.5px;width:64px;flex:none;text-align:right}
.reach-history-panel__empty,.reach-history-panel__error,.reach-history-panel__loading{padding:16px;color:#9099a3;text-align:center}
.reach-history-panel__error{color:#e08c8c}
`;

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = STYLE;
    document.head.appendChild(style);
  }

  let liveReady = null;
  function live() {
    if (!liveReady) liveReady = import(chrome.runtime.getURL("live-lookup.js"));
    return liveReady;
  }

  // A row handed to the search bar or run from here is one entry in
  // Reach's search history (app/lib/searches.js), the document the
  // notebook page reads; the rows themselves stay Splunk's own | history.
  // The notebook is loaded beside it so the entry carries the current
  // investigation's id (the notebook registers that reader on import).
  let searchesReady = null;
  function noteHistory(text, ran) {
    if (!searchesReady) searchesReady = Promise.all([import(chrome.runtime.getURL("app/lib/searches.js")), import(chrome.runtime.getURL("app/lib/notebook.js"))]);
    return searchesReady.then(([m]) => m.record({ text, platform: "splunk", source: "history", origin: "history", ran, name: "History" })).catch(() => null);
  }

  // /<locale>/app/<namespace>/search, the namespace this page is already
  // running searches in, not a setting from elsewhere in the extension.
  function appNamespace() {
    const parts = location.pathname.split("/").filter(Boolean);
    const i = parts.indexOf("app");
    return i >= 0 && parts[i + 1] ? parts[i + 1] : "search";
  }

  function relTime(iso) {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return "";
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return "just now";
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const hr = Math.round(m / 60);
    if (hr < 24) return `${hr}h ago`;
    return `${Math.round(hr / 24)}d ago`;
  }

  // The bar hides the implicit leading "search" keyword a raw event search
  // dispatches with; match that so pasted-back text reads the way the bar
  // would have shown it, and matches what the native panel displays.
  function displaySearch(text) {
    return text.replace(/^search\s+/, "");
  }

  // Splunk 10's search bar is an Ace editor, not a plain input. Writing
  // .value does nothing; the editor instance's own API is what the page's
  // change listeners (and the "Convert to SPL2" control) actually observe.
  // That instance lives on a `.env` expando the page's own (main-world)
  // script attached to the element, invisible from this isolated-world
  // content script, so the actual write happens in search-history-inject.js,
  // reached by dispatching a DOM CustomEvent (unlike expando properties,
  // events do cross the isolated/main world boundary).
  const INJECT_ID = "reach-history-inject";
  let injectReady = null;
  // A <script src> loads asynchronously. Dispatching the event right after
  // appending it (as the first version of this file did) races the script's
  // own load and silently drops the very first click on a fresh page.
  // Caching the load promise makes every call after the first resolve
  // immediately, so only that first click pays the wait.
  function ensureInjected() {
    if (!injectReady) {
      injectReady = new Promise((resolve) => {
        const s = document.createElement("script");
        s.id = INJECT_ID;
        s.src = chrome.runtime.getURL("search-history-inject.js");
        s.addEventListener("load", () => resolve(), { once: true });
        (document.head || document.documentElement).appendChild(s);
      });
    }
    return injectReady;
  }

  function setSearchBarValue(text) {
    ensureInjected().then(() => {
      document.dispatchEvent(new CustomEvent("reach-history-set-search", { detail: { text } }));
    });
    return true;
  }

  // Sticky across sessions, mode settings, not per-search choices.
  let autoRun = false;
  let timeMode = "exact";
  chrome.storage.local.get([AUTORUN_KEY, TIMEMODE_KEY]).then((r) => {
    autoRun = Boolean(r[AUTORUN_KEY]);
    if (r[TIMEMODE_KEY] && TIME_MODES[r[TIMEMODE_KEY]]) timeMode = r[TIMEMODE_KEY];
    if (panel) panel.updateAutoRunUI();
  });
  function setAutoRun(v) {
    autoRun = v;
    chrome.storage.local.set({ [AUTORUN_KEY]: v }).catch(() => {});
    if (panel) panel.updateAutoRunUI();
  }
  function setTimeMode(v) {
    timeMode = v;
    chrome.storage.local.set({ [TIMEMODE_KEY]: v }).catch(() => {});
    if (panel) panel.updateAutoRunUI();
  }

  // Same "search " normalization live-lookup's callers already use for a
  // deep link (drawer.js, value-popup.js): a raw event search has no
  // leading command name in the bar, but the dispatch URL needs one.
  function qParam(text) {
    return /^\s*(search|\|)/.test(text) ? text : `search ${text}`;
  }

  // The four modes, each producing { earliest, latest } for the dispatch
  // URL (a relative string, "now", or a raw epoch number; Splunk accepts
  // all three). et/lt/execTime are epoch seconds from the history row
  // (search_et, search_lt, exec_time), the exact bounds and run time that
  // search actually used, whatever they display as in the picker.
  function timeParamsFor(mode, et, lt, execTime) {
    if (mode === "none") {
      // Whatever the picker is already showing on THIS page, carried
      // forward unchanged. Splunk always reflects the active range in its
      // own URL, so reading the current page's is reading the picker.
      const sp = new URLSearchParams(location.search);
      const cur = { earliest: sp.get("earliest"), latest: sp.get("latest") };
      return cur.earliest && cur.latest ? cur : {};
    }
    const etNum = Math.floor(parseFloat(et));
    const ltNum = Math.floor(parseFloat(lt));
    if (!Number.isFinite(etNum) || !Number.isFinite(ltNum)) return {};
    if (mode === "exact") {
      // A rolling-window preset (Last 24 hours, etc.) resolves latest to
      // the dispatch moment, so search_lt lands within a couple seconds of
      // exec_time. Freezing that back as a literal number replays a
      // stale, no-longer-moving endpoint instead of what was actually a
      // live "up to now" search, and Splunk's own picker shows it as an
      // opaque "Date time range" instead of the far more readable "Since
      // <date>". Detected by closeness to exec_time (10s of dispatch
      // latency, not exactness) and kept live rather than frozen; earliest
      // stays the literal original instant either way.
      const execNum = Math.floor(parseFloat(execTime));
      const latestWasNow = Number.isFinite(execNum) && Math.abs(execNum - ltNum) <= 10;
      return { earliest: String(etNum), latest: latestWasNow ? "now" : String(ltNum) };
    }
    if (mode === "range") {
      // Same duration, snapped to the nearest Splunk preset and replayed
      // as a rolling window ending now. A search that covered ~24h shows
      // up as "Last 24 hours" measured from right now, not from whenever
      // it originally ran.
      const durationSec = Math.max(1, ltNum - etNum);
      return nearestRangePreset(durationSec);
    }
    if (mode === "relative") {
      // Same offset-from-when-it-ran, replayed from right now. A search
      // that ran two days ago covering the two days before that shifts
      // forward to cover the same two-day span ending two days before today.
      const execNum = Math.floor(parseFloat(execTime));
      const nowSec = Math.floor(Date.now() / 1000);
      const base = Number.isFinite(execNum) ? execNum : ltNum;
      return { earliest: String(nowSec - (base - etNum)), latest: String(nowSec - (base - ltNum)) };
    }
    return {};
  }

  // Splunk Web loads a query AND its time range straight off the URL, and
  // runs it immediately, the same mechanism the drawer's "Run in Splunk"
  // link uses. That's the only reliable way to restore a time range too:
  // the picker is a widget, not a plain field, so there's no equivalent of
  // the Ace editor's setValue() to drive it in place.
  function runNow(text, row) {
    const locale = location.pathname.split("/")[1] || "en-US";
    const params = new URLSearchParams({ q: qParam(text) });
    const time = timeParamsFor(timeMode, row.search_et, row.search_lt, row.exec_time);
    if (time.earliest) params.set("earliest", time.earliest);
    if (time.latest) params.set("latest", time.latest);
    location.href = `${location.origin}/${locale}/app/${encodeURIComponent(appNamespace())}/search?${params.toString()}`;
  }

  class HistoryPanel {
    constructor() {
      this.rows = null;
      this.loading = false;
      this.error = null;
      this.filter = "";
      this.sortKey = "_time";
      this.sortDir = -1;
      this.anchor = null;
      this.el = this.build();
      document.body.appendChild(this.el);
      document.addEventListener("mousedown", (e) => {
        if (!this.isOpen() || this.el.contains(e.target) || e.target === this.anchor) return;
        this.close();
      });
      document.addEventListener("keydown", (e) => {
        if (this.isOpen() && e.key === "Escape") this.close();
      });
      window.addEventListener("resize", () => this.reposition());
      window.addEventListener("scroll", () => this.reposition(), true);
    }

    build() {
      const filterInput = document.createElement("input");
      filterInput.type = "text";
      filterInput.placeholder = "filter…";
      filterInput.addEventListener("input", (e) => {
        this.filter = e.target.value;
        this.renderRows();
      });
      this.filterInput = filterInput;

      const autoRunBtn = document.createElement("button");
      autoRunBtn.type = "button";
      autoRunBtn.className = "reach-history-panel__iconbtn";
      autoRunBtn.textContent = "▶ Auto-run";
      autoRunBtn.setAttribute("aria-pressed", "false");
      autoRunBtn.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        setAutoRun(!autoRun);
      });
      this.autoRunBtn = autoRunBtn;

      const refresh = document.createElement("button");
      refresh.type = "button";
      refresh.className = "reach-history-panel__iconbtn";
      refresh.title = "Refresh";
      refresh.textContent = "↻";
      refresh.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        this.load(true);
      });

      const head = document.createElement("div");
      head.className = "reach-history-panel__head";
      head.append(filterInput, autoRunBtn, refresh);

      const timeLabel = document.createElement("span");
      timeLabel.textContent = "On run, set time to:";
      const timeSelect = document.createElement("select");
      for (const [value, label] of Object.entries(TIME_MODES)) {
        timeSelect.appendChild(new Option(label, value));
      }
      timeSelect.addEventListener("change", (e) => {
        if (!e.isTrusted) return;
        setTimeMode(e.target.value);
      });
      this.timeSelect = timeSelect;

      const timeRow = document.createElement("div");
      timeRow.className = "reach-history-panel__timerow";
      timeRow.append(timeLabel, timeSelect);
      this.timeRow = timeRow;

      const colSearch = this.sortHeader("Search", "search", "reach-history-panel__colsearch");
      const colTime = this.sortHeader("Last Run", "_time", "reach-history-panel__coltime");
      const cols = document.createElement("div");
      cols.className = "reach-history-panel__cols";
      cols.append(colSearch, document.createElement("span"), colTime);
      cols.children[1].className = "reach-history-panel__colmode";
      cols.children[1].textContent = "Mode";

      this.body = document.createElement("div");
      this.body.className = "reach-history-panel__body";

      // updateAutoRunUI() calls renderRows(), which needs this.body. Must
      // run after it's created, not before (the bug that shipped: a click
      // threw here and the panel silently never appeared).
      this.updateAutoRunUI();

      const panel = document.createElement("div");
      panel.className = "reach-history-panel";
      panel.hidden = true;
      panel.setAttribute("role", "listbox");
      panel.setAttribute("aria-label", "Search history");
      panel.append(head, timeRow, cols, this.body);
      return panel;
    }

    updateAutoRunUI() {
      this.autoRunBtn.classList.toggle("is-on", autoRun);
      this.autoRunBtn.setAttribute("aria-pressed", String(autoRun));
      this.autoRunBtn.title = autoRun
        ? "Auto-run is on: clicking a row runs it immediately. Click to turn off."
        : "Auto-run is off: clicking a row loads it into the search bar without running it. Click to turn on.";
      this.timeRow.hidden = !autoRun;
      this.timeSelect.value = timeMode;
      this.renderRows();
    }

    sortHeader(label, key, className) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = label;
      btn.addEventListener("click", () => {
        this.sortDir = this.sortKey === key ? -this.sortDir : -1;
        this.sortKey = key;
        this.renderRows();
      });
      const wrap = document.createElement("span");
      wrap.className = className;
      wrap.appendChild(btn);
      return wrap;
    }

    isOpen() {
      return !this.el.hidden;
    }

    reposition() {
      if (!this.isOpen() || !this.anchor || !this.anchor.isConnected) return;
      const r = this.anchor.getBoundingClientRect();
      const width = 520;
      const left = Math.max(8, Math.min(r.left, window.innerWidth - width - 8));
      this.el.style.top = `${Math.round(r.bottom + 4)}px`;
      this.el.style.left = `${Math.round(left)}px`;
    }

    toggle(anchor) {
      if (this.isOpen()) {
        this.close();
        return;
      }
      this.anchor = anchor;
      this.el.hidden = false;
      this.reposition();
      this.filterInput.focus();
      if (this.rows === null) this.load();
    }

    close() {
      this.el.hidden = true;
    }

    async load(force = false) {
      if (this.loading) return;
      this.loading = true;
      this.error = null;
      this.renderRows();
      try {
        const lib = await live();
        const out = await lib.runReporting(HISTORY_SPL, { app: appNamespace(), earliest: "0", latest: "now" });
        this.rows = out.rows || [];
      } catch (err) {
        this.error = err && err.message ? err.message : String(err);
      } finally {
        this.loading = false;
        this.renderRows();
      }
    }

    renderRows() {
      this.body.replaceChildren();
      if (this.loading && this.rows === null) {
        const p = document.createElement("div");
        p.className = "reach-history-panel__loading";
        p.textContent = "Running | history against your Splunk…";
        this.body.appendChild(p);
        return;
      }
      if (this.error) {
        const p = document.createElement("div");
        p.className = "reach-history-panel__error";
        p.textContent = this.error;
        this.body.appendChild(p);
        return;
      }
      const rows = (this.rows || []).slice();
      const needle = this.filter.trim().toLowerCase();
      const filtered = needle ? rows.filter((r) => (r.search || "").toLowerCase().includes(needle)) : rows;
      filtered.sort((a, b) => {
        const av = a[this.sortKey] || "";
        const bv = b[this.sortKey] || "";
        return av < bv ? -this.sortDir : av > bv ? this.sortDir : 0;
      });
      if (!filtered.length) {
        const p = document.createElement("div");
        p.className = "reach-history-panel__empty";
        p.textContent = (this.rows || []).length ? "No searches match." : "No search history yet.";
        this.body.appendChild(p);
        return;
      }
      for (const row of filtered.slice(0, 200)) {
        const text = displaySearch(row.search || "");
        const line = document.createElement("div");
        line.className = "reach-history-row";
        line.setAttribute("role", "option");
        line.title = autoRun
          ? `${text}\n\nClick to run this now. Time range: ${TIME_MODES[timeMode]}`
          : `${text}\n\nClick to load into the search bar (not run). Press Enter there to run it.`;

        const search = document.createElement("span");
        search.className = "reach-history-row__search";
        search.textContent = text;

        const mode = document.createElement("span");
        mode.className = "reach-history-row__mode";
        mode.textContent = row.adhoc_search_level || "";

        const time = document.createElement("span");
        time.className = "reach-history-row__time";
        time.textContent = relTime(row._time);

        line.append(search, mode, time);
        line.addEventListener("click", async (e) => {
          if (!e.isTrusted) return;
          if (autoRun) {
            this.close();
            // The write lands before the page navigates away.
            await noteHistory(text, true);
            runNow(text, row);
          } else if (setSearchBarValue(text)) {
            noteHistory(text, false);
            this.close();
          }
        });
        this.body.appendChild(line);
      }
    }
  }

  let panel = null;

  // Re-anchors on every call rather than inserting once: Splunk's own React
  // tree re-renders .left-container's children (e.g. mounting/unmounting
  // "Convert to SPL2" as the query changes) using index-based reconciliation
  // that doesn't know about our foreign node, so a one-time appendChild can
  // end up left of Splunk's own controls after the next render. Making this
  // idempotent-but-repositioning (safe to call on every mutation, since the
  // MutationObserver below already does) keeps it pinned to the right spot.
  function ensureButton() {
    const left = document.querySelector(".left-container");
    if (!left) return;
    // Clone whichever of Splunk's own controls is present so ours reads as
    // one more button in the same row, on either build state: "Convert to
    // SPL2" (a query exists) or the "SPL ▾" mode select (empty search).
    const modelBtn = left.querySelector('[data-id="convert-to-spl2"]') || left.querySelector('[data-id="spl-mode-select"]');
    const anchor = modelBtn && (modelBtn.closest(".convert-to-spl2-container") || modelBtn.closest(".search-mode-container") || modelBtn);

    let btn = document.getElementById(BUTTON_ID);
    if (!btn) {
      btn = document.createElement("button");
      btn.type = "button";
      btn.id = BUTTON_ID;
      btn.textContent = "History";
      btn.title = "Your recent searches on this Splunk instance";
      btn.setAttribute("aria-haspopup", "true");
      btn.setAttribute("aria-label", "Search history");
      btn.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        ensureStyle();
        if (!panel) panel = new HistoryPanel();
        panel.toggle(btn);
      });
    }
    if (modelBtn && btn.className !== modelBtn.className) btn.className = modelBtn.className;

    if (anchor) {
      if (anchor.nextElementSibling !== btn) anchor.after(btn);
    } else if (left.lastElementChild !== btn) {
      left.appendChild(btn);
    }
  }

  // One ensureButton per idle slot, not one per mutation batch: the search
  // page mutates continuously while a job runs, and each call is several
  // document-wide lookups plus a possible move. Same scheduler as
  // json-tree-fields.js, with the same 200 ms ceiling, because a bare
  // requestIdleCallback on this page can wait tens of seconds.
  const runWhenIdle = window.requestIdleCallback
    ? (fn) => window.requestIdleCallback(fn, { timeout: 200 })
    : (fn) => window.requestAnimationFrame(fn);
  let scheduled = false;
  function scheduleEnsure() {
    if (scheduled) return;
    scheduled = true;
    runWhenIdle(() => {
      scheduled = false;
      ensureButton();
    });
  }
  const observer = new MutationObserver(scheduleEnsure);
  observer.observe(document.body, { childList: true, subtree: true });
  ensureButton();
})();
