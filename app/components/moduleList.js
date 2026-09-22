// moduleList: the settings surface, drawn from the module registry
// (app/lib/modules.js). Four fixed groups, Core, Modules, Environment,
// Data (settings-contract.md): Core is the five always-on modules with a
// fixed marker, never a toggle; Modules is the fourteen optional modules
// with an On/Off pill; Environment and Data are the non-module settings,
// moved out of the module list entirely. Same element for the panel's
// gear fold (settingsBar.js) and for options.html, so a popup's "set it
// up" link lands on the module's head (id module-<id>).
//
//   moduleList({ platform, context })
//     platform   draw this platform's modules; null draws every module
//     context    "panel" | "options": where "Show setup again" leads
//   el.refreshCopy()   re-ask the copy.js lines after a surface change
//
// A row's fold (`.r-module__fold`, a native <details>) holds the sends
// sentence in full, the host permission line, drafted settings with Save
// and Forget, and a storage-keys line with Clear; it is never gated on
// on/off (SPEC 254, "never a greyed control") except CIRCL and EPSS, whose
// fold is the storage-keys line alone and only while their flag key is
// set (settings-contract.md §2.2). Every write goes through modules.js,
// wipe.js or the store the value belongs to.

import { h, replace } from "./h.js";
import * as modules from "../lib/modules.js";
import * as store from "../lib/store.js";
import * as settings from "../lib/settings.js";
import * as pinned from "../lib/pinned.js";
import * as scope from "../lib/scope.js";
import * as sentinelSettings from "../lib/sentinel-settings.js";
import * as onboarding from "../lib/onboarding.js";
import * as router from "../lib/router.js";
import * as wipe from "../lib/wipe.js";
import * as falconDictionary from "../lib/falcon-dictionary.js";
import * as selfhosted from "../lib/enrich/selfhosted.js";
import { looksLikeKey, describeError, PUBLIC_QUOTA } from "../lib/virustotal.js";
import { PLATFORM } from "../lib/platform.js";
import { KEYS } from "../lib/storage-keys.js";
import { copy } from "../lib/copy.js";
import { hasChrome, ask } from "../lib/runtime.js";

const KEYED_IDS = new Set(["virustotal", "selfhosted"]);

// The why line, Core only: pinned, verbatim, tested (S3).
const CORE_WHY = {
  shell: "The frame every other page draws inside",
  catalogue: "What everything else here means",
  pivots: "The edges every pivot walks",
  hold: "Where held values and the investigation live",
  settings: "This page: a settings page cannot switch off its own controls",
};

function hint(text) {
  return h("p", { class: "r-field__hint" }, text);
}

function statusLine() {
  const el = h("p", { class: "r-field__hint r-module__status", "aria-live": "polite" }, "");
  el.say = (text, err) => {
    el.textContent = text || "";
    el.setAttribute("aria-invalid", err ? "true" : "false");
  };
  return el;
}

// ---------------------------------------------------------------------------
// The sends indicator (§2.5): mechanical from hosts and the registry's own
// sends sentence, not authored text. The table is fixed here so a
// validator can assert against it directly.

const SENDS_NOTHING = new Set(["shell", "catalogue", "hold", "settings", "verdicts", "enrich-bundled", "coverage", "runbooks", "benign", "share"]);
const SENDS_OWN_SIEM = new Set(["pivots", "discovery", "workflows", "pattern", "advisor"]);
const SENDS_THIRD_PARTY = new Set(["virustotal", "circl", "epss", "selfhosted"]);

function parseHost(pattern) {
  const m = /^https?:\/\/([^/*]+)/.exec(String(pattern || ""));
  return m ? m[1].replace(/^www\./, "") : "";
}

function sendsFor(m, platform) {
  if (SENDS_OWN_SIEM.has(m.id)) {
    if (platform === "sentinel") return { kind: "nothing", text: "Sends: nothing" };
    return { kind: "own-siem", text: "Sends: your own Splunk, on your click" };
  }
  if (SENDS_THIRD_PARTY.has(m.id)) {
    if (m.id === "selfhosted") {
      const origin = modules.setting("selfhosted", KEYS.selfhostedOrigin);
      if (!origin) return { kind: "third-party", text: "Sends: the origin you set, on your click" };
      return { kind: "third-party", text: `Sends: ${parseHost(origin) || origin}, on your click` };
    }
    const host = parseHost(Array.isArray(m.hosts) ? m.hosts[0] : "");
    return { kind: "third-party", text: `Sends: ${host}` };
  }
  return { kind: "nothing", text: "Sends: nothing" };
}

function keyCountOf(id) {
  return Object.values(modules.keysOf(id)).reduce((n, list) => n + list.length, 0);
}

function hasStaticOrFnHosts(m) {
  return Array.isArray(m.hosts) ? m.hosts.length > 0 : typeof m.hosts === "function";
}

// ---------------------------------------------------------------------------
// The fold's storage-keys line: a live count of what the module's keys
// actually hold right now (modules.keysStoredOf), read at mount and after
// every action, never the registry's static name total (that total only
// gates whether this line can exist at all, below). Clear runs the same
// wipe Off does (wipe.clearModule), so a field-owned key clears here too.

function storageKeysLine(m, status, onCleared) {
  if (!keyCountOf(m.id)) return null;
  let busy = false;
  const btn = h("button", { type: "button", class: "r-btn r-btn--small" }, "Clear");
  const line = h("p", { class: "r-field__hint r-module__keys" });
  line.hidden = true;
  async function refresh() {
    const n = await modules.keysStoredOf(m.id);
    line.replaceChildren(`${n} stored key${n === 1 ? "" : "s"} `, btn);
    line.hidden = false;
  }
  btn.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    btn.disabled = true;
    try {
      await wipe.clearModule(m.id);
      status.say("Cleared.");
      if (onCleared) onCleared();
    } finally {
      await refresh();
      btn.disabled = false;
      busy = false;
    }
  });
  refresh().catch(() => {});
  return { el: line, refresh };
}

// The host permission line: present once the module's hosts (static, or a
// function of its current settings) are non-empty. Grant/Revoke never
// disable (S13); a busy flag alone guards against a double click.
function permissionLine(m, status) {
  const el = h("p", { class: "r-field__hint r-module__permission" });
  el.hidden = true;
  let busy = false;
  async function refresh() {
    const hosts = await modules.hostsOf(m.id);
    if (!hosts.length) {
      el.hidden = true;
      return;
    }
    const granted = await modules.permitted(m.id);
    const btn = h("button", { type: "button", class: "r-btn r-btn--small" }, granted ? "Revoke" : "Grant");
    btn.addEventListener("click", async () => {
      if (busy) return;
      busy = true;
      try {
        if (granted) await modules.revokeHosts(m.id, hosts);
        else if (!(await modules.requestHosts(m.id, hosts))) status.say(`Permission for ${hosts.join(", ")} was not granted.`, true);
      } finally {
        busy = false;
        refresh();
      }
    });
    el.replaceChildren(`Permission for ${hosts.join(", ")}: ${granted ? "granted" : "not granted"}. `, btn);
    el.hidden = false;
  }
  refresh().catch(() => {});
  return { el, refresh };
}

// ---------------------------------------------------------------------------
// Drafted settings (secret, url, select) with Save and Forget, and any
// toggle settings (benign's inject) written on change. `onSaved` and
// `onForgotten` are the keyed rows' extra write (setEnabled); the other
// twelve never pass them.

function validate(m, draft) {
  const values = { ...draft };
  if (m.id === "virustotal") {
    if (!looksLikeKey(values[KEYS.vtApiKey])) return { ok: false, why: "That does not look like a VirusTotal API key (64 hex characters). Copy it from virustotal.com/gui/my-apikey." };
    return { ok: true, values };
  }
  if (m.id === "selfhosted") {
    const v = selfhosted.originStatus(values[KEYS.selfhostedOrigin]);
    if (!v.ok) return { ok: false, why: v.why || "That does not look like an origin." };
    values[KEYS.selfhostedOrigin] = v.origin;
    if (!selfhosted.PROVIDERS.includes(values[KEYS.selfhostedProvider])) values[KEYS.selfhostedProvider] = "misp";
    return { ok: true, values, warn: v.warn };
  }
  return { ok: true, values };
}

async function testVirusTotal(status, btn) {
  btn.disabled = true;
  status.say("Asking VirusTotal…");
  try {
    const res = await ask({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" });
    if (res && res.ok) {
      const st = res.data && res.data.data && res.data.data.attributes && res.data.data.attributes.last_analysis_stats;
      status.say(`Works. VirusTotal answered for 8.8.8.8${st ? ` (${st.malicious || 0} malicious of ${Object.values(st).reduce((a, b) => a + (Number(b) || 0), 0)} vendors)` : ""}${res.cached ? ", from the worker's cache" : ""}. Free keys get ${PUBLIC_QUOTA.perMinute} lookups a minute, ${PUBLIC_QUOTA.perDay} a day.`);
    } else if (res === null) {
      status.say("Not available here: the served page has no background worker to ask.", true);
    } else {
      status.say(res && res.error ? res.error : describeError(res ? res.status : 0, res && res.body), true);
    }
  } finally {
    btn.disabled = false;
  }
}

function settingRows(m, status, { onSaved, onForgotten } = {}) {
  const defs = modules.settingsOf(m.id);
  if (!defs.length) return null;
  const inputs = new Map();
  const rows = [];
  const drafted = defs.filter((s) => s.kind !== "toggle");

  for (const s of defs) {
    if (s.kind === "toggle") {
      const input = h("input", { type: "checkbox", checked: modules.setting(m.id, s.key) === true });
      input.addEventListener("change", async () => {
        await modules.writeSetting(m.id, s.key, input.checked);
        status.say(`${s.label}: ${input.checked ? "on" : "off"}.`);
      });
      rows.push(h("label", { class: "r-secondary r-module__setting" }, input, " ", s.label));
      if (s.hint) rows.push(hint(s.hint));
      continue;
    }
    let input;
    if (s.kind === "select") {
      input = h("select", { class: "r-field__input", "aria-label": s.label }, (s.options || []).map((o) => h("option", { value: o.value }, o.label)));
    } else {
      input = h("input", { class: "r-field__input", type: s.kind === "secret" ? "password" : s.kind === "url" ? "url" : "text", placeholder: s.placeholder || "", "aria-label": s.label, autocomplete: "off", spellcheck: "false" });
    }
    input.value = String(modules.setting(m.id, s.key) ?? "");
    inputs.set(s.key, input);
    const reveal = s.kind === "secret" ? h("button", { type: "button", class: "r-btn r-btn--small", title: "Show or hide", onClick: () => { const show = input.type === "password"; input.type = show ? "text" : "password"; reveal.textContent = show ? "Hide" : "Show"; } }, "Show") : null;
    rows.push(h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, s.label), reveal ? h("div", { class: "r-module__keyrow" }, input, reveal) : input));
    if (s.hint) rows.push(hint(s.hint));
  }

  // Re-read every drafted input from the live cache rather than resetting
  // to a hardcoded default: Off clears only the secret-marked settings
  // (the credential goes blank, a survivor like selfhosted's provider
  // does not), Forget clears all of them, and this one function shows
  // either correctly because modules.setting() already reflects which.
  const syncInputs = () => {
    for (const s of drafted) inputs.get(s.key).value = String(modules.setting(m.id, s.key) ?? "");
  };
  if (drafted.length) rows.resetInputs = syncInputs;

  if (drafted.length) {
    const saveBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, "Save");
    const forgetBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, "Forget");
    const actions = [saveBtn, " ", forgetBtn];
    if (m.id === "virustotal") {
      const testBtn = h("button", { type: "button", class: "r-btn r-btn--small", title: "Spends one lookup from your quota" }, "Test key");
      testBtn.addEventListener("click", () => testVirusTotal(status, testBtn));
      actions.push(" ", testBtn);
    }
    saveBtn.addEventListener("click", async () => {
      const draft = {};
      for (const s of drafted) draft[s.key] = inputs.get(s.key).value.trim();
      const check = validate(m, draft);
      if (!check.ok) {
        status.say(check.why, true);
        return;
      }
      saveBtn.disabled = true;
      try {
        // A static hosts array (VirusTotal) is requested here too, so Save
        // alone is enough to both hold the key and reach it; a function of
        // the drafted values (selfhosted) already worked this way.
        const hosts = typeof m.hosts === "function" ? m.hosts(check.values) : Array.isArray(m.hosts) ? m.hosts : [];
        if (hosts.length && !(await modules.requestHosts(m.id, hosts))) {
          status.say(`Permission for ${hosts.join(", ")} was not granted; nothing was saved.`, true);
          return;
        }
        for (const s of drafted) await modules.writeSetting(m.id, s.key, check.values[s.key]);
        for (const s of drafted) inputs.get(s.key).value = String(check.values[s.key] ?? "");
        if (onSaved) await onSaved();
        status.say(check.warn ? `${check.warn} Saved.` : "Saved.", Boolean(check.warn));
      } catch (err) {
        status.say("Could not save: " + (err && err.message ? err.message : String(err)), true);
      } finally {
        saveBtn.disabled = false;
      }
    });
    forgetBtn.addEventListener("click", async () => {
      forgetBtn.disabled = true;
      try {
        if (onForgotten) {
          // A keyed row's Forget clears every drafted setting, not the
          // secret alone: stronger than the pill's own Off, which only
          // removes the credential and leaves the rest of the row's
          // settings stored.
          await onForgotten();
        } else {
          const hosts = typeof m.hosts === "function" ? await modules.hostsOf(m.id) : [];
          await modules.removeKeys(m.id);
          if (hosts.length) await modules.revokeHosts(m.id, hosts);
        }
        resetInputs();
        status.say("Forgotten.");
      } finally {
        forgetBtn.disabled = false;
      }
    });
    rows.push(h("p", { class: "r-module__actions" }, ...actions));
  }
  return rows;
}

// ---------------------------------------------------------------------------
// The Modules fold (§2.2): sends sentence in full, host permission, drafted
// settings, storage keys. CIRCL and EPSS are named exceptions: the
// storage-keys line alone, and only while on (their flag key mirrors it,
// written and removed in step by modules.setEnabled).

function buildModuleFold(m, status, opts, onChanged) {
  if (m.id === "circl" || m.id === "epss") {
    const keys = storageKeysLine(m, status, onChanged);
    return keys ? { rows: [keys.el], perm: null, resetInputs: null, keysRefresh: keys.refresh } : null;
  }
  const defs = modules.settingsOf(m.id);
  const drafted = defs.filter((s) => s.kind !== "toggle");
  if (!drafted.length && !hasStaticOrFnHosts(m) && !keyCountOf(m.id)) return null;
  const rows = [h("p", { class: "r-field__hint r-module__sendsfull" }, `Sends: ${m.sends}`)];
  const perm = permissionLine(m, status);
  rows.push(perm.el);
  const settingsRows = settingRows(m, status, opts);
  if (settingsRows) rows.push(...settingsRows);
  const keys = storageKeysLine(m, status, onChanged);
  if (keys) rows.push(keys.el);
  return { rows, perm, resetInputs: settingsRows ? settingsRows.resetInputs : null, keysRefresh: keys ? keys.refresh : null };
}

// ---------------------------------------------------------------------------
// Core rows' own fold content: shell keeps only "Show setup again" (the
// Sentinel-only checkbox moves to Environment); hold keeps the pinned
// values list and its add form; catalogue, pivots and settings have none.

function shellFold(context) {
  return [
    h(
      "a",
      {
        href: context === "options" ? "index.html#/" : "#/",
        class: "r-secondary",
        onClick: (e) => {
          onboarding.reset();
          if (context === "options") return;
          e.preventDefault();
          router.replace("start", {});
        },
      },
      "Show setup again",
    ),
  ];
}

function holdFold() {
  const pinList = h("div", { class: "r-settings__pins" });
  const pinKey = h("input", { class: "r-field__input", type: "text", placeholder: copy("settings.pinkey"), "aria-label": "Pinned value key", autocomplete: "off", spellcheck: "false" });
  const pinVal = h("input", { class: "r-field__input", type: "text", placeholder: "value", "aria-label": "Pinned value", autocomplete: "off", spellcheck: "false" });
  const pinForm = h(
    "form",
    {
      class: "r-settings__pin",
      onSubmit: (e) => {
        e.preventDefault();
        if (!pinKey.value.trim() || !pinVal.value.trim()) return;
        if (scope.isScopeKey(pinKey.value)) scope.setIndex(pinVal.value);
        else pinned.set(pinKey.value, pinVal.value);
        pinKey.value = "";
        pinVal.value = "";
        pinKey.focus();
      },
    },
    pinKey,
    pinVal,
    h("button", { type: "submit", class: "r-settings__pinbtn" }, "Pin"),
  );
  function renderPins() {
    const entries = Object.entries(pinned.all());
    replace(
      pinList,
      entries.length
        ? entries.map(([k, v]) =>
            h(
              "span",
              { class: "r-settings__chip" },
              h("code", null, k),
              h("span", { "aria-hidden": "true" }, "="),
              h("span", { class: "r-settings__val" }, v),
              h("button", { type: "button", class: "r-settings__rm", "aria-label": `Forget ${k}`, onClick: () => pinned.remove(k) }, "×"),
            ),
          )
        : h("p", { class: "r-muted" }, "Nothing else pinned."),
    );
  }
  pinned.subscribe(renderPins);
  renderPins();
  const pinsLabel = h("p", { class: "r-settings__label" }, copy("settings.pins"));
  const rows = [pinsLabel, pinList, pinForm];
  rows.refreshCopy = () => {
    pinsLabel.textContent = copy("settings.pins");
    pinKey.placeholder = copy("settings.pinkey");
  };
  return rows;
}

const CORE_FOLDS = {
  shell: (ctx) => shellFold(ctx.context),
  hold: () => holdFold(),
};

// ---------------------------------------------------------------------------
// One row, Core or Modules.

function moduleSection(m, { platform, context }) {
  const core = m.tier === "core";
  const keyed = KEYED_IDS.has(m.id);
  const status = statusLine();

  const head = h("div", { class: "r-module__head" }, h("span", { class: "r-module__label" }, m.label));
  let pill = null;
  if (core) {
    head.appendChild(h("span", { class: "r-module__fixed" }, "Always on"));
  } else {
    pill = h("button", { type: "button", class: "r-module__pill", role: "switch", "aria-checked": "false", "aria-label": m.label }, "Off");
    head.appendChild(pill);
  }

  const whyEl = core ? h("p", { class: "r-module__why" }, CORE_WHY[m.id] || "") : null;
  const aboutEl = h("p", { class: "r-module__about" }, m.about);
  const sendsEl = h("p", { class: "r-module__sends" }, "");

  const foldSummary = h("summary", null, "Details");
  const foldBodyEl = h("div", { class: "r-fold__body" });
  const foldEl = h("details", { class: "r-module__fold" }, foldSummary, foldBodyEl);

  let foldContent = null;
  let permCheck = null;
  let resetInputs = null;
  let keysRefresh = null;
  let dynamicFold = false; // circl/epss: presence follows on/off, not a static build
  if (core) {
    const build = CORE_FOLDS[m.id];
    if (build) foldContent = build({ context });
  } else if (m.id === "circl" || m.id === "epss") {
    dynamicFold = true;
    const built = buildModuleFold(m, status, {}, () => draw());
    if (built) {
      foldContent = built.rows;
      keysRefresh = built.keysRefresh;
    }
  } else {
    const opts = keyed
      ? {
          onSaved: async () => {
            await modules.setEnabled(m.id, true);
            draw();
          },
          onForgotten: async () => {
            // Off alone (setEnabled) revokes the host and removes the
            // secret; Forget also clears the row's other drafted
            // settings (selfhosted's provider, its writes toggle) so
            // the fold never shows a leftover choice for a key that is
            // gone. The order matters: setEnabled still sees the
            // current settings when it computes the host to revoke.
            await modules.setEnabled(m.id, false);
            await modules.removeKeys(m.id);
            draw();
          },
        }
      : undefined;
    const built = buildModuleFold(m, status, opts, () => draw());
    if (built) {
      foldContent = built.rows;
      permCheck = built.perm;
      resetInputs = built.resetInputs;
      keysRefresh = built.keysRefresh;
    }
  }
  if (foldContent) replace(foldBodyEl, foldContent);

  let busy = false;
  if (pill) {
    pill.addEventListener("click", async () => {
      if (busy) return;
      const isOn = pill.getAttribute("aria-checked") === "true";
      if (keyed) {
        if (!isOn) {
          foldEl.open = true; // reveal the key input only; no write, no request
          return;
        }
        busy = true;
        try {
          await modules.setEnabled(m.id, false);
          if (resetInputs) resetInputs(); // shows what actually survived Off, not a blanket reset
          status.say(`${m.label} stops; the key is gone. Its other saved data stays, use Clear to delete it.`);
        } finally {
          busy = false;
          draw();
        }
        return;
      }
      const want = !isOn;
      busy = true;
      try {
        const res = await modules.setEnabled(m.id, want);
        if (!res.ok) {
          status.say(res.why, true);
          return;
        }
        if (want) {
          status.say(res.hosts && res.hosts.length ? `${m.label} is on; permission for ${res.hosts.join(", ")} granted.` : `${m.label} is on.`);
          if (foldContent) foldEl.open = true;
        } else {
          const removedNote = res.removed && res.removed.length ? ` ${res.removed.length} credential key${res.removed.length === 1 ? "" : "s"} removed;` : "";
          status.say(`${m.label} stops;${removedNote} its saved data stays, use Clear to delete it.${res.hostsRevoked && res.hostsRevoked.length ? ` ${res.hostsRevoked.join(", ")} revoked.` : ""}`);
        }
      } catch (err) {
        status.say(err && err.message ? err.message : String(err), true);
      } finally {
        busy = false;
        draw();
      }
    });
  }

  const el = h(
    "section",
    { class: "r-module", id: modules.anchor(m.id), dataset: { module: m.id, tier: m.tier } },
    head,
    whyEl,
    aboutEl,
    sendsEl,
    foldContent ? foldEl : null,
    status,
  );

  function draw() {
    const isOn = modules.on(m.id, platform === null ? undefined : platform);
    if (pill) {
      pill.setAttribute("aria-checked", isOn ? "true" : "false");
      pill.textContent = isOn ? "On" : "Off";
    }
    const s = sendsFor(m, platform);
    sendsEl.dataset.sends = s.kind;
    sendsEl.textContent = s.text;
    if (dynamicFold) foldEl.hidden = !isOn;
    if (permCheck) permCheck.refresh().catch(() => {});
    if (keysRefresh) keysRefresh().catch(() => {});
  }
  draw();
  el.draw = draw;
  return el;
}

// ---------------------------------------------------------------------------
// Environment (§2.3): non-module, Splunk fields gated off Sentinel
// entirely (the base-URL leak this contract fixes), the always-panel
// toggle Sentinel only.

function environmentGroup(platform) {
  const baseInput = h("input", { class: "r-field__input", type: "url", placeholder: "https://splunk.example:8000", "aria-label": "Splunk base URL", autocomplete: "off", spellcheck: "false", value: settings.splunkBase() });
  const baseHint = hint("");
  baseInput.addEventListener("change", () => {
    const ok = settings.setSplunkBase(baseInput.value);
    baseInput.value = settings.splunkBase();
    baseInput.setAttribute("aria-invalid", ok ? "false" : "true");
    baseHint.textContent = ok ? "" : "Needs to start with http:// or https://.";
  });

  const indexInput = h("input", { class: "r-field__input", type: "text", placeholder: copy("settings.index.placeholder"), "aria-label": "Index", autocomplete: "off", spellcheck: "false", value: scope.index() });
  const indexHint = hint("");
  const chooser = h("div", { class: "r-settings__chooser" });
  const perSt = h("div", { class: "r-settings__pins" });
  const perStLabel = h("p", { class: "r-settings__label" }, copy("settings.index.perst"));
  const perStGroup = h("div", { class: "r-settings__perst" }, perStLabel, perSt);
  function renderIndex() {
    const override = scope.index();
    indexInput.value = override;
    indexInput.placeholder = copy("settings.index.placeholder");
    indexHint.textContent = override ? copy("settings.index.override", { index: override }) : copy("settings.index.derived");
    const asks = override ? [] : scope.pending();
    replace(
      chooser,
      asks.map((q) =>
        h(
          "div",
          { class: "r-settings__ask", role: "group", "aria-label": `Index for ${q.sourcetype}` },
          h("p", { class: "r-settings__askline" }, h("code", null, q.sourcetype), ` is in ${q.choices.length} indexes:`),
          h("div", { class: "r-settings__askchoices" }, q.choices.map((c) => h("button", { type: "button", class: "r-settings__choice", onClick: () => scope.remember(q.sourcetype, c) }, c))),
        ),
      ),
    );
    chooser.hidden = !asks.length;
    const chosen = Object.entries(scope.choices());
    replace(
      perSt,
      chosen.map(([st, idx]) =>
        h(
          "span",
          { class: "r-settings__chip", title: override ? `Kept; the override ${override} is in use while it is set.` : "" },
          h("code", null, st),
          h("span", { "aria-hidden": "true" }, "→"),
          h("span", { class: "r-settings__val" }, idx),
          h("button", { type: "button", class: "r-settings__rm", "aria-label": `Forget the index for ${st}`, onClick: () => scope.forget(st) }, "×"),
        ),
      ),
    );
    perStGroup.hidden = !chosen.length;
  }
  indexInput.addEventListener("change", () => {
    scope.setIndex(indexInput.value);
    renderIndex();
  });
  scope.subscribe(renderIndex);
  renderIndex();

  // Disabled until the stored value is read (hasChrome() ? true : already
  // known): a blank field flashing on every Settings open was the visible
  // half of the bug; the field being editable and losing a namespace typed
  // during that same window to the late .then() was the other half.
  // Disabling stops both, since neither a stale paint nor a keystroke can
  // land before the field knows the real value.
  const nsInput = h("input", { class: "r-field__input", type: "text", placeholder: "search", "aria-label": "App namespace", autocomplete: "off", spellcheck: "false" });
  nsInput.disabled = hasChrome();
  if (hasChrome()) {
    store.getLiteral(KEYS.spAppNamespace).then((got) => {
      nsInput.value = typeof got[KEYS.spAppNamespace] === "string" ? got[KEYS.spAppNamespace] : "";
      nsInput.disabled = false;
    });
  }
  nsInput.addEventListener("change", () => {
    if (hasChrome()) store.setLiteral({ [KEYS.spAppNamespace]: nsInput.value.trim() });
  });

  // Same shape as nsInput above: disabled until hydrate() resolves, so the
  // checkbox never shows (and cannot be toggled off) an unchecked default
  // while the real value is still in flight.
  const alwaysPanelInput = h("input", { type: "checkbox" });
  alwaysPanelInput.checked = sentinelSettings.alwaysPanel();
  alwaysPanelInput.disabled = true;
  const alwaysPanelLabel = h("label", { class: "r-secondary r-nowrap" }, alwaysPanelInput, " On the portal, always open Reach beside the menu");
  alwaysPanelInput.addEventListener("change", () => sentinelSettings.setAlwaysPanel(alwaysPanelInput.checked));
  const renderAlwaysPanel = () => { alwaysPanelInput.checked = sentinelSettings.alwaysPanel(); };
  sentinelSettings.subscribe(renderAlwaysPanel);
  sentinelSettings.hydrate().then(() => {
    renderAlwaysPanel();
    alwaysPanelInput.disabled = false;
  });

  const splunk = platform !== "sentinel";
  const rows = [
    splunk ? h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "Splunk base URL"), baseInput, baseHint) : null,
    splunk ? h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "Index"), indexInput, indexHint) : null,
    splunk ? chooser : null,
    splunk ? perStGroup : null,
    splunk ? h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "App namespace"), nsInput, hint("The Splunk app live searches are dispatched into. Blank means search.")) : null,
    platform === "sentinel" ? alwaysPanelLabel : null,
  ].filter(Boolean);

  const group = h("div", { class: "r-modules__group" }, h("h2", { dataset: { heading: "environment" } }, "Environment"), h("div", { class: "r-settings__env" }, ...rows));
  group.refreshCopy = () => {
    perStLabel.textContent = copy("settings.index.perst");
    renderIndex();
  };
  return group;
}

// ---------------------------------------------------------------------------
// Data (§2.4): Clear all Reach data, always present, ungated. Export and
// Import (share's controls) are left out of this pass: see the report.

// The Falcon dictionary row (board it_9951cfe3): a file picker for the
// analyst's own FDR schema pull, imported as a local layer catalogue.js
// reads for a Falcon field the bundle has nothing better for. The row's
// own summary, "N fields, M events, pulled <date>", stays live through
// falconDictionary.subscribe so an import from another context (a second
// options.html tab) is reflected here without a reload.
function falconRow() {
  const status = hint("No Falcon dictionary imported.");
  const file = h("input", { type: "file", accept: "application/json,.json", class: "r-field__input" });
  const forgetBtn = h("button", { type: "button", class: "r-btn r-btn--small", hidden: true }, "Forget");
  const importBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, "Import a Falcon dictionary");

  const refresh = () => {
    const c = falconDictionary.counts();
    status.textContent = c
      ? `Falcon dictionary: ${c.fields.toLocaleString()} fields, ${c.events.toLocaleString()} events, pulled ${c.pulled_at ? c.pulled_at.slice(0, 10) : "an unknown date"}.`
      : "No Falcon dictionary imported.";
    forgetBtn.hidden = !c;
  };

  importBtn.addEventListener("click", async () => {
    const f = file.files && file.files[0];
    if (!f) {
      status.textContent = "Pick a file first.";
      return;
    }
    importBtn.disabled = true;
    try {
      let raw;
      try {
        raw = JSON.parse(await f.text());
      } catch {
        throw new Error("Not a Falcon dictionary: the file is not valid JSON.");
      }
      await falconDictionary.importDoc(raw);
      refresh();
    } catch (err) {
      status.textContent = err && err.message ? err.message : String(err);
    } finally {
      importBtn.disabled = false;
      file.value = "";
    }
  });

  forgetBtn.addEventListener("click", async () => {
    forgetBtn.disabled = true;
    try {
      await falconDictionary.forget();
      refresh();
    } finally {
      forgetBtn.disabled = false;
    }
  });

  falconDictionary.load().then(refresh);
  falconDictionary.subscribe(refresh);

  return h("div", { class: "r-module__falcon" }, h("p", { class: "r-inline" }, file, importBtn, forgetBtn), status);
}

function dataGroup() {
  const wipeStatus = hint("");
  const wipeRevokeInput = h("input", { type: "checkbox" });
  const wipeRevokeLabel = h("label", { class: "r-secondary r-nowrap" }, wipeRevokeInput, " Also revoke Splunk and Sentinel page access");
  const wipeConfirmBtn = h("button", { type: "button", class: "r-btn r-btn--danger r-btn--small" }, "Yes, clear everything");
  const wipeCancelBtn = h("button", { type: "button", class: "r-btn r-btn--small" }, "Cancel");
  const wipeConfirmRow = h(
    "div",
    { class: "r-settings__wipeconfirm", hidden: true },
    hint("This removes every value, pin, discovered fact and stored key Reach keeps in this browser, across every module. It cannot be undone."),
    wipeRevokeLabel,
    h("p", null, wipeConfirmBtn, " ", wipeCancelBtn),
  );
  const wipeStartBtn = h("button", { type: "button", class: "r-btn r-btn--danger r-btn--small" }, "Clear all Reach data");
  wipeStartBtn.addEventListener("click", () => {
    wipeStatus.textContent = "";
    wipeConfirmRow.hidden = false;
    wipeStartBtn.hidden = true;
  });
  wipeCancelBtn.addEventListener("click", () => {
    wipeConfirmRow.hidden = true;
    wipeStartBtn.hidden = false;
  });
  wipeConfirmBtn.addEventListener("click", async () => {
    wipeConfirmBtn.disabled = true;
    try {
      const res = await wipe.run({ revokeHosts: wipeRevokeInput.checked });
      const n = res.storage.length + res.local.length + res.session.length;
      const parts = [`Cleared ${n} key${n === 1 ? "" : "s"}`];
      if (res.scriptsUnregistered) parts.push(`unregistered ${res.scriptsUnregistered} content script${res.scriptsUnregistered === 1 ? "" : "s"}`);
      if (res.hostsRevoked.length) parts.push(`revoked ${res.hostsRevoked.length} origin${res.hostsRevoked.length === 1 ? "" : "s"}`);
      wipeStatus.textContent = `${parts.join(", ")}. Reload the page to see it reflected everywhere.`;
    } catch (err) {
      wipeStatus.textContent = err && err.message ? err.message : String(err);
    } finally {
      wipeConfirmBtn.disabled = false;
      wipeConfirmRow.hidden = true;
      wipeStartBtn.hidden = false;
    }
  });

  return h(
    "div",
    { class: "r-modules__group" },
    h("h2", { dataset: { heading: "data" } }, "Data"),
    falconRow(),
    h("div", { class: "r-module__wipe" }, wipeStartBtn, wipeConfirmRow, wipeStatus),
  );
}

// ---------------------------------------------------------------------------

function modulesFor(platform) {
  return modules.MODULES.filter((m) => platform === null || m.platforms.includes(platform));
}

export function moduleList({ platform = PLATFORM, context = "panel" } = {}) {
  const all = modulesFor(platform);
  const core = all.filter((m) => m.tier === "core");
  const optional = all.filter((m) => m.tier !== "core");
  const coreSections = core.map((m) => moduleSection(m, { platform, context }));
  const optionalSections = optional.map((m) => moduleSection(m, { platform, context }));

  const groups = [];
  if (coreSections.length) groups.push(h("div", { class: "r-modules__group" }, h("h2", { dataset: { heading: "core" } }, "Core"), h("div", { class: "r-modules" }, ...coreSections)));
  if (optionalSections.length) groups.push(h("div", { class: "r-modules__group" }, h("h2", { dataset: { heading: "modules" } }, "Modules"), h("div", { class: "r-modules" }, ...optionalSections)));
  const env = environmentGroup(platform);
  groups.push(env);
  const data = dataGroup();
  groups.push(data);

  const el = h("div", { class: "r-modules-page" }, ...groups);
  const list = [...coreSections, ...optionalSections];
  modules.subscribe(() => {
    for (const s of list) s.draw();
  });
  el.refreshCopy = () => {
    for (const s of list) if (s.refreshCopy) s.refreshCopy();
    if (env.refreshCopy) env.refreshCopy();
  };
  return el;
}

export default moduleList;
