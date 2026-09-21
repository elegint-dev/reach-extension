// moduleList: the settings surface, drawn from the module registry
// (app/lib/modules.js). One list, each module a head with its toggle (core
// modules have none), its sends line, and its settings beneath: the same
// element for the panel's gear fold (settingsBar.js) and for options.html,
// so VirusTotal, CIRCL, EPSS and the self-hosted relay sit together and a
// popup's "set it up" link lands on the module's head (id module-<id>).
//
//   moduleList({ platform, context })
//     platform   draw this platform's modules; null draws every module and
//                marks the platform-narrow ones
//     context    "panel" | "options": where "Show setup again" and the
//                notebook links lead
//   el.refreshCopy()   re-ask the copy.js lines after a surface change
//
// Generic settings (toggle, secret, url, select) come from each module's
// settings list; the core modules' hand-built blocks (Splunk base URL, the
// index and its chooser, pinned values, Clear all Reach data, the Sentinel
// panel switch) are drawn here by module id. Every write goes through
// modules.js, wipe.js or the store the value belongs to.

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
import * as selfhosted from "../lib/enrich/selfhosted.js";
import { looksLikeKey, describeError, PUBLIC_QUOTA } from "../lib/virustotal.js";
import { PLATFORM } from "../lib/platform.js";
import { KEYS } from "../lib/storage-keys.js";
import { copy } from "../lib/copy.js";
import { hasChrome, ask } from "../lib/runtime.js";

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
// The generic settings body: one control per settings entry. Toggles write
// on change; text-like settings draft into inputs and write on Save, which
// first requests the hosts the drafted values imply (the self-hosted
// relay's origin), so a declined grant leaves nothing stored.

function genericBody(m, status) {
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
        if (typeof m.hosts === "function") {
          const hosts = m.hosts(check.values);
          if (hosts.length && !(await modules.requestHosts(m.id, hosts))) {
            status.say(`Permission for ${hosts.join(", ")} was not granted; nothing was saved.`, true);
            return;
          }
        }
        for (const s of drafted) await modules.writeSetting(m.id, s.key, check.values[s.key]);
        for (const s of drafted) inputs.get(s.key).value = String(check.values[s.key] ?? "");
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
        const hosts = typeof m.hosts === "function" ? await modules.hostsOf(m.id) : [];
        await modules.removeKeys(m.id);
        if (hosts.length) await modules.revokeHosts(m.id, hosts);
        for (const s of drafted) inputs.get(s.key).value = String(s.default ?? "");
        status.say(hosts.length ? `Forgotten. The ${hosts.join(", ")} permission was revoked.` : "Forgotten.");
      } finally {
        forgetBtn.disabled = false;
      }
    });
    rows.push(h("p", { class: "r-module__actions" }, ...actions));
  }
  return rows;
}

// What a module's drafted settings must look like before they are written.
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

// A real lookup through the background worker, of an address whose report
// exists for certain, so a wrong key, a missing permission and a spent
// quota each show up as the sentence the popup would show.
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

// ---------------------------------------------------------------------------
// The core modules' own blocks

function settingsBody(platform, status) {
  const baseInput = h("input", { class: "r-field__input", type: "url", placeholder: "https://splunk.example:8000", "aria-label": "Splunk base URL", autocomplete: "off", spellcheck: "false", value: settings.splunkBase() });
  const baseHint = hint("");
  baseInput.addEventListener("change", () => {
    const ok = settings.setSplunkBase(baseInput.value);
    baseInput.value = settings.splunkBase();
    baseInput.setAttribute("aria-invalid", ok ? "false" : "true");
    baseHint.textContent = ok ? "" : "Needs to start with http:// or https://.";
  });

  // The index: scope, not a pin. Empty, each search takes the index
  // discovery recorded for its sourcetype; set, this one is the index of
  // every search. A sourcetype that lives in several indexes is asked
  // about here, once, and the answer kept per sourcetype.
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

  // The app namespace Splunk dispatches live searches into: read by the
  // Splunk popup (value-popup.js) from chrome.storage.local.
  const nsInput = h("input", { class: "r-field__input", type: "text", placeholder: "search", "aria-label": "App namespace", autocomplete: "off", spellcheck: "false" });
  if (hasChrome()) store.getLiteral(KEYS.spAppNamespace).then((got) => { nsInput.value = typeof got[KEYS.spAppNamespace] === "string" ? got[KEYS.spAppNamespace] : ""; });
  nsInput.addEventListener("change", () => {
    if (hasChrome()) store.setLiteral({ [KEYS.spAppNamespace]: nsInput.value.trim() });
  });

  // Clear all Reach data: a two-step inline confirm rather than
  // window.confirm (which blocks the page and cannot be driven or
  // measured from a script). app/lib/wipe.js does the work.
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

  const splunk = platform !== "sentinel";
  const rows = [
    h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "Splunk base URL"), baseInput, baseHint),
    splunk ? h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "Index"), indexInput, indexHint) : null,
    splunk ? chooser : null,
    splunk ? perStGroup : null,
    splunk ? h("label", { class: "r-field" }, h("span", { class: "r-field__label" }, "App namespace"), nsInput, hint("The Splunk app live searches are dispatched into. Blank means search.")) : null,
    h("div", { class: "r-module__wipe" }, wipeStartBtn, wipeConfirmRow, wipeStatus),
  ];
  rows.refreshCopy = () => {
    perStLabel.textContent = copy("settings.index.perst");
    renderIndex();
  };
  return rows;
}

function shellBody(platform, context) {
  const rows = [];
  if (platform !== "splunk") {
    // Sentinel only: the blade's own menu is skipped for Reach's panel
    // beside it (app/lib/sentinel-settings.js).
    const alwaysPanelInput = h("input", { type: "checkbox", checked: sentinelSettings.alwaysPanel() });
    const alwaysPanelLabel = h("label", { class: "r-secondary r-nowrap" }, alwaysPanelInput, " On the portal, always open Reach beside the menu");
    alwaysPanelInput.addEventListener("change", () => sentinelSettings.setAlwaysPanel(alwaysPanelInput.checked));
    const renderAlwaysPanel = () => {
      alwaysPanelInput.checked = sentinelSettings.alwaysPanel();
    };
    sentinelSettings.subscribe(renderAlwaysPanel);
    sentinelSettings.hydrate().then(renderAlwaysPanel);
    rows.push(alwaysPanelLabel);
  }
  // "show setup again": brings back the onboarding card on the start page
  // (app/lib/onboarding.js). In the panel router.replace() forces the
  // start route's re-render even from the start page itself.
  rows.push(
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
  );
  return rows;
}

function holdBody() {
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
        // The index is scope: typed here, it is the override in Settings.
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

// ---------------------------------------------------------------------------
// One module

function moduleSection(m, { platform, context }) {
  const status = statusLine();
  const core = m.tier === "core";
  const narrow = platform === null && m.platforms.length === 1 ? m.platforms[0] : null;
  const keyCount = Object.values(modules.keysOf(m.id)).reduce((n, list) => n + list.length, 0);

  let toggle = null;
  if (!core) {
    toggle = h("input", { type: "checkbox", class: "r-module__switch", "aria-label": `${m.label} on or off` });
    toggle.title = keyCount || m.hosts.length || typeof m.hosts === "function" ? "Off removes the module's stored data and revokes its host permissions." : "";
    toggle.addEventListener("change", async () => {
      const want = toggle.checked;
      toggle.disabled = true;
      try {
        const res = await modules.setEnabled(m.id, want);
        if (!res.ok) {
          toggle.checked = !want;
          status.say(res.why, true);
          return;
        }
        if (want) status.say(res.hosts && res.hosts.length ? `${m.label} is on; permission for ${res.hosts.join(", ")} granted.` : `${m.label} is on.`);
        else status.say(`${m.label} is off${res.removed && res.removed.length ? `; ${res.removed.length} stored key${res.removed.length === 1 ? "" : "s"} removed` : ""}${res.hostsRevoked && res.hostsRevoked.length ? `; ${res.hostsRevoked.join(", ")} revoked` : ""}.`);
      } catch (err) {
        toggle.checked = !want;
        status.say(err && err.message ? err.message : String(err), true);
      } finally {
        toggle.disabled = false;
      }
    });
  }

  const head = h(
    "div",
    { class: "r-module__head" },
    toggle ? h("label", { class: "r-module__toggle" }, toggle, h("span", { class: "r-module__label" }, m.label)) : h("span", { class: "r-module__label" }, m.label),
    core ? h("span", { class: "r-module__tier" }, "core") : null,
    narrow ? h("span", { class: "r-module__tier" }, `${narrow === "splunk" ? "Splunk" : "Sentinel"} only`) : null,
  );

  let body = null;
  if (m.id === "settings") body = settingsBody(platform, status);
  else if (m.id === "shell") body = shellBody(platform, context);
  else if (m.id === "hold") body = holdBody();
  else body = genericBody(m, status);

  const bodyEl = body ? h("div", { class: "r-module__body" }, ...body) : null;
  const el = h(
    "section",
    { class: "r-module", id: modules.anchor(m.id), dataset: { module: m.id, tier: m.tier } },
    head,
    h("p", { class: "r-module__about" }, m.about),
    h("p", { class: "r-module__sends" }, "Sends: ", m.sends),
    bodyEl,
    status,
  );

  const permissionNote = async () => {
    if (!modules.on(m.id, platform === null ? undefined : platform)) return;
    const hosts = await modules.hostsOf(m.id);
    if (!hosts.length) return;
    const ok = await modules.permitted(m.id);
    if (ok) return;
    const grant = h("button", { type: "button", class: "r-btn r-btn--small", onClick: async () => { if (await modules.requestHosts(m.id, hosts)) status.say(`Permission for ${hosts.join(", ")} granted.`); } }, "Grant again");
    status.replaceChildren(`${m.label} is on but the ${hosts.join(", ")} permission is gone. `, grant);
  };

  const draw = () => {
    const isOn = modules.on(m.id, platform === null ? undefined : platform);
    el.classList.toggle("r-module--off", !isOn);
    if (toggle) toggle.checked = isOn;
    if (bodyEl) bodyEl.hidden = !isOn;
    permissionNote().catch(() => {});
  };
  draw();
  el.draw = draw;
  el.refreshCopy = body && body.refreshCopy ? body.refreshCopy : null;
  return el;
}

export function moduleList({ platform = PLATFORM, context = "panel" } = {}) {
  const list = modulesFor(platform).map((m) => moduleSection(m, { platform, context }));
  const el = h("div", { class: "r-modules" }, ...list);
  modules.subscribe(() => {
    for (const s of list) s.draw();
  });
  el.refreshCopy = () => {
    for (const s of list) if (s.refreshCopy) s.refreshCopy();
  };
  return el;
}

function modulesFor(platform) {
  return modules.MODULES.filter((m) => platform === null || m.platforms.includes(platform));
}

export default moduleList;
