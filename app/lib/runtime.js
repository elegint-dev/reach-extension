// The extension runtime, read from one place: whether chrome.* is here at
// all (the same modules run on a served page with no extension around
// them), one way to ask the background worker, the app's own URLs, the
// clipboard, and the two facts a Splunk page states about itself (its
// asset signature and its locale prefix).
//
//   hasChrome()                       chrome.storage.local is here (an extension page or a content script)
//   canAsk()                          chrome.runtime.sendMessage is here
//   ask(msg) → Promise<answer | { ok: false, status: 0, error } | null>
//       one round trip to the background worker; null when there is no
//       worker to ask (a served page), the error shape when the worker did
//       not answer (chrome.runtime.lastError). Never rejects.
//   appUrl(platform, hash = "")       index.html?platform=<platform><hash>, absolute under the extension
//   optionsUrl(platform, anchor = "") options.html?platform=<platform>#<anchor>
//   copyText(text, el, label = "copied")
//       writes the clipboard and flashes `label` on el for a moment;
//       "Could not copy" when the page has no clipboard or refused
//   SPLUNK_ASSET_SELECTOR             a <link> or <script> under Splunk Web's versioned /static/@<hash>/ path
//   looksLikeSplunk(doc = document)   that signature is on the page. The content scripts and the
//       toolbar popup gate on the same selector inline (a classic script
//       cannot import before its first line); tests pin them to this one.
//   localePrefix(loc = location)      Splunk Web's locale path segment ("en-US"), read off the page
//
// No imports. Never fetches.

export function hasChrome() {
  return typeof chrome !== "undefined" && Boolean(chrome.storage && chrome.storage.local);
}

export function canAsk() {
  return typeof chrome !== "undefined" && Boolean(chrome.runtime && chrome.runtime.sendMessage);
}

export function ask(msg) {
  if (!canAsk()) return Promise.resolve(null);
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (res) => {
        const err = chrome.runtime.lastError;
        resolve(err ? { ok: false, status: 0, error: err.message } : res);
      });
    } catch (err) {
      resolve({ ok: false, status: 0, error: err && err.message ? err.message : String(err) });
    }
  });
}

function extensionUrl(path) {
  return typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL ? chrome.runtime.getURL(path) : path;
}

export function appUrl(platform, hash = "") {
  return extensionUrl(`index.html?platform=${encodeURIComponent(platform)}${hash}`);
}

export function optionsUrl(platform, anchor = "") {
  return extensionUrl(`options.html?platform=${encodeURIComponent(platform)}${anchor ? `#${anchor}` : ""}`);
}

export function copyText(text, el, label = "copied") {
  const was = el.textContent;
  const flash = (word) => {
    el.textContent = word;
    setTimeout(() => (el.textContent = was), 900);
  };
  const nav = globalThis.navigator;
  if (!nav || !nav.clipboard || typeof nav.clipboard.writeText !== "function") {
    flash("Could not copy");
    return Promise.resolve(false);
  }
  return nav.clipboard.writeText(String(text)).then(
    () => {
      flash(label);
      return true;
    },
    () => {
      flash("Could not copy");
      return false;
    },
  );
}

export const SPLUNK_ASSET_SELECTOR = 'link[href*="/static/@"], script[src*="/static/@"]';

export function looksLikeSplunk(doc = globalThis.document) {
  return Boolean(doc && typeof doc.querySelector === "function" && doc.querySelector(SPLUNK_ASSET_SELECTOR));
}

export function localePrefix(loc = globalThis.location) {
  const seg = loc && typeof loc.pathname === "string" ? loc.pathname.split("/")[1] : "";
  return seg || "en-US";
}

export default { hasChrome, canAsk, ask, appUrl, optionsUrl, copyText, SPLUNK_ASSET_SELECTOR, looksLikeSplunk, localePrefix };
