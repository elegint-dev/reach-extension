// onboarding: whether the first-install card on the bare catalogue start
// page should show. Two facts, both cached and hydrated once:
//
//   dismissed       the user closed the card (persists)
//   enabledCount    how many origins are enabled, read from the same
//                   trustedOrigins list popup.js and background.js keep in
//                   chrome.storage.local (background.js enabledOrigins())
//
// chrome.storage.local when the page has it (the catalogue tab, the side
// panel, the options page), through store.js, which keeps `dismissed` in
// localStorage when it does not (the served harness, tests without an
// extension). There is no storage-less fallback for enabledCount: nothing
// has granted an origin without chrome.permissions existing to grant it,
// so 0 is simply correct there, and that is what makes the card visible on
// the harness.
//
//   onboarding.shouldShow()       → cached boolean, true until hydrate() says otherwise
//   onboarding.cardModel()        → the card's copy, pure, no DOM
//   onboarding.dismiss()
//   onboarding.reset()            → "show setup again" (Settings)
//   onboarding.hydrate()          → reads storage once, follows later changes
//   onboarding.subscribe(fn)      → fn() only when shouldShow() actually flips

import { isSentinel } from "./platform.js";
import * as store from "./store.js";
import { KEYS } from "./storage-keys.js";
import { hasChrome } from "./runtime.js";

const DISMISSED_KEY = KEYS.onboardingDismissed;
const ORIGINS_KEY = KEYS.trustedOrigins; // the list popup.js and background.js keep

const listeners = new Set();
let dismissedCache = false;
let enabledCountCache = 0;

function notify(prevShow) {
  if (shouldShow() === prevShow) return; // only the flip is a change worth a re-render
  for (const fn of listeners) fn();
}

export function shouldShow() {
  return !dismissedCache && enabledCountCache === 0;
}

export function dismiss() {
  const prev = shouldShow();
  dismissedCache = true;
  store.setLiteral({ [DISMISSED_KEY]: true }).catch(() => {});
  notify(prev);
}

export function reset() {
  const prev = shouldShow();
  dismissedCache = false;
  store.removeLiteral(DISMISSED_KEY).catch(() => {});
  notify(prev);
}

// The card's copy, platform-worded, no DOM. steps[0] is the enable step,
// steps[1] the first click; both are plain strings a component renders.
export function cardModel() {
  const sentinel = isSentinel();
  return {
    show: shouldShow(),
    line: "Reach is a data catalogue that runs in your browser: nothing it knows leaves your machine, and nothing it does touches your SIEM until you click.",
    steps: [
      sentinel
        ? "Open the Sentinel Logs blade and click the Reach icon, then Enable in the Azure portal."
        : "Open your Splunk search page and click the Reach icon, then Enable on this Splunk instance.",
      "Click any value in an event.",
    ],
    note: "Nothing runs until you click.",
  };
}

let hydrated = null;
export function hydrate() {
  if (hydrated) return hydrated;
  hydrated = (async () => {
    const prev = shouldShow();
    const got = await store.getLiteral([DISMISSED_KEY, ORIGINS_KEY]).catch(() => ({}));
    dismissedCache = Boolean(got[DISMISSED_KEY]);
    enabledCountCache = hasChrome() && Array.isArray(got[ORIGINS_KEY]) ? got[ORIGINS_KEY].length : 0;
    store.subscribeLiteral((key, value) => {
      const before = shouldShow();
      if (key === DISMISSED_KEY) dismissedCache = Boolean(value);
      else if (key === ORIGINS_KEY) enabledCountCache = hasChrome() && Array.isArray(value) ? value.length : 0;
      else return;
      notify(before);
    });
    notify(prev);
  })();
  return hydrated;
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export default { shouldShow, cardModel, dismiss, reset, hydrate, subscribe };
