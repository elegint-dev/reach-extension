// The storage key names more than one context reads: the background
// worker, the module registry, the settings surface, the views and the
// content scripts all name chrome.storage.local keys, and the app pages
// keep the platform under one localStorage key. Each name is spelled here
// and read from here (tests/storage-keys.test.js holds the registry to this list).
//
//   KEYS.<name>   the literal key
//
// Plain ES module. No DOM, no chrome.*.

export const KEYS = Object.freeze({
  // chrome.storage.local
  trustedOrigins: "trustedOrigins",
  csIndex: "csIndex",
  spAppNamespace: "spAppNamespace",
  sentinelAlwaysPanel: "reach.sentinel.alwaysPanel",
  sentinelWorkspace: "reach.sentinel.currentWorkspace",
  onboardingDismissed: "reach.onboarding.dismissed",
  benignInject: "reach.benign.inject",
  vtApiKey: "vtApiKey",
  circlEnabled: "reach.enrich.circl.enabled",
  epssEnabled: "reach.enrich.epss.enabled",
  selfhostedProvider: "reach.enrich.selfhosted.provider",
  selfhostedOrigin: "reach.enrich.selfhosted.origin",
  selfhostedToken: "reach.enrich.selfhosted.token",
  selfhostedWrites: "reach.enrich.selfhosted.writes",
  // localStorage
  platform: "reach.platform",
});

export default KEYS;
