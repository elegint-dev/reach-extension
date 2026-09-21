// Bounds the bundled catalogue to the six packs the cross-feed union
// fixtures were written against (CloudTrail, Entra, Falcon, the Sentinel
// samples, Okta, Workspace), so a pack landing later does not move their
// expected text. Import after ./_bundle.js and before the catalogue loads.
const CORE = new Set(["aws-cloudtrail.json", "entra-signin.json", "crowdstrike-falcon.json", "reach-sentinel-samples.json", "okta.json", "gws.json"]);
const inner = globalThis.fetch;

globalThis.fetch = async (url) => {
  const res = await inner(url);
  if (!res.ok || !/\/packs\/index\.json$/.test(String(url))) return res;
  const index = await res.json();
  const bounded = { ...index, packs: (index.packs || []).filter((f) => CORE.has(f)), values: (index.values || []).filter((v) => CORE.has(`${v.pack}.json`)) };
  return { ...res, json: async () => bounded, text: async () => JSON.stringify(bounded) };
};
