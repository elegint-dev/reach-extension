// Serves app/data/*.json and app/packs/*.json to the loaders under node through a
// fetch() stub. Import it before the catalogue in any test that needs the packs.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

globalThis.fetch = async (url) => {
  const path = fileURLToPath(url);
  try {
    const text = await readFile(path, "utf8");
    return { ok: true, status: 200, statusText: "OK", json: async () => JSON.parse(text), text: async () => text };
  } catch (err) {
    return { ok: false, status: 404, statusText: String(err.code || err.message), json: async () => { throw err; }, text: async () => "" };
  }
};
