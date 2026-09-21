// download(name, text, type): hand the browser a file to save. The share
// page and the runbook page both write JSON this way; nothing leaves the
// browser except as the file the user picks a place for.

import { h } from "./h.js";

export function download(name, text, type = "application/json") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function slug(text, max = 60) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max) || "reach";
}

export default { download, slug };
