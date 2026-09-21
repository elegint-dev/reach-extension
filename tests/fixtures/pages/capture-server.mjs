// A capture endpoint for refreshing the page fixtures: the live Splunk or
// portal tab POSTs its DOM here and the body lands under tests/fixtures/
// pages/raw/ (untracked). See README.md in this directory.
//
//   node tests/fixtures/pages/capture-server.mjs        listens on 127.0.0.1:8799
//   fetch("http://127.0.0.1:8799/?name=splunk.html", { method: "POST", body: html })
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "raw");
fs.mkdirSync(out, { recursive: true });

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  if (req.method === "OPTIONS") {
    res.end();
    return;
  }
  if (req.method !== "POST") {
    res.end("POST a page body here with ?name=<file>");
    return;
  }
  const name = (new URL(req.url, "http://x").searchParams.get("name") || "capture.html").replace(/[^a-z0-9_.-]/gi, "_");
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const file = path.join(out, name);
    fs.writeFileSync(file, Buffer.concat(chunks));
    console.log(`wrote ${file} (${fs.statSync(file).size} bytes)`);
    res.end("ok");
  });
});
server.listen(8799, "127.0.0.1", () => console.log("capture server on http://127.0.0.1:8799"));
