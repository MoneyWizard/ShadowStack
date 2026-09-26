import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

test("fingerprintHeaders extracts server, cdn, technologies", async () => {
  const { fingerprintHeaders } = await importDist("ingest/headers.js");
  const fp = fingerprintHeaders({
    url: "https://www.example.com",
    headers: {
      Server: "cloudflare",
      "X-Powered-By": "Express",
      "X-Served-By": "cache-xyz",
    },
  });
  assert.equal(fp.server, "cloudflare");
  assert.equal(fp.poweredBy, "Express");
  assert.equal(fp.cdn, "cloudflare");
  assert.deepEqual(fp.technologies, ["cloudflare", "Express"]);
});

test("fingerprintHeaders detects cdn from via and cache headers", async () => {
  const { fingerprintHeaders } = await importDist("ingest/headers.js");
  const fp = fingerprintHeaders({
    url: "https://www.example.com",
    headers: { Via: "1.1 varnish", "X-Cache": "HIT" },
  });
  assert.equal(fp.cdn, "varnish");
});

test("parseHeaderArtifact handles json array of records", async () => {
  const { parseHeaderArtifact } = await importDist("ingest/headers.js");
  const raw = JSON.stringify([
    { url: "https://a.example.com", status: 200, headers: [["Server", "nginx"]] },
    { url: "https://b.example.com", headers: { Server: "apache", "X-Powered-By": "PHP/7.4" } },
  ]);
  const records = parseHeaderArtifact(raw);
  assert.equal(records.length, 2);
  assert.equal(records[0].headers.server, "nginx");
  assert.equal(records[1].headers["x-powered-by"], "PHP/7.4");
});

test("parseHeaderArtifact handles raw response dumps", async () => {
  const { parseHeaderArtifact } = await importDist("ingest/headers.js");
  const raw = [
    "https://a.example.com",
    "HTTP/1.1 200 OK",
    "Server: nginx",
    "X-Powered-By: Express",
    "",
    "https://b.example.com",
    "HTTP/1.1 200 OK",
    "Server: nginx",
    "X-Powered-By: Express",
  ].join("\n");
  const records = parseHeaderArtifact(raw);
  assert.equal(records.length, 2);
  assert.equal(records[0].status, 200);
  assert.equal(records[0].headers.server, "nginx");
});

test("headerFindings dedupes urls and attaches metadata", async () => {
  const { headerFindings } = await importDist("ingest/headers.js");
  const findings = headerFindings(
    [
      { url: "https://a.example.com", headers: { Server: "nginx" } },
      { url: "https://a.example.com", headers: { Server: "nginx" } },
    ],
    "example.com",
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, "url");
  assert.equal(findings[0].rootDomain, "example.com");
  assert.equal(findings[0].metadata.server, "nginx");
  assert.equal(findings[0].provenance.source, "scan-artifact");
});

test("cli ingest command end to end with clustering", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-ingest-"));
  const repoRoot = new URL("../", import.meta.url).pathname;
  try {
    const artifact = join(dir, "headers.json");
    writeFileSync(artifact, JSON.stringify([
      { url: "https://a.example.com", headers: { Server: "nginx", "X-Powered-By": "Express" } },
      { url: "https://b.example.com", headers: { Server: "nginx", "X-Powered-By": "Express" } },
    ]));
    const outPath = join(dir, "ledger.json");
    execFileSync(
      "node",
      ["dist/cli.js", "ingest", artifact, "--root-domain", "example.com", "--out", outPath, "--quiet"],
      { cwd: repoRoot, encoding: "utf8" },
    );
    const written = JSON.parse(readFileSync(outPath, "utf8"));
    assert.equal(written.findings.length, 2);
    const clustered = written.findings.filter((f) => f.metadata.clusterKey);
    assert.equal(clustered.length, 2);
    assert.ok(clustered[0].metadata.clusterKey.startsWith("shared-headers:"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli ingest fails without --root-domain", () => {
  const repoRoot = new URL("../", import.meta.url).pathname;
  let failed = false;
  try {
    execFileSync("node", ["dist/cli.js", "ingest", "/dev/null", "--quiet"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    failed = true;
    assert.ok(String(err.stderr).includes("--root-domain is required"));
  }
  assert.ok(failed);
});
