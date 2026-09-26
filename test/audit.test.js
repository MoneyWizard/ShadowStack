import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

const f = (kind, value, extra = {}) => ({
  id: `${kind}-${value}`,
  kind,
  value,
  rootDomain: "example.com",
  confidence: "high",
  provenance: { source: "t", method: "t", retrievedAt: "now" },
  metadata: { ...extra },
});

const NOW = new Date("2026-09-26T00:00:00Z");

test("auditCertExpiry flags expiring and expired certs by severity", async () => {
  const { auditCertExpiry } = await importDist("audit/audit.js");
  const issues = auditCertExpiry(
    [
      f("cert", "expired", { validTo: "Sep 20 00:00:00 2026 GMT", domains: ["a.example.com"] }),
      f("cert", "critical", { validTo: "Sep 29 00:00:00 2026 GMT", domains: ["b.example.com"] }),
      f("cert", "warning", { validTo: "Oct 20 00:00:00 2026 GMT", domains: ["c.example.com"] }),
      f("cert", "ok", { validTo: "Jan  1 00:00:00 2028 GMT" }),
    ],
    { now: NOW },
  );
  assert.equal(issues.length, 3);
  assert.equal(issues[0].severity, "high");
  assert.ok(issues[0].detail.includes("expired 6 days ago"));
  assert.equal(issues[1].severity, "high");
  assert.equal(issues[2].severity, "medium");
});

test("auditDanglingCname flags takeover risk as high", async () => {
  const { auditDanglingCname } = await importDist("audit/audit.js");
  const issues = auditDanglingCname([
    f("domain", "dead.example.com", { cname: "old.herokuapp.com", cnameDangling: true }),
    f("domain", "alive.example.com", { cname: "live.herokuapp.com", cnameDangling: false }),
    f("domain", "plain.example.com"),
  ]);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].severity, "high");
  assert.equal(issues[0].check, "dangling-cname");
  assert.ok(issues[0].detail.includes("old.herokuapp.com"));
});

test("auditWildcardCertSprawl flags wildcard sans", async () => {
  const { auditWildcardCertSprawl } = await importDist("audit/audit.js");
  const issues = auditWildcardCertSprawl([
    f("cert", "wild", { san: ["*.example.com", "example.com"] }),
    f("cert", "tight", { san: ["only.example.com"] }),
  ]);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].severity, "medium");
  assert.ok(issues[0].detail.includes("*.example.com"));
});

test("auditSecurityHeaders rates by missing count", async () => {
  const { auditSecurityHeaders } = await importDist("audit/audit.js");
  const issues = auditSecurityHeaders([
    f("url", "https://bad.example.com", {
      headers: { server: "nginx" },
    }),
    f("url", "https://ok.example.com", {
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
      },
    }),
    f("url", "https://partial.example.com", {
      headers: {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
      },
    }),
  ]);
  assert.equal(issues.length, 2);
  const bad = issues.find((i) => i.asset === "https://bad.example.com");
  assert.equal(bad.severity, "medium");
  const partial = issues.find((i) => i.asset === "https://partial.example.com");
  assert.equal(partial.severity, "low");
  assert.ok(partial.detail.includes("x-frame-options"));
});

test("auditSourceHealth reports failed sources as low", async () => {
  const { auditSourceHealth } = await importDist("audit/audit.js");
  const issues = auditSourceHealth([
    { source: "crtsh", status: "ok" },
    { source: "wayback", status: "failed", error: "timeout" },
  ]);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].severity, "low");
  assert.ok(issues[0].detail.includes("timeout"));
});

test("runAudit sorts by severity and counts", async () => {
  const { runAudit } = await importDist("audit/audit.js");
  const report = runAudit(
    [
      f("domain", "dead.example.com", { cname: "x.example.net", cnameDangling: true }),
      f("cert", "wild", { san: ["*.example.com"] }),
      f("cert", "expired", { validTo: "Sep 20 00:00:00 2026 GMT", domains: [] }),
    ],
    [{ source: "wayback", status: "failed", error: "boom" }],
    { now: NOW },
  );
  assert.equal(report.counts.high, 2);
  assert.equal(report.counts.medium, 1);
  assert.equal(report.counts.low, 1);
  assert.equal(report.issues[0].severity, "high");
  assert.equal(report.issues[report.issues.length - 1].severity, "low");
});

test("cli audit exits 2 on high severity, 0 when clean", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-audit-"));
  const repoRoot = new URL("../", import.meta.url).pathname;
  try {
    const bad = join(dir, "bad.json");
    writeFileSync(bad, JSON.stringify({
      generatedAt: "2026-01-01T00:00:00Z",
      findings: [
        f("domain", "dead.example.com", { cname: "x.example.net", cnameDangling: true }),
      ],
      sources: [],
    }));
    let code = 0;
    try {
      execFileSync("node", ["dist/cli.js", "audit", bad, "--quiet"], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      code = err.status ?? 1;
    }
    assert.equal(code, 2);

    const clean = join(dir, "clean.json");
    writeFileSync(clean, JSON.stringify({
      generatedAt: "2026-01-01T00:00:00Z",
      findings: [f("domain", "fine.example.com")],
      sources: [{ source: "crtsh", status: "ok" }],
    }));
    const out = execFileSync("node", ["dist/cli.js", "audit", clean, "--quiet"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    assert.ok(out.includes("issues: 0"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
