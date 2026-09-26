import { test } from "node:test";
import assert from "node:assert/strict";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

test("parseOpenSslDate parses openssl gmt format", async () => {
  const { parseOpenSslDate } = await importDist("certs/expiry.js");
  const d = parseOpenSslDate("Jan  1 00:00:00 2027 GMT");
  assert.ok(d instanceof Date);
  assert.equal(d.toISOString(), "2027-01-01T00:00:00.000Z");
  assert.equal(parseOpenSslDate("not a date"), null);
});

test("daysRemaining computes floor of days", async () => {
  const { daysRemaining } = await importDist("certs/expiry.js");
  const now = new Date("2026-09-26T00:00:00Z");
  assert.equal(daysRemaining("Oct  3 00:00:00 2026 GMT", now), 7);
  assert.equal(daysRemaining("Sep 25 00:00:00 2026 GMT", now), -1);
  assert.ok(isNaN(daysRemaining("garbage", now)));
});

test("statusFor classifies thresholds", async () => {
  const { statusFor } = await importDist("certs/expiry.js");
  assert.equal(statusFor(-1), "expired");
  assert.equal(statusFor(0), "critical");
  assert.equal(statusFor(7), "critical");
  assert.equal(statusFor(8), "warning");
  assert.equal(statusFor(30), "warning");
  assert.equal(statusFor(31), "ok");
  assert.equal(statusFor(NaN), "ok");
});

test("expiryAlerts sorts and filters from findings", async () => {
  const { expiryAlerts } = await importDist("certs/expiry.js");
  const now = new Date("2026-09-26T00:00:00Z");
  const findings = [
    { id: "1", kind: "cert", value: "AA", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { subject: "ok.example.com", validTo: "Jan  1 00:00:00 2027 GMT", domains: ["ok.example.com"] } },
    { id: "2", kind: "cert", value: "BB", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { subject: "crit.example.com", validTo: "Sep 29 00:00:00 2026 GMT", domains: ["crit.example.com"] } },
    { id: "3", kind: "cert", value: "CC", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { subject: "warn.example.com", validTo: "Oct 20 00:00:00 2026 GMT", domains: ["warn.example.com"] } },
    { id: "4", kind: "domain", value: "x.example.com", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: {} },
  ];
  const alerts = expiryAlerts(findings, now);
  assert.equal(alerts.length, 2);
  assert.equal(alerts[0].status, "critical");
  assert.equal(alerts[0].daysRemaining, 3);
  assert.equal(alerts[1].status, "warning");
  assert.equal(alerts[1].daysRemaining, 24);
});

test("ledger embeds expiry alerts in json output", async () => {
  const { ExposureLedger } = await importDist("report/ledger.js");
  const { mkdtempSync, readFileSync: rf, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-expiry-"));
  const outPath = join(dir, "ledger.json");
  const now = new Date("2026-09-26T00:00:00Z");
  const findings = [
    { id: "1", kind: "cert", value: "AA", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { subject: "crit.example.com", validTo: "Sep 29 00:00:00 2026 GMT", domains: ["crit.example.com"] } },
  ];
  const ledger = new ExposureLedger({ outPath, now });
  const { alerts } = ledger.write(findings);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].status, "critical");
  const written = JSON.parse(rf(outPath, "utf8"));
  assert.equal(written.alerts.expiry.length, 1);
  assert.equal(written.alerts.expiry[0].fingerprint, "AA");
  assert.ok(ledger.toConsole(findings, alerts).includes("[critical]"));
  rmSync(dir, { recursive: true, force: true });
});
