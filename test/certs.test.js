import { test } from "node:test";
import assert from "node:assert/strict";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

test("parseSan extracts dns names only", async () => {
  const { parseSan } = await importDist("certs/grabber.js");
  const input =
    "DNS:Example.COM, DNS:*.example.com, IP Address:1.2.3.4, DNS:other.example.com";
  assert.deepEqual(parseSan(input), [
    "example.com",
    "*.example.com",
    "other.example.com",
  ]);
  assert.deepEqual(parseSan(undefined), []);
});

test("cert grabber dedupes by fingerprint and tags domains", async () => {
  const { CertGrabber } = await importDist("certs/grabber.js");
  const fakeCert = {
    subject: { CN: "a.invalid" },
    issuer: { CN: "Fake CA" },
    valid_from: "Jan  1 00:00:00 2026 GMT",
    valid_to: "Jan  1 00:00:00 2027 GMT",
    fingerprint256: "AB:CD",
    serialNumber: "01",
    subjectaltname: "DNS:a.invalid, DNS:b.invalid",
  };
  const fakeConnect = (_opts, onConnect) => {
    const socket = {
      getPeerCertificate: () => fakeCert,
      end: () => {},
      setTimeout: () => {},
      on: () => {},
    };
    if (onConnect) queueMicrotask(() => onConnect());
    return socket;
  };
  const grabber = new CertGrabber({ concurrency: 2, timeoutMs: 1, connectFn: fakeConnect });
  const findings = [
    { id: "1", kind: "domain", value: "a.invalid", rootDomain: "invalid", confidence: "high", provenance: {}, metadata: {} },
    { id: "2", kind: "domain", value: "b.invalid", rootDomain: "invalid", confidence: "high", provenance: {}, metadata: {} },
  ];

  const out = await grabber.run(findings);
  const certs = out.filter((f) => f.kind === "cert");
  assert.equal(certs.length, 1, "dedupes by fingerprint");
  assert.equal(certs[0].metadata.domains.length, 2);
  assert.deepEqual(certs[0].metadata.san, ["a.invalid", "b.invalid"]);
  const a = out.find((f) => f.value === "a.invalid");
  assert.equal(a.metadata.certFingerprint, "AB:CD");
  assert.equal(a.metadata.certSubject, "a.invalid");
});

test("correlator clusters domains sharing a cert", async () => {
  const { AssetCorrelator } = await importDist("correlate/correlator.js");
  const findings = [
    { id: "1", kind: "cert", value: "AB:CD", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { domains: ["a.example.com", "b.example.com"] } },
    { id: "2", kind: "domain", value: "a.example.com", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: {} },
    { id: "3", kind: "domain", value: "b.example.com", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: {} },
  ];
  const correlator = new AssetCorrelator();
  const out = await correlator.run(findings);
  const clustered = out.filter((f) => f.metadata.clusterKey);
  assert.equal(clustered.length, 3);
  assert.equal(clustered[0].metadata.clusterKey, "shared-cert:AB:CD");
});
