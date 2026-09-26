import { test } from "node:test";
import assert from "node:assert/strict";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

function fakeFetch(responses) {
  return async (url) => {
    const u = String(url);
    for (const [pattern, body, ok = true] of responses) {
      if (u.includes(pattern)) {
        return {
          ok,
          text: async () => body,
          json: async () => JSON.parse(body),
        };
      }
    }
    throw new Error(`unexpected url: ${u}`);
  };
}

async function withGlobalFetch(mock, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = mock;
  try {
    return await fn();
  } finally {
    globalThis.fetch = orig;
  }
}

test("wayback source extracts hosts from cdx output", async () => {
  const { WaybackSource } = await importDist("sources/wayback.js");
  const cdx = [
    "example.com/",
    "www.example.com/index.html",
    "https://api.example.com/v1",
    "other.domain.com/",
    "",
  ].join("\n");
  const source = new WaybackSource();
  const findings = await withGlobalFetch(
    fakeFetch([["web.archive.org", cdx]]),
    () => source.collect("example.com"),
  );
  assert.deepEqual(
    findings.map((f) => f.value).sort(),
    ["api.example.com", "example.com", "www.example.com"],
  );
  assert.equal(findings[0].provenance.source, "wayback-machine-cdx");
  assert.equal(findings[0].confidence, "medium");
});

test("wayback source fails soft on error response", async () => {
  const { WaybackSource } = await importDist("sources/wayback.js");
  const source = new WaybackSource();
  const findings = await withGlobalFetch(
    fakeFetch([["web.archive.org", "", false]]),
    () => source.collect("example.com"),
  );
  assert.equal(findings.length, 0);
});

test("hackertarget source parses host,ip lines", async () => {
  const { HackerTargetSource } = await importDist("sources/hackertarget.js");
  const body = [
    "www.example.com,93.184.216.34",
    "www.example.com,93.184.216.34",
    "api.example.com,93.184.216.35",
    "error check api usage",
  ].join("\n");
  const source = new HackerTargetSource();
  const findings = await withGlobalFetch(
    fakeFetch([["api.hackertarget.com", body]]),
    () => source.collect("example.com"),
  );
  assert.deepEqual(
    findings.map((f) => f.value),
    ["www.example.com", "api.example.com"],
  );
  assert.equal(findings[0].provenance.source, "hackertarget");
});

test("hackertarget source returns empty on api error body", async () => {
  const { HackerTargetSource } = await importDist("sources/hackertarget.js");
  const source = new HackerTargetSource();
  const findings = await withGlobalFetch(
    fakeFetch([["api.hackertarget.com", "error invalid host"]]),
    () => source.collect("example.com"),
  );
  assert.equal(findings.length, 0);
});
