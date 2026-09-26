import { readFileSync } from "node:fs";
import { makeId, confidenceFrom } from "../core/finding.js";
import type { Finding } from "../core/finding.js";

export interface HeaderRecord {
  url: string;
  status?: number;
  headers: Record<string, string>;
}

export interface HeaderFingerprint {
  url: string;
  server?: string;
  poweredBy?: string;
  cdn?: string;
  technologies: string[];
}

const TECH_HEADERS: Record<string, string> = {
  server: "server",
  "x-powered-by": "poweredBy",
  "x-aspnet-version": "poweredBy",
  "x-drupal-cache": "poweredBy",
  "x-generator": "generator",
  "x-shopify-stage": "poweredBy",
};

const CDN_HINTS: Array<[string, string]> = [
  ["cloudflare", "cloudflare"],
  ["fastly", "fastly"],
  ["akamai", "akamai"],
  ["cloudfront", "cloudfront"],
  ["sucuri", "sucuri"],
  ["varnish", "varnish"],
];

function detectCdn(headers: Record<string, string>): string | undefined {
  const haystack =
    `${headers.server ?? ""} ${headers["x-served-by"] ?? ""} ${headers.via ?? ""} ${headers["x-cache"] ?? ""}`.toLowerCase();
  for (const [hint, name] of CDN_HINTS) {
    if (haystack.includes(hint)) return name;
  }
  return undefined;
}

export function fingerprintHeaders(record: HeaderRecord): HeaderFingerprint {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(record.headers ?? {})) {
    lower[k.toLowerCase()] = String(v);
  }

  const technologies: string[] = [];
  for (const [header] of Object.entries(TECH_HEADERS)) {
    const value = lower[header];
    if (value && !technologies.includes(value)) {
      technologies.push(value);
    }
  }

  const cdn = detectCdn(lower);

  return {
    url: record.url,
    server: lower.server,
    poweredBy: lower["x-powered-by"],
    cdn,
    technologies,
  };
}

export function parseHeaderArtifact(raw: string): HeaderRecord[] {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    return parseJsonArtifact(trimmed);
  }
  return parseRawDump(trimmed);
}

function parseJsonArtifact(raw: string): HeaderRecord[] {
  const parsed: unknown = JSON.parse(raw);
  const normalize = (entry: Record<string, unknown>): HeaderRecord | null => {
    const url = typeof entry.url === "string" ? entry.url : null;
    if (!url) return null;
    const headers: Record<string, string> = {};
    const rawHeaders = entry.headers;
    if (Array.isArray(rawHeaders)) {
      for (const h of rawHeaders as Array<[string, string] | { name: string; value: string }>) {
        if (Array.isArray(h)) {
          headers[h[0].toLowerCase()] = h[1];
        } else if (h && typeof h.name === "string") {
          headers[h.name.toLowerCase()] = String(h.value);
        }
      }
    } else if (rawHeaders && typeof rawHeaders === "object") {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
        headers[k.toLowerCase()] = String(v);
      }
    }
    const status = typeof entry.status === "number" ? entry.status : undefined;
    return { url, status, headers };
  };

  if (Array.isArray(parsed)) {
    const out: HeaderRecord[] = [];
    for (const entry of parsed as Record<string, unknown>[]) {
      const rec = normalize(entry);
      if (rec) out.push(rec);
    }
    return out;
  }
  const single = normalize(parsed as Record<string, unknown>);
  return single ? [single] : [];
}

function parseRawDump(raw: string): HeaderRecord[] {
  const blocks = raw.split(/(?=^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) \/|https?:\/\/)/m);
  const records: HeaderRecord[] = [];

  for (const block of blocks) {
    const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) continue;

    let url: string | undefined;
    let status: number | undefined;
    const headers: Record<string, string> = {};

    for (const line of lines) {
      const statusMatch = /^HTTP\/[\d.]+\s+(\d{3})/.exec(line);
      if (statusMatch) {
        status = Number(statusMatch[1]);
        continue;
      }
      if (/^https?:\/\//.test(line)) {
        url = line.replace(/\/$/, "");
        continue;
      }
      const headerMatch = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
      if (headerMatch && !url && !status) {
        continue;
      }
      if (headerMatch) {
        headers[headerMatch[1].toLowerCase()] = headerMatch[2];
      }
    }

    if (!url) {
      const host = headers.host;
      if (host) url = `http://${host}`;
    }
    if (url) {
      records.push({ url, status, headers });
    }
  }
  return records;
}

export function headerFindings(
  records: HeaderRecord[],
  rootDomain: string,
): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const record of records) {
    const fp = fingerprintHeaders(record);
    if (seen.has(fp.url)) continue;
    seen.add(fp.url);
    out.push({
      id: makeId("hdr"),
      kind: "url",
      value: fp.url,
      rootDomain,
      confidence: confidenceFrom(0.85),
      provenance: {
        source: "scan-artifact",
        method: "http-header-fingerprint",
        retrievedAt: new Date().toISOString(),
      },
      metadata: {
        server: fp.server,
        poweredBy: fp.poweredBy,
        cdn: fp.cdn,
        technologies: fp.technologies,
        headers: record.headers,
      },
    });
  }
  return out;
}

export function ingestHeaderArtifact(path: string, rootDomain: string): Finding[] {
  return headerFindings(parseHeaderArtifact(readFileSync(path, "utf8")), rootDomain);
}
