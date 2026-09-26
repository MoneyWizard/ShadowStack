import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";
import { makeId, confidenceFrom } from "../core/finding.js";

export class WaybackSource implements PassiveSource {
  readonly name = "wayback";
  readonly description = "Web archive (Wayback Machine CDX) historical subdomain discovery";
  readonly enabled = true;

  constructor(private readonly timeoutMs = 20000) {}

  async collect(rootDomain: string): Promise<Finding[]> {
    const url =
      `http://web.archive.org/cdx/search/cdx` +
      `?url=*.${rootDomain}/*&output=text&fl=original&collapse=urlkey&limit=2000`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "user-agent": "ShadowStack/0.1 (passive recon)" },
      });
      if (!res.ok) return [];
      const body = await res.text();

      const names = new Set<string>();
      for (const line of body.split("\n")) {
        const raw = line.trim();
        if (!raw) continue;
        try {
          const parsed = new URL(raw.includes("://") ? raw : `http://${raw}`);
          const host = parsed.hostname.toLowerCase();
          if (host.endsWith(`.${rootDomain}`) || host === rootDomain) {
            names.add(host);
          }
        } catch {
          continue;
        }
      }

      const findings: Finding[] = [];
      for (const name of names) {
        findings.push({
          id: makeId("wb"),
          kind: "domain",
          value: name,
          rootDomain,
          confidence: confidenceFrom(0.55),
          provenance: {
            source: "wayback-machine-cdx",
            method: "web-archive",
            retrievedAt: new Date().toISOString(),
          },
          metadata: {},
        });
      }
      return findings;
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  }
}
