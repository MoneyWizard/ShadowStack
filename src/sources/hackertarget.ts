import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";
import { makeId, confidenceFrom } from "../core/finding.js";

export class HackerTargetSource implements PassiveSource {
  readonly name = "hackertarget";
  readonly description = "Passive DNS subdomain lookup via hackertarget.com API";
  readonly enabled = true;

  constructor(private readonly timeoutMs = 15000) {}

  async collect(rootDomain: string): Promise<Finding[]> {
    const url = `https://api.hackertarget.com/hostsearch/?q=${rootDomain}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "user-agent": "ShadowStack/0.1 (passive recon)" },
      });
      if (!res.ok) return [];
      const body = await res.text();
      if (body.startsWith("error")) return [];

      const findings: Finding[] = [];
      const seen = new Set<string>();
      for (const line of body.split("\n")) {
        const [host, ip] = line.split(",").map((s) => s.trim());
        if (!host || !ip || seen.has(host)) continue;
        seen.add(host);

        findings.push({
          id: makeId("ht"),
          kind: "domain",
          value: host.toLowerCase(),
          rootDomain,
          confidence: confidenceFrom(0.65),
          provenance: {
            source: "hackertarget",
            method: "passive-dns",
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
