import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";
import { makeId, confidenceFrom } from "../core/finding.js";

interface CrtShEntry {
  name: string | null;
}

export class CrtShSource implements PassiveSource {
  readonly name = "crtsh";
  readonly description = "Certificate transparency log aggregation via crt.sh";
  readonly enabled = true;

  constructor(private readonly timeoutMs = 15000) {}

  async collect(rootDomain: string): Promise<Finding[]> {
    const url = `https://crt.sh/?q=%.${rootDomain}&output=json`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "user-agent": "ShadowStack/0.1 (passive recon)" },
      });
      if (!res.ok) {
        return [];
      }
      const entries = (await res.json()) as CrtShEntry[];
      const names = new Set<string>();
      for (const entry of entries) {
        if (entry.name) {
          names.add(entry.name.toLowerCase());
        }
      }
      const findings: Finding[] = [];
      for (const name of names) {
        findings.push({
          id: makeId("crt"),
          kind: "domain",
          value: name,
          rootDomain,
          confidence: confidenceFrom(0.8),
          provenance: {
            source: "crt.sh",
            method: "certificate-transparency",
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
