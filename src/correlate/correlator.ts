import type { ReconStage } from "../core/pipeline.js";
import type { Finding } from "../core/finding.js";

export interface Cluster {
  key: string;
  members: string[];
  reason: string;
}

export class AssetCorrelator implements ReconStage {
  readonly name = "correlate";

  async run(findings: Finding[]): Promise<Finding[]> {
    const clusters = [
      ...this.clusterBySharedIp(findings),
      ...this.clusterBySharedCert(findings),
      ...this.clusterBySharedHeaders(findings),
    ];
    for (const f of findings) {
      const cluster = clusters.find((c) => c.members.includes(f.value));
      if (cluster) {
        f.metadata.clusterKey = cluster.key;
        f.metadata.clusterReason = cluster.reason;
      }
    }
    return findings;
  }

  private clusterBySharedHeaders(findings: Finding[]): Cluster[] {
    const bySig = new Map<string, Set<string>>();
    for (const f of findings) {
      if (f.kind !== "url") continue;
      const tech = f.metadata.technologies as string[] | undefined;
      if (!tech || tech.length === 0) continue;
      const sig = tech.slice().sort().join("|");
      const set = bySig.get(sig) ?? new Set<string>();
      set.add(f.value);
      bySig.set(sig, set);
    }
    const clusters: Cluster[] = [];
    for (const [sig, urls] of bySig) {
      if (urls.size < 2) continue;
      clusters.push({
        key: `shared-headers:${sig}`,
        members: [...urls],
        reason: `urls share header fingerprint (${sig})`,
      });
    }
    return clusters;
  }

  private clusterBySharedCert(findings: Finding[]): Cluster[] {
    const clusters: Cluster[] = [];
    for (const f of findings) {
      if (f.kind !== "cert") continue;
      const domains = f.metadata.domains as string[] | undefined;
      if (!domains || domains.length < 2) continue;
      clusters.push({
        key: `shared-cert:${f.value}`,
        members: [...domains, f.value],
        reason: `domains present the same certificate (${f.value})`,
      });
    }
    return clusters;
  }

  private clusterBySharedIp(findings: Finding[]): Cluster[] {
    const ipToDomains = new Map<string, Set<string>>();
    for (const f of findings) {
      if (f.kind !== "ip") continue;
      const domain = String(f.metadata.domain ?? "");
      if (!domain) continue;
      const set = ipToDomains.get(f.value) ?? new Set<string>();
      set.add(domain);
      ipToDomains.set(f.value, set);
    }

    const domainToIps = new Map<string, Set<string>>();
    for (const [ip, domains] of ipToDomains) {
      for (const d of domains) {
        const set = domainToIps.get(d) ?? new Set<string>();
        set.add(ip);
        domainToIps.set(d, set);
      }
    }

    const seen = new Set<string>();
    const clusters: Cluster[] = [];
    for (const [ip, domains] of ipToDomains) {
      if (domains.size < 2) continue;
      const key = `shared-ip:${ip}`;
      if (seen.has(key)) continue;
      seen.add(key);
      clusters.push({
        key,
        members: [...domains, ip],
        reason: `domains share ip ${ip}`,
      });
    }
    void domainToIps;
    return clusters;
  }
}
