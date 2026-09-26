import { connect as tlsConnect } from "node:tls";
import type { PeerCertificate } from "node:tls";

export type TlsConnect = typeof tlsConnect;
import type { ReconStage } from "../core/pipeline.js";
import type { Finding } from "../core/finding.js";
import { makeId, confidenceFrom } from "../core/finding.js";

export interface CertGrabberOptions {
  concurrency?: number;
  timeoutMs?: number;
  port?: number;
  connectFn?: typeof tlsConnect;
}

export interface CertDetails {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  serialNumber: string;
  san: string[];
}

export function parseSan(subjectaltname: string | undefined): string[] {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("DNS:"))
    .map((entry) => entry.slice("DNS:".length).toLowerCase());
}

function cn(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
}

function toDetails(cert: PeerCertificate): CertDetails | null {
  if (!cert || !cert.fingerprint256) return null;
  return {
    subject: cn(cert.subject?.CN),
    issuer: cn(cert.issuer?.CN),
    validFrom: cert.valid_from ?? "",
    validTo: cert.valid_to ?? "",
    fingerprint256: cert.fingerprint256,
    serialNumber: cert.serialNumber ?? "",
    san: parseSan(cert.subjectaltname),
  };
}

function grabCert(
  connectFn: typeof tlsConnect,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<CertDetails | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: CertDetails | null) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const socket = connectFn(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        try {
          finish(toDetails(socket.getPeerCertificate()));
        } catch {
          finish(null);
        } finally {
          socket.end();
        }
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(null);
    });
    socket.on("error", () => {
      finish(null);
    });
  });
}

export class CertGrabber implements ReconStage {
  readonly name = "certs";
  private readonly concurrency: number;
  private readonly timeoutMs: number;
  private readonly port: number;
  private readonly connectFn: typeof tlsConnect;

  constructor(options: CertGrabberOptions = {}) {
    this.concurrency = options.concurrency ?? 8;
    this.timeoutMs = options.timeoutMs ?? 8000;
    this.port = options.port ?? 443;
    this.connectFn = options.connectFn ?? tlsConnect;
  }

  async run(findings: Finding[]): Promise<Finding[]> {
    const domains = new Set<string>();
    for (const f of findings) {
      if (f.kind === "domain") domains.add(f.value);
    }

    const queue = [...domains];
    const details = new Map<string, CertDetails | null>();
    const workers = Array.from({ length: this.concurrency }, async () => {
      for (;;) {
        const domain = queue.shift();
        if (domain === undefined) return;
        details.set(domain, await grabCert(this.connectFn, domain, this.port, this.timeoutMs));
      }
    });
    await Promise.all(workers);

    const certsByFingerprint = new Map<string, Finding>();
    const out = [...findings];
    for (const [domain, cert] of details) {
      if (!cert) continue;

      const domainFinding = out.find(
        (f) => f.kind === "domain" && f.value === domain,
      );
      if (domainFinding) {
        domainFinding.metadata.certFingerprint = cert.fingerprint256;
        domainFinding.metadata.certSubject = cert.subject;
        domainFinding.metadata.certValidTo = cert.validTo;
      }

      const existing = certsByFingerprint.get(cert.fingerprint256);
      if (existing) {
        const known = existing.metadata.domains as string[];
        if (!known.includes(domain)) known.push(domain);
        const knownSan = existing.metadata.san as string[];
        for (const name of cert.san) {
          if (!knownSan.includes(name)) knownSan.push(name);
        }
        continue;
      }

      certsByFingerprint.set(cert.fingerprint256, {
        id: makeId("cert"),
        kind: "cert",
        value: cert.fingerprint256,
        rootDomain: domainFinding ? domainFinding.rootDomain : domain,
        confidence: confidenceFrom(0.95),
        provenance: {
          source: "tls-handshake",
          method: "certificate-retrieval",
          retrievedAt: new Date().toISOString(),
        },
        metadata: {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          serialNumber: cert.serialNumber,
          san: [...cert.san],
          domains: [domain],
        },
      });
    }

    out.push(...certsByFingerprint.values());
    return out;
  }
}
