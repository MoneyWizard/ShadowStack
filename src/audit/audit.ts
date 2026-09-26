import type { Finding } from "../core/finding.js";
import { daysRemaining, statusFor } from "../certs/expiry.js";
import type { ExpiryStatus } from "../certs/expiry.js";

export type Severity = "high" | "medium" | "low";

export interface AuditIssue {
  check: string;
  severity: Severity;
  asset: string;
  detail: string;
}

export interface AuditReport {
  ranAt: string;
  ledgerPath?: string;
  issues: AuditIssue[];
  counts: Record<Severity, number>;
}

export interface AuditOptions {
  now?: Date;
  warnDays?: number;
  criticalDays?: number;
}

export const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
] as const;

function sev(status: ExpiryStatus, criticalStatus: ExpiryStatus): Severity {
  if (status === "expired") return "high";
  if (status === "critical") return "high";
  if (status === criticalStatus) return "medium";
  return "low";
}

export function auditCertExpiry(
  findings: Finding[],
  options: AuditOptions = {},
): AuditIssue[] {
  const now = options.now ?? new Date();
  const criticalDays = options.criticalDays ?? 7;
  const issues: AuditIssue[] = [];
  for (const f of findings) {
    if (f.kind !== "cert") continue;
    const validTo = String(f.metadata.validTo ?? "");
    if (!validTo) continue;
    const days = daysRemaining(validTo, now);
    const status = statusFor(days);
    if (status === "ok") continue;
    const domains = (f.metadata.domains as string[] | undefined) ?? [];
    issues.push({
      check: "cert-expiry",
      severity: status === "warning" ? "medium" : sev(status, "critical"),
      asset: f.value,
      detail:
        days < 0
          ? `certificate expired ${-days} days ago (validTo ${validTo}); domains: ${domains.join(", ")}`
          : `certificate expires in ${days} days (validTo ${validTo}); domains: ${domains.join(", ")}`,
    });
  }
  return issues;
}

export function auditDanglingCname(findings: Finding[]): AuditIssue[] {
  const issues: AuditIssue[] = [];
  for (const f of findings) {
    if (f.kind !== "domain") continue;
    if (f.metadata.cnameDangling === true) {
      const cname = String(f.metadata.cname ?? "unknown");
      issues.push({
        check: "dangling-cname",
        severity: "high",
        asset: f.value,
        detail: `CNAME points to ${cname} which does not resolve — possible takeover risk`,
      });
    }
  }
  return issues;
}

export function auditWildcardCertSprawl(findings: Finding[]): AuditIssue[] {
  const wildcardCerts = findings.filter(
    (f) =>
      f.kind === "cert" &&
      Array.isArray(f.metadata.san) &&
      (f.metadata.san as string[]).some((s) => s.startsWith("*.")),
  );
  const issues: AuditIssue[] = [];
  for (const f of wildcardCerts) {
    const san = (f.metadata.san as string[]).filter((s) => s.startsWith("*."));
    issues.push({
      check: "wildcard-cert",
      severity: "medium",
      asset: f.value,
      detail: `wildcard cert covers ${san.join(", ")} — a compromise of this cert affects all subdomains`,
    });
  }
  return issues;
}

export function auditSecurityHeaders(findings: Finding[]): AuditIssue[] {
  const issues: AuditIssue[] = [];
  for (const f of findings) {
    if (f.kind !== "url") continue;
    const headers = (f.metadata.headers as Record<string, string> | undefined) ?? undefined;
    if (!headers) continue;
    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
    const missing = SECURITY_HEADERS.filter((h) => !lower[h]);
    if (missing.length > 0) {
      issues.push({
        check: "security-headers",
        severity: missing.length >= 3 ? "medium" : "low",
        asset: f.value,
        detail: `missing security headers: ${missing.join(", ")}`,
      });
    }
  }
  return issues;
}

export function auditSourceHealth(
  sources: Array<{ source: string; status: string; error?: string }>,
): AuditIssue[] {
  return sources
    .filter((s) => s.status === "failed")
    .map((s) => ({
      check: "source-health",
      severity: "low" as Severity,
      asset: s.source,
      detail: `source failed during collection${s.error ? `: ${s.error}` : ""}`,
    }));
}

export function runAudit(
  findings: Finding[],
  sources: Array<{ source: string; status: string; error?: string }> = [],
  options: AuditOptions = {},
): AuditReport {
  const issues = [
    ...auditCertExpiry(findings, options),
    ...auditDanglingCname(findings),
    ...auditWildcardCertSprawl(findings),
    ...auditSecurityHeaders(findings),
    ...auditSourceHealth(sources),
  ];
  const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  issues.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    ranAt: new Date().toISOString(),
    issues,
    counts: {
      high: issues.filter((i) => i.severity === "high").length,
      medium: issues.filter((i) => i.severity === "medium").length,
      low: issues.filter((i) => i.severity === "low").length,
    },
  };
}

export function auditToConsole(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`shadowstack audit — ${report.ranAt}`);
  lines.push(
    `  issues: ${report.issues.length} (high: ${report.counts.high}, medium: ${report.counts.medium}, low: ${report.counts.low})`,
  );
  for (const i of report.issues) {
    lines.push(`  [${i.severity}] ${i.check}: ${i.asset}`);
    lines.push(`      ${i.detail}`);
  }
  return lines.join("\n");
}
