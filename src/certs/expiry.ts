import type { Finding } from "../core/finding.js";

export type ExpiryStatus = "expired" | "critical" | "warning" | "ok";

export interface ExpiryAlert {
  fingerprint: string;
  subject: string;
  validTo: string;
  daysRemaining: number;
  status: ExpiryStatus;
  domains: string[];
}

const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

export function parseOpenSslDate(value: string): Date | null {
  const match = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+GMT$/.exec(
    value.trim(),
  );
  if (!match) return null;
  const [, monthName, day, time, year] = match;
  const month = MONTHS.indexOf(monthName);
  if (month === -1) return null;
  const [h, m, s] = time.split(":").map(Number);
  const date = new Date(
    Date.UTC(Number(year), month, Number(day), h, m, s),
  );
  return isNaN(date.getTime()) ? null : date;
}

export function daysRemaining(validTo: string, now = new Date()): number {
  const expiry = parseOpenSslDate(validTo);
  if (!expiry) return Number.NaN;
  const ms = expiry.getTime() - now.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

export function statusFor(days: number): ExpiryStatus {
  if (isNaN(days)) return "ok";
  if (days < 0) return "expired";
  if (days <= 7) return "critical";
  if (days <= 30) return "warning";
  return "ok";
}

export function expiryAlerts(
  findings: Finding[],
  now = new Date(),
): ExpiryAlert[] {
  const alerts: ExpiryAlert[] = [];
  for (const f of findings) {
    if (f.kind !== "cert") continue;
    const validTo = String(f.metadata.validTo ?? "");
    if (!validTo) continue;
    const days = daysRemaining(validTo, now);
    const status = statusFor(days);
    if (status === "ok") continue;
    alerts.push({
      fingerprint: f.value,
      subject: String(f.metadata.subject ?? ""),
      validTo,
      daysRemaining: days,
      status,
      domains: (f.metadata.domains as string[] | undefined) ?? [],
    });
  }
  return alerts.sort((a, b) => a.daysRemaining - b.daysRemaining);
}
