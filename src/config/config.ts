import { readFileSync, existsSync } from "node:fs";

export interface SourceConfig {
  crtsh: boolean;
  wayback: boolean;
  hackertarget: boolean;
}

export interface CertsConfig {
  enabled: boolean;
  warnDays: number;
  criticalDays: number;
  saveDir?: string;
}

export interface WatchConfig {
  ledgerDir: string;
  retention: number;
}

export interface ShadowStackConfig {
  targets: string[];
  sources: SourceConfig;
  certs: CertsConfig;
  watch: WatchConfig;
}

export const DEFAULT_CONFIG: ShadowStackConfig = {
  targets: [],
  sources: { crtsh: true, wayback: true, hackertarget: true },
  certs: { enabled: false, warnDays: 30, criticalDays: 7 },
  watch: { ledgerDir: "recon-output", retention: 30 },
};

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

export function normalizeDomain(input: string): string {
  return input.trim().toLowerCase().replace(/\.$/, "");
}

export function isAllowlisted(domain: string, targets: string[]): boolean {
  const normalized = normalizeDomain(domain);
  return targets.some((t) => {
    const target = normalizeDomain(t);
    return normalized === target || normalized.endsWith(`.${target}`);
  });
}

function coerceNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : fallback;
}

export function loadConfig(path: string): ShadowStackConfig {
  if (!existsSync(path)) {
    throw new Error(`config file not found: ${path}`);
  }
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("config must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;

  const targetsRaw = obj.targets;
  if (!Array.isArray(targetsRaw) || targetsRaw.length === 0) {
    throw new Error("config.targets must be a non-empty array of domains you are authorized to assess");
  }
  const targets = targetsRaw.map((t) => {
    const normalized = normalizeDomain(String(t));
    if (!DOMAIN_RE.test(normalized)) {
      throw new Error(`config.targets contains an invalid domain: ${String(t)}`);
    }
    return normalized;
  });

  const sourcesRaw = (obj.sources ?? {}) as Record<string, unknown>;
  const sources: SourceConfig = {
    crtsh: sourcesRaw.crtsh !== false,
    wayback: sourcesRaw.wayback !== false,
    hackertarget: sourcesRaw.hackertarget !== false,
  };

  const certsRaw = (obj.certs ?? {}) as Record<string, unknown>;
  const certs: CertsConfig = {
    enabled: certsRaw.enabled === true,
    warnDays: coerceNumber(certsRaw.warnDays, DEFAULT_CONFIG.certs.warnDays),
    criticalDays: coerceNumber(certsRaw.criticalDays, DEFAULT_CONFIG.certs.criticalDays),
    saveDir: typeof certsRaw.saveDir === "string" ? certsRaw.saveDir : undefined,
  };

  const watchRaw = (obj.watch ?? {}) as Record<string, unknown>;
  const watch: WatchConfig = {
    ledgerDir:
      typeof watchRaw.ledgerDir === "string" && watchRaw.ledgerDir.length > 0
        ? watchRaw.ledgerDir
        : DEFAULT_CONFIG.watch.ledgerDir,
    retention: coerceNumber(watchRaw.retention, DEFAULT_CONFIG.watch.retention),
  };

  return { targets, sources, certs, watch };
}
