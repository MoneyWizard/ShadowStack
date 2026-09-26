import { parseArgs } from "node:util";
import { Pipeline } from "./core/pipeline.js";
import { SeedSource } from "./sources/seed.js";
import { CrtShSource } from "./sources/crtsh.js";
import { WaybackSource } from "./sources/wayback.js";
import { HackerTargetSource } from "./sources/hackertarget.js";
import { SourceRegistry } from "./sources/registry.js";
import { QuietResolver } from "./resolve/resolver.js";
import { CertGrabber } from "./certs/grabber.js";
import { AssetCorrelator } from "./correlate/correlator.js";
import { ExposureLedger } from "./report/ledger.js";
import { loadConfig, isAllowlisted, normalizeDomain } from "./config/config.js";
import type { ShadowStackConfig } from "./config/config.js";
import type { Finding } from "./core/finding.js";
import type { SourceHealth } from "./sources/registry.js";
import type { TargetReport, WatchReport } from "./report/watch.js";
import { driftFor } from "./report/watch.js";

const USAGE = `shadowstack — passive-first attack surface recon

Usage:
  shadowstack recon <domain> [options]
  shadowstack diff <ledger-a.json> <ledger-b.json> [options]
  shadowstack graph <ledger.json> [--out graph.dot] [--json]
  shadowstack ingest <headers-artifact> --root-domain <domain> [--out ledger.json]
  shadowstack watch [--config shadowstack.json] [--out report.json]
  shadowstack audit <ledger.json> [--out report.json] [--quiet]

Options (recon):
  --out <path>     write findings ledger to a JSON file
  --quiet          only print summary counts
  --certs          also grab TLS certificates from discovered hosts (active)

Options (diff):
  --out <path>     write diff result to a JSON file
  --quiet          only print summary counts

Options (graph):
  --out <path>     write graph as Graphviz DOT (default) or JSON (--json)
  --json           write the graph as node-link JSON instead of DOT
  --quiet          only print summary counts

Options (ingest):
  --root-domain <d>  root domain to tag ingested findings with (required)
  --out <path>       write ingested findings as a ledger JSON file
  --quiet            only print summary counts

Options (all):
  --config <path>    path to shadowstack.json (default: shadowstack.json)

watch runs recon for every allowlisted target, diffs against the previous
ledger, and exits 2 if any drift or source failure was detected.

audit runs severity-scored checks over a ledger (cert expiry, dangling
CNAMEs, wildcard cert sprawl, missing security headers, source health)
and exits 2 if any high-severity issue is found.

  --help           show this help

By default the engine only uses passive sources (certificate transparency,
public DNS resolution). --certs performs live TLS handshakes with
discovered hosts; only use it against assets you are authorized to assess.
`;

interface CliOptions {
  out?: string;
  quiet: boolean;
  certs: boolean;
  json: boolean;
  rootDomain?: string;
  configPath?: string;
  help: boolean;
}

function parseCli(argv: string[]): { command: string; positional: string[]; opts: CliOptions } | null {
  const positional: string[] = [];
  const flags = new Set<string>();
  let out: string | undefined;
  let rootDomain: string | undefined;
  let configPath: string | undefined;

  if (argv.includes("--help")) {
    return { command: "", positional: [], opts: { quiet: false, certs: false, json: false, help: true } };
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--out" && i + 1 < argv.length) {
      out = argv[++i];
      continue;
    }
    if (arg === "--root-domain" && i + 1 < argv.length) {
      rootDomain = argv[++i].toLowerCase().replace(/\.$/, "");
      continue;
    }
    if (arg === "--config" && i + 1 < argv.length) {
      configPath = argv[++i];
      continue;
    }
    if (arg === "--out" || arg === "--quiet" || arg === "--certs" || arg === "--json" || arg === "--help") {
      flags.add(arg);
      continue;
    }
    if (arg.startsWith("--")) {
      return null;
    }
    positional.push(arg);
  }

  const command = positional[0];
  if (!command) return null;

  if (command === "diff") {
    if (positional.length < 3) return null;
  } else if (command === "graph") {
    if (positional.length < 2) return null;
  } else if (command === "ingest") {
    if (positional.length < 2) return null;
  } else if (command === "watch") {
    if (positional.length !== 1) return null;
  } else if (command === "audit") {
    if (positional.length < 2) return null;
  } else if (positional.length < 2) {
    return null;
  }

  return {
    command,
    positional,
    opts: {
      out,
      quiet: flags.has("--quiet"),
      certs: flags.has("--certs"),
      json: flags.has("--json"),
      rootDomain,
      configPath,
      help: flags.has("--help"),
    },
  };
}

interface ReconResult {
  findings: Finding[];
  health: SourceHealth[];
}

async function collectDomain(
  domain: string,
  config: ShadowStackConfig,
): Promise<ReconResult> {
  const registry = new SourceRegistry().register(new SeedSource(domain));
  if (config.sources.crtsh) registry.register(new CrtShSource());
  if (config.sources.wayback) registry.register(new WaybackSource());
  if (config.sources.hackertarget) registry.register(new HackerTargetSource());

  const { findings: collected, health } = await registry.collectAll(domain);

  const pipeline = new Pipeline().add(new QuietResolver());
  if (config.certs.enabled) {
    pipeline.add(new CertGrabber());
  }
  pipeline.add(new AssetCorrelator());

  const findings = await pipeline.run(collected);
  return { findings, health };
}

async function runRecon(
  domain: string,
  opts: CliOptions,
  config: ShadowStackConfig,
): Promise<ReconResult> {
  if (!isAllowlisted(domain, config.targets)) {
    throw new Error(
      `domain not in allowlist: ${domain} — add it to config.targets (assets you are authorized to assess only)`,
    );
  }

  const result = await collectDomain(domain, config);

  const ledger = new ExposureLedger({ outPath: opts.out });
  const { alerts } = ledger.write(result.findings);

  if (!opts.quiet) {
    console.log(ledger.toConsole(result.findings, alerts));
    const failures = result.health.filter((h) => h.status === "failed");
    if (failures.length > 0) {
      console.log(`  source failures:`);
      for (const f of failures) {
        console.log(`    ! ${f.source}: ${f.error ?? "unknown error"}`);
      }
    }
  } else {
    const domains = result.findings.filter((f) => f.kind === "domain").length;
    const ips = result.findings.filter((f) => f.kind === "ip").length;
    const failed = result.health.filter((h) => h.status === "failed").length;
    console.log(`domains: ${domains}  ips: ${ips}  source failures: ${failed}`);
  }
  return result;
}

async function runDiff(paths: string[], opts: CliOptions): Promise<void> {
  const { readFileSync } = await import("node:fs");
  const { diffLedgers, diffToConsole } = await import("./report/diff.js");
  const aRaw = JSON.parse(readFileSync(paths[0], "utf8"));
  const bRaw = JSON.parse(readFileSync(paths[1], "utf8"));
  const diff = diffLedgers(aRaw, bRaw);

  if (opts.out) {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(
      opts.out,
      JSON.stringify({ diffedAt: new Date().toISOString(), ...diff }, null, 2),
    );
  }

  if (!opts.quiet) {
    console.log(diffToConsole(diff));
  } else {
    console.log(
      `added: ${diff.added.length}  removed: ${diff.removed.length}  rotations: ${diff.certRotations.length}`,
    );
  }
}

async function runGraph(path: string, opts: CliOptions): Promise<void> {
  const { readFileSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { dirname } = await import("node:path");
  const { buildGraph, toDot, graphToConsole } = await import("./report/graph.js");
  const ledger = JSON.parse(readFileSync(path, "utf8"));
  const graph = buildGraph(ledger.findings);

  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true });
    if (opts.json) {
      writeFileSync(opts.out, JSON.stringify(graph, null, 2));
    } else {
      writeFileSync(opts.out, toDot(graph));
    }
  } else if (opts.json) {
    console.log(JSON.stringify(graph, null, 2));
  } else {
    console.log(toDot(graph));
  }

  if (!opts.quiet) {
    console.error(graphToConsole(graph));
  }
}

async function runIngest(path: string, opts: CliOptions): Promise<void> {
  if (!opts.rootDomain) {
    throw new Error("--root-domain is required for ingest");
  }
  const { ingestHeaderArtifact } = await import("./ingest/headers.js");
  const { AssetCorrelator } = await import("./correlate/correlator.js");
  const { ExposureLedger } = await import("./report/ledger.js");
  const findings = ingestHeaderArtifact(path, opts.rootDomain);
  const correlated = await new AssetCorrelator().run(findings);
  const ledger = new ExposureLedger({ outPath: opts.out });
  const { alerts } = ledger.write(correlated);
  if (!opts.quiet) {
    console.log(ledger.toConsole(correlated, alerts));
  } else {
    console.log(`urls: ${correlated.filter((f) => f.kind === "url").length}`);
  }
}

async function runWatch(config: ShadowStackConfig, opts: CliOptions): Promise<void> {
  const {
    latestLedger,
    ledgerFileName,
    pruneLedgers,
    readLedgerFindings,
    writeLedger,
    watchToConsole,
  } = await import("./report/watch.js");
  const dir = config.watch.ledgerDir;
  const targets: TargetReport[] = [];
  let driftCount = 0;
  let sourceFailureCount = 0;

  for (const target of config.targets) {
    const result = await collectDomain(target, config);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const ledgerPath = writeLedger(dir, ledgerFileName(target, timestamp), result.findings, result.health);

    const previousPath = latestLedger(dir, target);
    let previous: Finding[] | null = null;
    if (previousPath && previousPath !== ledgerPath) {
      previous = readLedgerFindings(previousPath);
    }

    const drift = driftFor(previous, result.findings);
    if (drift && (drift.added.length > 0 || drift.removed.length > 0 || drift.certRotations.length > 0)) {
      driftCount += 1;
    }

    const sourceFailures = result.health
      .filter((h) => h.status === "failed")
      .map((h) => ({ source: h.source, error: h.error }));
    sourceFailureCount += sourceFailures.length;

    pruneLedgers(dir, target, config.watch.retention);

    targets.push({
      target,
      ledgerPath,
      previousLedgerPath: previousPath ?? undefined,
      findings: result.findings.length,
      drift,
      sourceFailures,
    });
  }

  const report: WatchReport = {
    ranAt: new Date().toISOString(),
    targets,
    driftCount,
    sourceFailureCount,
  };

  if (opts.out) {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, JSON.stringify(report, null, 2));
  }

  console.log(opts.quiet ? `targets: ${targets.length}  drift: ${driftCount}  source failures: ${sourceFailureCount}` : watchToConsole(report));

  if (driftCount > 0 || sourceFailureCount > 0) {
    process.exitCode = 2;
  }
}

async function runAuditCmd(path: string, opts: CliOptions): Promise<void> {
  const { readFileSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { dirname } = await import("node:path");
  const { runAudit, auditToConsole } = await import("./audit/audit.js");
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const findings = Array.isArray(parsed?.findings) ? parsed.findings : [];
  const sources = Array.isArray(parsed?.sources) ? parsed.sources : [];

  const report = runAudit(findings, sources);

  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(
      opts.out,
      JSON.stringify({ ...report, ledgerPath: path }, null, 2),
    );
  }

  console.log(opts.quiet
    ? `issues: ${report.issues.length}  high: ${report.counts.high}  medium: ${report.counts.medium}  low: ${report.counts.low}`
    : auditToConsole(report));

  if (report.counts.high > 0) {
    process.exitCode = 2;
  }
}

async function main(): Promise<void> {
  const parsed = parseCli(process.argv.slice(2));
  if (
    !parsed ||
    parsed.opts.help ||
    (
      parsed.command !== "recon" &&
      parsed.command !== "diff" &&
      parsed.command !== "graph" &&
      parsed.command !== "ingest" &&
      parsed.command !== "watch" &&
      parsed.command !== "audit"
    )
  ) {
    console.log(USAGE);
    process.exitCode = parsed?.opts.help ? 0 : 1;
    return;
  }

  if (parsed.command === "diff") {
    try {
      await runDiff([parsed.positional[1], parsed.positional[2]], parsed.opts);
    } catch (err) {
      console.error(`diff failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "graph") {
    try {
      await runGraph(parsed.positional[1], parsed.opts);
    } catch (err) {
      console.error(`graph failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "ingest") {
    try {
      await runIngest(parsed.positional[1], parsed.opts);
    } catch (err) {
      console.error(`ingest failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "audit") {
    try {
      await runAuditCmd(parsed.positional[1], parsed.opts);
    } catch (err) {
      console.error(`audit failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "watch") {
    try {
      const config = loadConfig(parsed.opts.configPath ?? "shadowstack.json");
      await runWatch(config, parsed.opts);
    } catch (err) {
      console.error(`watch failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  const domain = normalizeDomain(parsed.positional[1]);
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(domain)) {
    console.error(`invalid domain: ${parsed.positional[1]}`);
    process.exitCode = 1;
    return;
  }

  try {
    const config = loadConfig(parsed.opts.configPath ?? "shadowstack.json");
    if (parsed.opts.certs) config.certs.enabled = true;
    await runRecon(domain, parsed.opts, config);
  } catch (err) {
    console.error(`recon failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

void main();
