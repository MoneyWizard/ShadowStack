import { parseArgs } from "node:util";
import { Pipeline } from "./core/pipeline.js";
import { SeedSource } from "./sources/seed.js";
import { CrtShSource } from "./sources/crtsh.js";
import { SourceRegistry } from "./sources/registry.js";
import { QuietResolver } from "./resolve/resolver.js";
import { CertGrabber } from "./certs/grabber.js";
import { AssetCorrelator } from "./correlate/correlator.js";
import { ExposureLedger } from "./report/ledger.js";
import type { Finding } from "./core/finding.js";

const USAGE = `shadowstack — passive-first attack surface recon

Usage:
  shadowstack recon <domain> [options]

Options:
  --out <path>     write findings ledger to a JSON file
  --quiet          only print summary counts
  --certs          also grab TLS certificates from discovered hosts (active)
  --help           show this help

By default the engine only uses passive sources (certificate transparency,
public DNS resolution). --certs performs live TLS handshakes with
discovered hosts; only use it against assets you are authorized to assess.
`;

interface CliOptions {
  out?: string;
  quiet: boolean;
  certs: boolean;
  help: boolean;
}

function parseCli(argv: string[]): { command: string; domain: string; opts: CliOptions } | null {
  const positional: string[] = [];
  const flags = new Set<string>();
  let out: string | undefined;

  if (argv.includes("--help")) {
    return { command: "", domain: "", opts: { quiet: false, certs: false, help: true } };
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--out" && i + 1 < argv.length) {
      out = argv[++i];
      continue;
    }
    if (arg === "--out" || arg === "--quiet" || arg === "--certs" || arg === "--help") {
      flags.add(arg);
      continue;
    }
    if (arg.startsWith("--")) {
      return null;
    }
    positional.push(arg);
  }

  const [command, domain] = positional;
  if (!command || !domain) return null;

  return {
    command,
    domain,
    opts: {
      out,
      quiet: flags.has("--quiet"),
      certs: flags.has("--certs"),
      help: flags.has("--help"),
    },
  };
}

async function runRecon(domain: string, opts: CliOptions): Promise<void> {
  const registry = new SourceRegistry()
    .register(new SeedSource(domain))
    .register(new CrtShSource());

  const seed: Finding[] = [];
  const collected = await registry.collectAll(domain);
  seed.push(...collected);

  const pipeline = new Pipeline().add(new QuietResolver());
  if (opts.certs) {
    pipeline.add(new CertGrabber());
  }
  pipeline.add(new AssetCorrelator());

  const findings = await pipeline.run(collected);

  const ledger = new ExposureLedger({ outPath: opts.out });
  ledger.write(findings);

  if (!opts.quiet) {
    console.log(ledger.toConsole(findings));
  } else {
    const domains = findings.filter((f) => f.kind === "domain").length;
    const ips = findings.filter((f) => f.kind === "ip").length;
    console.log(`domains: ${domains}  ips: ${ips}`);
  }
}

async function main(): Promise<void> {
  const parsed = parseCli(process.argv.slice(2));
  if (!parsed || parsed.opts.help || parsed.command !== "recon") {
    console.log(USAGE);
    process.exitCode = parsed?.opts.help ? 0 : 1;
    return;
  }

  const domain = parsed.domain.toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(domain)) {
    console.error(`invalid domain: ${parsed.domain}`);
    process.exitCode = 1;
    return;
  }

  try {
    await runRecon(domain, parsed.opts);
  } catch (err) {
    console.error(`recon failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

void main();
