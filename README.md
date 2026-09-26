# ShadowStack

Passive-first attack surface recon engine. ShadowStack discovers what is *already exposed* about assets you are authorized to assess — without touching the target directly.

## Vision

ShadowStack maps the "stack shadow": the hidden infrastructure topology behind your domains that never made it into your asset inventory. It is built as a pipeline of small, auditable stages:

```
sources → resolve → correlate → report
```

- **sources** — pluggable passive intel adapters: certificate transparency (crt.sh), web archive history (Wayback Machine CDX), and passive DNS (HackerTarget). No active scanning, no probing.
- **resolve** — quiet DNS resolution through public resolvers, with bounded concurrency.
- **certs** — opt-in certificate grabber: live TLS handshake with discovered hosts to pull subject, issuer, validity window, serial, SHA-256 fingerprint, and SANs. Certificates are deduped by fingerprint — one finding per deployed cert, tagged with every domain that presents it.
- **correlate** — clusters assets that share infrastructure: domains on the same IP (`shared-ip:`), domains presenting the same certificate (`shared-cert:` — a strong same-deployment signal), and URLs sharing an HTTP header fingerprint (`shared-headers:`), revealing hidden topology.
- **ingest** — HTTP header fingerprint ingestion from existing scan artifacts (JSON or raw response dumps): server, x-powered-by, and CDN detection, no live traffic.
- **report** — an exposure ledger: every finding carries source provenance, timestamp, and confidence. Auditable, re-runnable, diffable over time. With `--certs`, the ledger also carries expiry alerts (`expired` / `critical` ≤7d / `warning` ≤30d). The `diff` command surfaces drift between runs (added/removed assets, cert rotations); the `graph` command exports the asset relationship graph as Graphviz DOT or node-link JSON.

## Install & build

```bash
npm install
npm run build
```

## Usage

Configuration is allowlist-based: create a `shadowstack.json` (see `shadowstack.example.json`) listing the targets you are authorized to assess. The `recon` and `watch` commands refuse any domain not in `config.targets` (subdomains of listed targets are allowed).

```json
{
  "targets": ["example.com"],
  "sources": { "crtsh": true, "wayback": true, "hackertarget": true },
  "certs": { "enabled": false, "warnDays": 30, "criticalDays": 7 },
  "watch": { "ledgerDir": "recon-output", "retention": 30 }
}
```

```bash
# run passive recon against an allowlisted root domain
npm run recon -- recon example.com

# write a JSON exposure ledger
npm run recon -- recon example.com --out recon-output/example.json

# summary counts only
npm run recon -- recon example.com --quiet

# also grab TLS certificates from discovered hosts (active handshake)
npm run recon -- recon example.com --certs --out recon-output/example.json

# monitor all allowlisted targets: run, diff vs previous ledger, report drift
# exits 2 if drift or source failures detected (CI-friendly)
npm run recon -- watch --config shadowstack.json

# compare two ledger runs: new/removed assets, cert rotations
npm run recon -- diff recon-output/old.json recon-output/new.json

# export the asset relationship graph (Graphviz DOT or JSON)
npm run recon -- graph recon-output/example.json --out recon-output/example.dot
npm run recon -- graph recon-output/example.json --json --out recon-output/example-graph.json

# ingest HTTP header fingerprints from an existing scan artifact
npm run recon -- ingest scan-headers.json --root-domain example.com --out recon-output/headers.json
```

## Continuous monitoring

A scheduled GitHub Actions workflow (`.github/workflows/watch.yml`) runs `shadowstack watch` daily, restores the ledger history via cache, and fails the run when drift or source failures are detected. Push a `shadowstack.json` with your targets to enable it. Drift is surfaced as a workflow annotation plus a `watch-report` artifact; ledgers are cached between runs so each diff is against the real previous state.

## Authorization

ShadowStack is a defensive attack-surface management tool. Only run it against assets you own or are explicitly authorized to assess. The allowlist in `shadowstack.json` is the enforcement mechanism: `recon` and `watch` refuse domains outside `config.targets`. The default pipeline is passive (certificate transparency logs, public DNS). The `--certs` stage performs live TLS handshakes with discovered hosts; only enable it against assets you are authorized to assess.

## Tests

```bash
npm test
```

The suite is fully offline (mocked TLS sockets, injected fetch, fake clocks) — no network required.

## Roadmap

- [ ] `audit` command — severity-scored checks over ledgers (dangling CNAMEs, wildcard sprawl, orphan IPs)
- [ ] `scan` command — opt-in port scan of authorized assets
- [ ] Cert PEM export (`--certs-dir`)
- [ ] Passive endpoint inventory (harvest paths from wayback data) + active probing (opt-in)
- [ ] Alert integrations (webhook/email) on drift
- [ ] Telemetry ingestion (own-infra netflow/DNS logs) → communication graph
- [ ] Interactive dashboard over accumulated ledgers
