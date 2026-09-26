# ShadowStack

Passive-first attack surface recon engine. ShadowStack discovers what is *already exposed* about assets you are authorized to assess — without touching the target directly.

## Vision

ShadowStack maps the "stack shadow": the hidden infrastructure topology behind your domains that never made it into your asset inventory. It is built as a pipeline of small, auditable stages:

```
sources → resolve → correlate → report
```

- **sources** — pluggable passive intel adapters (certificate transparency via crt.sh, more to come). No active scanning, no probing.
- **resolve** — quiet DNS resolution through public resolvers, with bounded concurrency.
- **correlate** — clusters assets that share infrastructure (e.g. domains on the same IP), revealing hidden topology.
- **report** — an exposure ledger: every finding carries source provenance, timestamp, and confidence. Auditable, re-runnable, diffable over time.

## Install & build

```bash
npm install
npm run build
```

## Usage

```bash
# run passive recon against a root domain you are authorized to assess
npm run recon -- recon example.com

# write a JSON exposure ledger
npm run recon -- recon example.com --out recon-output/example.json

# summary counts only
npm run recon -- recon example.com --quiet
```

## Tests

```bash
npm test
```

## Authorization

ShadowStack is a defensive attack-surface management tool. Only run it against assets you own or are explicitly authorized to assess. All collection is passive (certificate transparency logs, public DNS); the engine never sends traffic to discovered assets beyond standard DNS resolution.

## Roadmap

- [ ] More passive sources (web archive metadata, passive DNS)
- [ ] Ledger diffing — surface exposure drift between runs
- [ ] Correlation graph export (asset relationship visualization)
- [ ] HTTP header fingerprint ingestion from existing scan artifacts
