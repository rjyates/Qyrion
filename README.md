# Qyrion

Qyrion is a cost-free portfolio project for private, local-first post-quantum cybersecurity planning.

It generates Cryptographic Bills of Materials, or CBOMs, from public TLS certificate metadata, then turns those findings into plain-English reports, evidence packs, policy checks, and change-history comparisons.

Core idea:

**Have a plan before you need one.**

## Why This Project Exists

Post-quantum cybersecurity can feel abstract and intimidating. Qyrion makes the first step practical: find where cryptography is being used, explain what may become vulnerable, and create a readiness plan without uploading sensitive data.

The current prototype focuses on public TLS endpoints. It is intentionally small, transparent, and free to run locally.

## Features

- **CBOM scanner:** Generates JSON and Markdown CBOM reports from public TLS endpoints.
- **Evidence packs:** Converts CBOMs into leadership-friendly planning artifacts.
- **CBOM diffing:** Compares two CBOMs and explains what changed.
- **Policy reports:** Applies prototype governance checks to a CBOM.
- **Quantum Security 101:** Static education page for plain-English learning.
- **Trust receipts:** States what data was used, what was not collected, and whether external AI was used.
- **Smoke test:** Verifies the CLI and website files.

## Cost-Free Stack

- Python CLI
- Static HTML/CSS/JavaScript website
- No paid APIs
- No paid AI models
- No paid database
- No paid hosting required
- GitHub Pages-compatible frontend

## Requirements

- Python 3.10+
- OpenSSL or Windows `certutil` for certificate parsing

No Python package installation is required.

## Quick Start

Generate a CBOM:

```powershell
python qyrion.py cbom example.com
```

Scan multiple public TLS endpoints:

```powershell
python qyrion.py cbom example.com openai.com cloudflare.com
```

Generate an Evidence Pack from a CBOM:

```powershell
python qyrion.py evidence reports/qyrion-cbom-example.com-443.json
```

Compare two CBOM files:

```powershell
python qyrion.py diff reports/qyrion-cbom-example.com-443.json reports/qyrion-cbom-openai.com-443.json
```

Evaluate a CBOM against prototype policy rules:

```powershell
python qyrion.py policy reports/qyrion-cbom-example.com-443.json
```

Run the smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke_test.ps1
```

## Website

Open the static website locally:

```text
website/index.html
```

Education page:

```text
website/quantum-security-101.html
```

The website CBOM explainer is educational only. It does not perform a live scan, contact the entered domain, send the domain anywhere, or use external AI.

## Sample Outputs

Safe sample files are included in `samples/`:

- `samples/sample-cbom-example.com-443.json`
- `samples/sample-evidence-example.com-443.md`
- `samples/sample-policy-example.com-443.md`

Generated local outputs are ignored by Git:

- `reports/`
- `evidence/`
- `diffs/`
- `policy/`

## Project Structure

```text
qyrion.py                         CLI prototype
website/index.html                Landing page
website/quantum-security-101.html Education page
website/styles.css                Site styles
website/script.js                 Educational CBOM preview form
scripts/smoke_test.ps1            Local verification script
samples/                          Safe sample outputs
CBOM_SCHEMA.md                    Draft CBOM schema
START_HERE.md                     Product plan and roadmap
BUSINESS_STRENGTHENERS.md         Business strategy ideas
EDUCATION_STRATEGY.md             Education/content strategy
VIDEO_SCRIPTS.md                  Draft explainer video scripts
PROTECTION_AND_NEXT_STEPS.md      Founder protection checklist
INVENTION_LOG.md                  Internal idea log
```

## Privacy Posture

The current prototype only scans public TLS metadata for hostnames you provide.

It does not collect:

- private keys
- source code
- logs
- customer data
- internal infrastructure maps
- secrets

It does not use external AI or third-party APIs.

## Portfolio Skills Demonstrated

- Cybersecurity product thinking
- Python CLI development
- JSON report generation
- Static frontend design
- Privacy-aware technical writing
- Git feature branching
- Technical-to-business communication
- Early-stage product strategy

## Limits

Qyrion is an early prototype and portfolio project.

It is not:

- a full security audit
- a penetration test
- a compliance attestation
- legal advice
- cryptographic engineering advice
- proof that any production system is secure or quantum-safe

Post-quantum cybersecurity is an evolving field. Standards, vendor support, migration practices, and risk models may change over time.

## Roadmap Ideas

- Stronger CBOM schema
- CycloneDX-compatible export
- Repository and dependency scanning
- Local-only AI summaries
- Private deployment packaging
- GitHub Pages publishing

## Contact

Temporary project contact:

```text
qyrionsecurity@gmail.com
```
