# Qyrion

Qyrion is a private AI and post-quantum cybersecurity project focused on local-first Cryptographic Bills of Materials.

Core mentality:

Have a plan before you need one.

The first prototype is intentionally small:

```powershell
python qyrion.py cbom example.com
```

If `python` is not available on PATH in Codex, use the bundled runtime:

```powershell
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" qyrion.py cbom example.com
```

You can also scan multiple public TLS endpoints:

```powershell
python qyrion.py cbom example.com openai.com cloudflare.com
```

It scans a public TLS endpoint and creates:

- `reports/qyrion-cbom-example.com-443.json`
- `reports/qyrion-cbom-example.com-443.md`

You can turn a CBOM JSON file into a business-friendly evidence pack:

```powershell
python qyrion.py evidence reports/qyrion-cbom-example.com-443.json
```

That creates:

- `evidence/qyrion-evidence-example.com-443.md`

You can compare two CBOM JSON files:

```powershell
python qyrion.py diff reports/qyrion-cbom-example.com-443.json reports/qyrion-cbom-openai.com-443.json
```

That creates:

- `diffs/qyrion-diff-example.com-443-to-openai.com-443.md`

You can evaluate a CBOM against Qyrion's prototype policy rules:

```powershell
python qyrion.py policy reports/qyrion-cbom-example.com-443.json
```

That creates:

- `policy/qyrion-policy-example.com-443.md`

Run the smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke_test.ps1
```

## Current Prototype

Qyrion BlackBox Lite currently reports:

- TLS version
- Cipher suite
- Certificate public key algorithm
- Certificate key size
- Signature algorithm
- Basic quantum-vulnerability status
- Quantum Readiness Score
- Plain-English finding and recommendation
- Trust Receipt showing what was and was not collected
- Evidence Pack generation from a CBOM JSON file
- CBOM diff reports for tracking cryptographic posture changes over time
- Prototype policy reports for governance-style CBOM checks

On Windows, certificate parsing can use the built-in `certutil` command. If OpenSSL is installed, Qyrion will use it automatically.

## Website Prototype

The first landing page is available at:

`website/index.html`

The first education page is available at:

`website/quantum-security-101.html`

It introduces Qyrion's core message:

Have a plan before you need one.

Temporary contact:

`qyrionsecurity@gmail.com`

## Privacy Posture

The prototype only scans public TLS metadata for a hostname you provide.

It does not collect:

- Private keys
- Source code
- Logs
- Customer data
- Internal infrastructure maps
- Secrets

## Important Limits

This is an early planning and prototype tool, not a complete security assessment.

Future versions should add:

- A stronger CBOM schema
- Better TLS/certificate parsing
- Repository and dependency scanning
- CBOM diffing
- Local AI report generation
- Private deployment packaging
