# Qyrion — agent instructions

Cost-free, local-first portfolio prototype for post-quantum cybersecurity planning: generates Cryptographic Bills of Materials (CBOMs) from public TLS certificate metadata, then evidence packs, policy reports and CBOM diffs. Start with `START_HERE.md`; architecture in `docs/architecture.md`; schema in `CBOM_SCHEMA.md`; security policy in `SECURITY.md`.

## Commands
- CLI: `python qyrion.py` (see README for subcommands).
- Smoke test (run before every commit): `powershell -File scripts/smoke_test.ps1`

## Rules
- Cost-free by design: no paid APIs, paid AI models, databases or hosting.
- Only scan public endpoints the user names; never scan networks or hosts without explicit approval.
- Reports must state what data was used and collected (trust receipts). Don't overstate security guarantees; this is a prototype, not certified tooling.
- Static website in `website/` stays framework-free.

## Working conventions
- Branch per change; keep `CBOM_SCHEMA.md` and samples in sync with code changes.
- Public repo: no secrets or personal data.
