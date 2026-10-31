# Qyrion CBOM Diff Report

## Summary

- Before Asset: example.com:443
- After Asset: openai.com:443
- Outcome: different_assets
- Score Change: +15
- Before Score: 40
- After Score: 55

## Plain-English Interpretation

These CBOMs are for different assets. Treat this as a comparison, not proof that one asset improved over time.

## Detected Changes

- Asset: `example.com:443` -> `openai.com:443`
- Quantum Readiness Score: `40` -> `55`
- Signature Algorithm: `sha256ECDSA` -> `ecdsa-with-SHA384`
- Certificate Valid Until: `Aug 29 21:41:26 2026 GMT` -> `Aug 26 19:33:25 2026 GMT`

## Recommended Next Steps

1. Compare assets only when the business goal is side-by-side prioritization.
2. For historical tracking, compare two CBOMs from the same asset at different times.
3. Use the detected changes to decide which asset needs more planning context.

## Limits

This diff compares Qyrion CBOM metadata fields. It is not a full security audit, compliance attestation, or proof that production cryptography is safe.