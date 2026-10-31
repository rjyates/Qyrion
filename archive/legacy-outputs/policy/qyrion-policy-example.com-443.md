# Qyrion CBOM Policy Report

## Summary

- Asset: example.com:443
- Outcome: attention_required
- Passed: 2
- Warnings: 2
- Failed: 1

## Plain-English Interpretation

This CBOM has policy failures that should be reviewed as part of the quantum-readiness plan.

## Policy Checks

### QYR-PQC-001: Track quantum-vulnerable public-key cryptography

- Status: fail
- Severity: medium
- Reason: ECC public-key cryptography should be tracked for post-quantum migration.
- Recommendation: Keep this asset in the CBOM and include it in post-quantum migration planning.

### QYR-PQC-002: Record confidentiality lifetime

- Status: warn
- Severity: medium
- Reason: Data confidentiality lifetime is unknown, so harvest-now-decrypt-later urgency cannot be ranked.
- Recommendation: Ask the asset owner how long protected data must remain confidential.

### QYR-PQC-003: Review internet-exposed cryptography

- Status: warn
- Severity: low
- Reason: This endpoint is internet-exposed, so its public cryptographic posture is externally visible.
- Recommendation: Prioritize ownership, monitoring, and renewal tracking for internet-exposed assets.

### QYR-TLS-001: Use modern TLS posture

- Status: pass
- Severity: info
- Reason: TLS 1.3 is present. This is modern classical TLS, though not automatically post-quantum safe.
- Recommendation: Track TLS version as part of the broader post-quantum readiness roadmap.

### QYR-GOV-001: Maintain readiness scoring evidence

- Status: pass
- Severity: low
- Reason: Readiness score factors are present and explain how the score was produced.
- Recommendation: Keep score factors in generated CBOMs so leadership can understand risk changes.

## Limits

This policy report applies Qyrion's current prototype rules to one CBOM file. It is not a full compliance attestation, legal opinion, or production security certification.