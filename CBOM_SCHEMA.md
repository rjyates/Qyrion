# Qyrion CBOM Schema Draft

## Purpose

The Qyrion CBOM, or Cryptographic Bill of Materials, describes the cryptography an asset depends on.

The first version should be small enough to generate from a public domain scan, but structured enough to expand later into repositories, cloud assets, vendors, APIs, and internal systems.

## Design Rules

- Do not require secrets.
- Do not store private keys.
- Do not store sensitive payload data.
- Prefer metadata over raw data.
- Make every finding traceable to an asset.
- Make quantum risk explainable in plain English.
- Keep the schema versioned.

## Top-Level Fields

```json
{
  "schema_version": "0.1.0",
  "generated_at": "2026-06-06T00:00:00Z",
  "generator": {
    "name": "qyrion",
    "version": "0.1.0"
  },
  "organization": {
    "name": null,
    "environment": "unknown"
  },
  "assets": [],
  "findings": [],
  "summary": {}
}
```

## Asset

An asset is anything that uses, exposes, stores, signs, encrypts, or depends on cryptography.

First supported asset type:

- `public_tls_endpoint`

Future asset types:

- `source_repository`
- `software_dependency`
- `container_image`
- `cloud_kms_key`
- `api_endpoint`
- `database`
- `vendor_service`
- `code_signing_certificate`
- `document_signing_certificate`

Example:

```json
{
  "asset_id": "asset_001",
  "asset_type": "public_tls_endpoint",
  "name": "example.com",
  "location": {
    "hostname": "example.com",
    "port": 443
  },
  "exposure": {
    "internet_exposed": true,
    "data_sensitivity": "unknown",
    "data_lifetime": "unknown"
  },
  "crypto": []
}
```

## Crypto Component

A crypto component describes a specific cryptographic dependency found on an asset.

Example:

```json
{
  "component_id": "crypto_001",
  "component_type": "certificate",
  "algorithm_family": "RSA",
  "algorithm": "RSA",
  "key_size_bits": 2048,
  "signature_algorithm": "sha256WithRSAEncryption",
  "quantum_vulnerable": true,
  "standards_context": {
    "classical_status": "widely_used",
    "post_quantum_status": "not_quantum_safe"
  }
}
```

Component types:

- `certificate`
- `key_exchange`
- `signature`
- `encryption`
- `library`
- `protocol`
- `hash`
- `unknown`

## Finding

A finding explains why a crypto component matters.

Example:

```json
{
  "finding_id": "finding_001",
  "asset_id": "asset_001",
  "component_id": "crypto_001",
  "severity": "medium",
  "category": "quantum_vulnerable_public_key_crypto",
  "title": "RSA certificate is vulnerable to future quantum attacks",
  "description": "This endpoint uses RSA-based public-key cryptography. RSA is considered vulnerable to a future cryptographically relevant quantum computer.",
  "recommendation": "Track this asset for post-quantum migration planning and evaluate hybrid or post-quantum alternatives as ecosystem support matures.",
  "confidence": "high"
}
```

Severity values:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Confidence values:

- `low`
- `medium`
- `high`

## Summary

The summary gives a small executive-level view.

Example:

```json
{
  "asset_count": 1,
  "crypto_component_count": 1,
  "quantum_vulnerable_component_count": 1,
  "highest_severity": "medium",
  "quantum_readiness_score": 42,
  "plain_english": "This asset uses public-key cryptography that should be tracked for post-quantum migration. No private data was required to generate this CBOM."
}
```

## First Scanner Target

The first scanner should support:

```text
qyrion cbom example.com
```

It should produce:

- `qyrion-cbom-example.com.json`
- `qyrion-cbom-example.com.md`

## Open Questions

- Should the CBOM format become public later, or should only a limited version be public?
- Should the schema align with CycloneDX CBOM conventions if useful?
- Should Qyrion create its own CBOM extension for post-quantum readiness?
- Should scoring be open and explainable, or private and proprietary?

## Current Recommendation

Keep the basic CBOM structure understandable and portable.

Keep the advanced quantum-risk scoring, prioritization logic, and private AI workflow proprietary until there is a clear reason to open any part of it.
