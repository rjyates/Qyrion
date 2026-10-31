# Qyrion Evidence Pack

## Executive Summary

Qyrion generated a local Cryptographic Bill of Materials for `openai.com:443`. The asset received a Quantum Readiness Score of 55 with highest severity `medium`.

This asset uses public-key cryptography that should be tracked for post-quantum migration. No private data was required to generate this CBOM.

This evidence pack is intended to help leadership, security, engineering, and compliance teams make a plan before quantum security becomes urgent.

## CBOM Summary

- Asset: openai.com:443
- Asset Type: public_tls_endpoint
- TLS Version: TLSv1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
- Cryptographic Components: 1
- Quantum-Vulnerable Components: 1

## Primary Cryptographic Component

- Component Type: certificate
- Algorithm Family: ECC
- Algorithm: id-ecPublicKey
- Key Size: 256
- Signature Algorithm: ecdsa-with-SHA384
- Quantum Vulnerable: True
- Valid Until: Aug 26 19:33:25 2026 GMT

## What This Means

- ECC certificate is vulnerable to future quantum attacks: This endpoint uses ECC-based public-key cryptography. RSA, ECC, and DSA are considered vulnerable to a future cryptographically relevant quantum computer.
- Recommended action: Track this asset in a CBOM, monitor ecosystem support for hybrid or post-quantum TLS, and prioritize migration based on data sensitivity and confidentiality lifetime.

## Recommended Next Steps

1. Keep this asset in a cryptographic inventory so it can be tracked as post-quantum standards and vendor support mature.
2. Assign an owner for this asset so future certificate, TLS, and migration decisions are not orphaned.
3. Document the expected confidentiality lifetime for data protected by this endpoint.
4. Prioritize this asset if it protects sensitive data that must remain confidential for years.
5. Monitor vendor and platform support for hybrid or post-quantum TLS options before making production changes.
6. Create a migration note for leadership explaining that the right next step is planning and tracking, not panic replacement.

## Trust Receipt

This CBOM was generated locally from public TLS certificate metadata. No private keys, source code, logs, customer data, secrets, or internal infrastructure maps were collected or sent to external AI.

Data sources:

- public TLS handshake metadata
- public X.509 certificate metadata

Not collected:

- private keys
- source code
- logs
- customer data
- secrets
- internal infrastructure maps

External AI Used: False
Sensitive Data Uploaded: False

## Limits

This evidence pack is generated from the CBOM provided to the tool. It is not a full security audit, penetration test, compliance attestation, or legal opinion.