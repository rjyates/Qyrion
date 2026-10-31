# Qyrion CBOM Report

Generated: 2026-06-06T21:38:06Z
Asset: openai.com:443

## Summary

- Quantum Readiness Score: 55
- Highest Severity: medium
- Quantum-Vulnerable Components: 1
- Plain English: This asset uses public-key cryptography that should be tracked for post-quantum migration. No private data was required to generate this CBOM.

## Cryptographic Component

- Type: certificate
- Algorithm Family: ECC
- Algorithm: id-ecPublicKey
- Key Size: 256
- Signature Algorithm: ecdsa-with-SHA384
- Quantum Vulnerable: True
- Valid Until: Aug 26 19:33:25 2026 GMT

## Protocol

- TLS Version: TLSv1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384

## Findings

### ECC certificate is vulnerable to future quantum attacks

- Severity: medium
- Confidence: high
- Description: This endpoint uses ECC-based public-key cryptography. RSA, ECC, and DSA are considered vulnerable to a future cryptographically relevant quantum computer.
- Recommendation: Track this asset in a CBOM, monitor ecosystem support for hybrid or post-quantum TLS, and prioritize migration based on data sensitivity and confidentiality lifetime.


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