# Qyrion CBOM Report

Generated: 2026-06-07T13:36:55Z
Asset: example.com:443

## Summary

- Quantum Readiness Score: 40
- Highest Severity: medium
- Quantum-Vulnerable Components: 1
- Plain English: This asset uses public-key cryptography that should be tracked for post-quantum migration. No private data was required to generate this CBOM.

## Readiness Score Factors

- public_key_algorithm (-45): ECC public-key cryptography should be tracked for post-quantum migration.
- internet_exposed (-10): The endpoint is publicly reachable, so cryptographic posture is externally visible.
- tls_version (0): TLS 1.3 is modern classical TLS, but it is not automatically post-quantum safe.
- data_lifetime_unknown (-5): The confidentiality lifetime is unknown, so harvest-now-decrypt-later urgency cannot be ranked yet.

## Cryptographic Component

- Type: certificate
- Algorithm Family: ECC
- Algorithm: id-ecPublicKey
- Key Size: 256
- Signature Algorithm: sha256ECDSA
- Quantum Vulnerable: True
- Valid Until: Aug 29 21:41:26 2026 GMT

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