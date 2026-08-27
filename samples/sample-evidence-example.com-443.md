# Qyrion Evidence Pack

## Executive Summary

Qyrion generated a local Cryptographic Bill of Materials for `example.com:443`. The asset received a Quantum Readiness Score of 40 with highest severity `medium`.

This asset uses public-key cryptography that should be tracked for post-quantum migration. No private data was required to generate this CBOM.

This evidence pack helps leadership, security, engineering, and compliance teams make a plan before quantum security becomes urgent.

## CBOM Summary

- Asset: example.com:443
- Asset Type: public_tls_endpoint
- TLS Version: TLSv1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
- Cryptographic Components: 1
- Quantum-Vulnerable Components: 1

## Recommended Next Steps

1. Keep this asset in a cryptographic inventory.
2. Assign an owner for future certificate, TLS, and migration decisions.
3. Document the expected confidentiality lifetime for data protected by this endpoint.
4. Monitor platform support for hybrid or post-quantum TLS.

## Trust Receipt

This CBOM was generated locally from public TLS certificate metadata. No private keys, source code, logs, customer data, secrets, or internal infrastructure maps were collected or sent to external AI.
