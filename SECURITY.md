# Security Policy

Qyrion is an early portfolio prototype for local-first CBOM generation and post-quantum readiness planning.

## Reporting Security Issues

Please report security concerns privately to:

```text
qyrionsecurity@gmail.com
```

Do not open a public issue for suspected vulnerabilities that could expose users, systems, or sensitive details.

## Scope

In scope:

- Issues in the Qyrion CLI prototype
- Issues in generated report handling
- Website behavior that contradicts the stated privacy posture
- Accidental collection or exposure of data beyond public TLS metadata

Out of scope:

- Requests to scan systems you do not own or have permission to test
- Social engineering
- Denial-of-service testing
- Claims that require invasive scanning

## Privacy Posture

The current prototype:

- scans public TLS certificate metadata for hostnames provided by the user
- generates local reports
- does not collect private keys, source code, logs, customer data, secrets, or internal infrastructure maps
- does not use external AI or third-party APIs

## Responsible Use

Use Qyrion only on public endpoints you own, manage, or have permission to assess.
