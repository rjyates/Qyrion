# Qyrion Invention Log

Use this log to capture technical ideas before they are publicly disclosed.

This does not replace legal advice or a formal patent process. It creates a dated internal record of what Qyrion is exploring.

## 2026-06-06

### Private AI-Generated CBOMs For Post-Quantum Readiness

Concept:

Qyrion generates Cryptographic Bills of Materials locally or inside a customer-controlled environment, then uses private AI workflows to summarize quantum risk without sending sensitive data to external AI systems.

Potentially novel areas to investigate:

- Local-first CBOM generation for post-quantum migration planning.
- Sanitized cryptographic metadata pipelines for AI analysis.
- Quantum-risk scoring based on cryptographic algorithm, asset exposure, data sensitivity, and data lifetime.
- Air-gapped executive and technical report generation.
- CBOM diffing to show how cryptographic risk changes between releases.

Current prototype:

- `qyrion.py cbom example.com`
- Generates a JSON CBOM and Markdown report from public TLS metadata.
- Does not collect private keys, source code, logs, secrets, or customer data.

Next technical idea:

Define a proprietary Qyrion risk-scoring model while keeping the basic CBOM format understandable and portable.
