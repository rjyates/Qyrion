# Verification — October 22, 2026

[Overview](../README.md) · [Architecture](architecture.md)

Using Python and the bundled `samples/sample-cbom-example.com-443.json`:

- CLI help listed `cbom`, `evidence`, `diff`, and `policy`.
- `evidence` generated a Markdown evidence pack.
- `policy` generated a Markdown policy report.
- `diff` generated a report comparing the sample with itself.

Commands used the `--output` option to write disposable local verification artifacts outside the repository. No public endpoint, internal network, paid API, or AI service was contacted.

Not verified: a fresh TLS collection, certificate parsing across platforms, policy/score correctness, post-quantum readiness, or production suitability. This check validates local report-generation execution, not the security conclusions of a report.
