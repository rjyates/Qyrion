#!/usr/bin/env python3
"""Qyrion BlackBox Lite: local CBOM generator for public TLS endpoints."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "0.1.0"
GENERATOR_VERSION = "0.1.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def run_openssl_x509(der_cert: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        temp_file.write(der_cert)

    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", str(temp_path), "-noout", "-text"],
            capture_output=True,
            check=True,
        )
        return result.stdout.decode("utf-8", errors="replace")
    finally:
        temp_path.unlink(missing_ok=True)


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else None


def parse_certificate_text(cert_text: str) -> dict[str, Any]:
    public_key_algorithm = first_match(r"Public Key Algorithm:\s*(.+)", cert_text)
    public_key_bits_raw = first_match(r"Public-Key:\s*\((\d+) bit\)", cert_text)
    signature_algorithm = first_match(r"Signature Algorithm:\s*(.+)", cert_text)

    algorithm_family = "unknown"
    if public_key_algorithm:
        lower = public_key_algorithm.lower()
        if "rsa" in lower:
            algorithm_family = "RSA"
        elif "ec" in lower or "id-ecpublickey" in lower:
            algorithm_family = "ECC"
        elif "dsa" in lower:
            algorithm_family = "DSA"

    return {
        "public_key_algorithm": public_key_algorithm or "unknown",
        "algorithm_family": algorithm_family,
        "key_size_bits": int(public_key_bits_raw) if public_key_bits_raw else None,
        "signature_algorithm": signature_algorithm or "unknown",
    }


def get_tls_endpoint(hostname: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            cert_der = tls_socket.getpeercert(binary_form=True)
            cert_info = tls_socket.getpeercert()
            tls_version = tls_socket.version()
            cipher = tls_socket.cipher()

    if not cert_der:
        raise RuntimeError("No peer certificate returned by endpoint.")

    cert_text = run_openssl_x509(cert_der)
    parsed = parse_certificate_text(cert_text)

    return {
        "hostname": hostname,
        "port": port,
        "tls_version": tls_version,
        "cipher_suite": cipher[0] if cipher else "unknown",
        "certificate": {
            "subject": cert_info.get("subject"),
            "issuer": cert_info.get("issuer"),
            "not_before": cert_info.get("notBefore"),
            "not_after": cert_info.get("notAfter"),
            "subject_alt_names": cert_info.get("subjectAltName", []),
            **parsed,
        },
    }


def is_quantum_vulnerable(algorithm_family: str) -> bool:
    return algorithm_family in {"RSA", "ECC", "DSA"}


def severity_for_endpoint(quantum_vulnerable: bool, internet_exposed: bool = True) -> str:
    if quantum_vulnerable and internet_exposed:
        return "medium"
    if quantum_vulnerable:
        return "low"
    return "info"


def build_cbom(endpoint: dict[str, Any]) -> dict[str, Any]:
    hostname = endpoint["hostname"]
    port = endpoint["port"]
    cert = endpoint["certificate"]
    algorithm_family = cert["algorithm_family"]
    quantum_vulnerable = is_quantum_vulnerable(algorithm_family)
    severity = severity_for_endpoint(quantum_vulnerable)

    asset_id = "asset_001"
    component_id = "crypto_001"
    finding_id = "finding_001"

    asset = {
        "asset_id": asset_id,
        "asset_type": "public_tls_endpoint",
        "name": f"{hostname}:{port}",
        "location": {
            "hostname": hostname,
            "port": port,
        },
        "exposure": {
            "internet_exposed": True,
            "data_sensitivity": "unknown",
            "data_lifetime": "unknown",
        },
        "protocol": {
            "tls_version": endpoint["tls_version"],
            "cipher_suite": endpoint["cipher_suite"],
        },
        "crypto": [
            {
                "component_id": component_id,
                "component_type": "certificate",
                "algorithm_family": algorithm_family,
                "algorithm": cert["public_key_algorithm"],
                "key_size_bits": cert["key_size_bits"],
                "signature_algorithm": cert["signature_algorithm"],
                "validity": {
                    "not_before": cert["not_before"],
                    "not_after": cert["not_after"],
                },
                "quantum_vulnerable": quantum_vulnerable,
                "standards_context": {
                    "classical_status": "widely_used" if quantum_vulnerable else "unknown",
                    "post_quantum_status": "not_quantum_safe" if quantum_vulnerable else "unknown",
                },
            }
        ],
    }

    findings = []
    if quantum_vulnerable:
        findings.append(
            {
                "finding_id": finding_id,
                "asset_id": asset_id,
                "component_id": component_id,
                "severity": severity,
                "category": "quantum_vulnerable_public_key_crypto",
                "title": f"{algorithm_family} certificate is vulnerable to future quantum attacks",
                "description": (
                    f"This endpoint uses {algorithm_family}-based public-key cryptography. "
                    "RSA, ECC, and DSA are considered vulnerable to a future cryptographically "
                    "relevant quantum computer."
                ),
                "recommendation": (
                    "Track this asset in a CBOM, monitor ecosystem support for hybrid or "
                    "post-quantum TLS, and prioritize migration based on data sensitivity "
                    "and confidentiality lifetime."
                ),
                "confidence": "high",
            }
        )

    score = 100
    if quantum_vulnerable:
        score -= 45

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "generator": {
            "name": "qyrion",
            "version": GENERATOR_VERSION,
        },
        "organization": {
            "name": None,
            "environment": "unknown",
        },
        "assets": [asset],
        "findings": findings,
        "summary": {
            "asset_count": 1,
            "crypto_component_count": 1,
            "quantum_vulnerable_component_count": 1 if quantum_vulnerable else 0,
            "highest_severity": severity,
            "quantum_readiness_score": score,
            "plain_english": (
                "This asset uses public-key cryptography that should be tracked for "
                "post-quantum migration. No private data was required to generate this CBOM."
                if quantum_vulnerable
                else "No known quantum-vulnerable public-key cryptography was identified by this scan."
            ),
        },
        "trust_receipt": {
            "data_sources": [
                "public TLS handshake metadata",
                "public X.509 certificate metadata",
            ],
            "not_collected": [
                "private keys",
                "source code",
                "logs",
                "customer data",
                "secrets",
                "internal infrastructure maps",
            ],
            "external_ai_used": False,
            "sensitive_data_uploaded": False,
            "plain_english": (
                "This CBOM was generated locally from public TLS certificate metadata. "
                "No private keys, source code, logs, customer data, secrets, or internal "
                "infrastructure maps were collected or sent to external AI."
            ),
        },
    }


def write_markdown_report(cbom: dict[str, Any], path: Path) -> None:
    asset = cbom["assets"][0]
    crypto = asset["crypto"][0]
    summary = cbom["summary"]
    findings = cbom["findings"]
    trust_receipt = cbom["trust_receipt"]

    lines = [
        "# Qyrion CBOM Report",
        "",
        f"Generated: {cbom['generated_at']}",
        f"Asset: {asset['name']}",
        "",
        "## Summary",
        "",
        f"- Quantum Readiness Score: {summary['quantum_readiness_score']}",
        f"- Highest Severity: {summary['highest_severity']}",
        f"- Quantum-Vulnerable Components: {summary['quantum_vulnerable_component_count']}",
        f"- Plain English: {summary['plain_english']}",
        "",
        "## Cryptographic Component",
        "",
        f"- Type: {crypto['component_type']}",
        f"- Algorithm Family: {crypto['algorithm_family']}",
        f"- Algorithm: {crypto['algorithm']}",
        f"- Key Size: {crypto['key_size_bits'] or 'unknown'}",
        f"- Signature Algorithm: {crypto['signature_algorithm']}",
        f"- Quantum Vulnerable: {crypto['quantum_vulnerable']}",
        f"- Valid Until: {crypto['validity']['not_after']}",
        "",
        "## Protocol",
        "",
        f"- TLS Version: {asset['protocol']['tls_version']}",
        f"- Cipher Suite: {asset['protocol']['cipher_suite']}",
        "",
        "## Findings",
        "",
    ]

    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding['title']}",
                    "",
                    f"- Severity: {finding['severity']}",
                    f"- Confidence: {finding['confidence']}",
                    f"- Description: {finding['description']}",
                    f"- Recommendation: {finding['recommendation']}",
                    "",
                ]
            )
    else:
        lines.append("No findings generated by this scan.")

    lines.extend(
        [
            "",
            "## Trust Receipt",
            "",
            trust_receipt["plain_english"],
            "",
            "Data sources:",
            "",
            *[f"- {source}" for source in trust_receipt["data_sources"]],
            "",
            "Not collected:",
            "",
            *[f"- {item}" for item in trust_receipt["not_collected"]],
            "",
            f"External AI Used: {trust_receipt['external_ai_used']}",
            f"Sensitive Data Uploaded: {trust_receipt['sensitive_data_uploaded']}",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")


def scan_hostname(hostname: str, port: int, output_dir: Path) -> dict[str, Any]:
    endpoint = get_tls_endpoint(hostname, port)
    cbom = build_cbom(endpoint)

    output_dir.mkdir(parents=True, exist_ok=True)

    base = safe_filename(f"{hostname}-{port}")
    json_path = output_dir / f"qyrion-cbom-{base}.json"
    markdown_path = output_dir / f"qyrion-cbom-{base}.md"

    json_path.write_text(json.dumps(cbom, indent=2), encoding="utf-8")
    write_markdown_report(cbom, markdown_path)

    return {
        "hostname": hostname,
        "json_path": json_path,
        "markdown_path": markdown_path,
        "score": cbom["summary"]["quantum_readiness_score"],
        "highest_severity": cbom["summary"]["highest_severity"],
    }


def cbom_command(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    results = []
    failures = []

    for hostname in args.hostnames:
        try:
            results.append(scan_hostname(hostname, args.port, output_dir))
        except Exception as exc:
            failures.append({"hostname": hostname, "error": str(exc)})

    for result in results:
        print(f"{result['hostname']}:")
        print(f"  CBOM JSON: {result['json_path']}")
        print(f"  CBOM report: {result['markdown_path']}")
        print(f"  Quantum Readiness Score: {result['score']}")
        print(f"  Highest Severity: {result['highest_severity']}")

    if failures:
        print("\nScan failures:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure['hostname']}: {failure['error']}", file=sys.stderr)

    return 1 if failures and not results else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qyrion local CBOM scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cbom_parser = subparsers.add_parser("cbom", help="Generate a CBOM for a public TLS endpoint")
    cbom_parser.add_argument("hostnames", nargs="+", help="Hostnames to scan, such as example.com openai.com")
    cbom_parser.add_argument("--port", type=int, default=443, help="TLS port to scan")
    cbom_parser.add_argument("--output-dir", default="reports", help="Directory for generated reports")
    cbom_parser.set_defaults(func=cbom_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"qyrion error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
