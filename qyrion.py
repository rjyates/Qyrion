#!/usr/bin/env python3
"""Qyrion BlackBox Lite: local CBOM generator for public TLS endpoints."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
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


def run_certificate_dump(der_cert: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as temp_file:
        temp_path = Path(temp_file.name)
        temp_file.write(der_cert)

    try:
        openssl = shutil.which("openssl")
        if openssl:
            result = subprocess.run(
                [openssl, "x509", "-inform", "DER", "-in", str(temp_path), "-noout", "-text"],
                capture_output=True,
                check=True,
            )
            return result.stdout.decode("utf-8", errors="replace")

        certutil = shutil.which("certutil")
        if certutil:
            result = subprocess.run(
                [certutil, "-dump", str(temp_path)],
                capture_output=True,
                check=True,
            )
            return result.stdout.decode("utf-8", errors="replace")

        raise RuntimeError("Qyrion needs either OpenSSL or Windows certutil to parse certificate metadata.")
    finally:
        temp_path.unlink(missing_ok=True)


def run_openssl_x509(der_cert: bytes) -> str:
    return run_certificate_dump(der_cert)


def normalize_signature_algorithm(raw_value: str | None) -> str | None:
    if not raw_value:
        return None

    value = raw_value.strip()
    if " " in value:
        return value.rsplit(" ", 1)[-1]
    return value


def certutil_public_key_algorithm(cert_text: str) -> str | None:
    object_id = first_match(
        r"Public Key Algorithm:[^\S\r\n]*\r?\n[^\S\r\n]*Algorithm ObjectId:[^\S\r\n]*[0-9.]+[^\S\r\n]+(.+)",
        cert_text,
    )
    if object_id:
        value = object_id.strip()
        if "ECC" in value:
            return "id-ecPublicKey"
        if "RSA" in value:
            return "rsaEncryption"
        return value

    return first_match(r"Public Key Algorithm:[^\S\r\n]*(.+)", cert_text)


def certutil_key_size(cert_text: str) -> str | None:
    return first_match(r"Public Key Length:[^\S\r\n]*(\d+)[^\S\r\n]*bits?", cert_text)


def certutil_signature_algorithm(cert_text: str) -> str | None:
    raw_value = first_match(
        r"Signature Algorithm:[^\S\r\n]*\r?\n[^\S\r\n]*Algorithm ObjectId:[^\S\r\n]*[0-9.]+[^\S\r\n]+(.+)",
        cert_text,
    )
    return normalize_signature_algorithm(raw_value)


def parse_certificate_text(cert_text: str) -> dict[str, Any]:
    public_key_algorithm = first_match(r"Public Key Algorithm:[^\S\r\n]*(.+)", cert_text)
    public_key_bits_raw = first_match(r"Public-Key:[^\S\r\n]*\((\d+) bit\)", cert_text)
    signature_algorithm = first_match(r"Signature Algorithm:[^\S\r\n]*(.+)", cert_text)

    if not public_key_algorithm:
        public_key_algorithm = certutil_public_key_algorithm(cert_text)
    if not public_key_bits_raw:
        public_key_bits_raw = certutil_key_size(cert_text)
    if not signature_algorithm:
        signature_algorithm = certutil_signature_algorithm(cert_text)

    signature_algorithm = normalize_signature_algorithm(signature_algorithm)

    algorithm_family = "unknown"
    if public_key_algorithm:
        lower = public_key_algorithm.lower()
        if "rsa" in lower:
            algorithm_family = "RSA"
        elif "ec" in lower or "ecc" in lower or "id-ecpublickey" in lower:
            algorithm_family = "ECC"
        elif "dsa" in lower:
            algorithm_family = "DSA"

    return {
        "public_key_algorithm": public_key_algorithm or "unknown",
        "algorithm_family": algorithm_family,
        "key_size_bits": int(public_key_bits_raw) if public_key_bits_raw else None,
        "signature_algorithm": signature_algorithm or "unknown",
    }


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else None


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


def calculate_readiness_score(asset: dict[str, Any], crypto: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    score = 100
    factors = []

    if crypto["quantum_vulnerable"]:
        score -= 45
        factors.append(
            {
                "factor": "public_key_algorithm",
                "impact": -45,
                "reason": f"{crypto['algorithm_family']} public-key cryptography should be tracked for post-quantum migration.",
            }
        )

    if asset["exposure"]["internet_exposed"]:
        score -= 10
        factors.append(
            {
                "factor": "internet_exposed",
                "impact": -10,
                "reason": "The endpoint is publicly reachable, so cryptographic posture is externally visible.",
            }
        )

    tls_version = asset["protocol"]["tls_version"] or "unknown"
    if tls_version == "TLSv1.3":
        factors.append(
            {
                "factor": "tls_version",
                "impact": 0,
                "reason": "TLS 1.3 is modern classical TLS, but it is not automatically post-quantum safe.",
            }
        )
    else:
        score -= 10
        factors.append(
            {
                "factor": "tls_version",
                "impact": -10,
                "reason": f"{tls_version} should be reviewed as part of a broader TLS modernization plan.",
            }
        )

    if asset["exposure"]["data_lifetime"] == "unknown":
        score -= 5
        factors.append(
            {
                "factor": "data_lifetime_unknown",
                "impact": -5,
                "reason": "The confidentiality lifetime is unknown, so harvest-now-decrypt-later urgency cannot be ranked yet.",
            }
        )

    return max(score, 0), factors


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
    score, score_factors = calculate_readiness_score(asset, asset["crypto"][0])

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
            "readiness_score_factors": score_factors,
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
        "## Readiness Score Factors",
        "",
        *[
            f"- {factor['factor']} ({factor['impact']}): {factor['reason']}"
            for factor in summary.get("readiness_score_factors", [])
        ],
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


def first_asset(cbom: dict[str, Any]) -> dict[str, Any]:
    assets = cbom.get("assets", [])
    if not assets:
        raise ValueError("CBOM does not contain any assets.")
    return assets[0]


def first_crypto(asset: dict[str, Any]) -> dict[str, Any]:
    crypto_components = asset.get("crypto", [])
    if not crypto_components:
        raise ValueError("CBOM asset does not contain any crypto components.")
    return crypto_components[0]


def recommended_next_steps(cbom: dict[str, Any]) -> list[str]:
    summary = cbom["summary"]
    findings = cbom.get("findings", [])
    vulnerable_count = summary.get("quantum_vulnerable_component_count", 0)

    steps = [
        "Keep this asset in a cryptographic inventory so it can be tracked as post-quantum standards and vendor support mature.",
        "Assign an owner for this asset so future certificate, TLS, and migration decisions are not orphaned.",
        "Document the expected confidentiality lifetime for data protected by this endpoint.",
    ]

    if vulnerable_count:
        steps.extend(
            [
                "Prioritize this asset if it protects sensitive data that must remain confidential for years.",
                "Monitor vendor and platform support for hybrid or post-quantum TLS options before making production changes.",
                "Create a migration note for leadership explaining that the right next step is planning and tracking, not panic replacement.",
            ]
        )
    elif not findings:
        steps.append("Repeat this scan after certificate renewals or major infrastructure changes.")

    return steps


def write_evidence_pack(cbom: dict[str, Any], path: Path) -> None:
    asset = first_asset(cbom)
    crypto = first_crypto(asset)
    summary = cbom["summary"]
    findings = cbom.get("findings", [])
    trust_receipt = cbom["trust_receipt"]

    lines = [
        "# Qyrion Evidence Pack",
        "",
        "## Executive Summary",
        "",
        (
            f"Qyrion generated a local Cryptographic Bill of Materials for `{asset['name']}`. "
            f"The asset received a Quantum Readiness Score of {summary['quantum_readiness_score']} "
            f"with highest severity `{summary['highest_severity']}`."
        ),
        "",
        summary["plain_english"],
        "",
        "This evidence pack is intended to help leadership, security, engineering, and compliance teams make a plan before quantum security becomes urgent.",
        "",
        "## CBOM Summary",
        "",
        f"- Asset: {asset['name']}",
        f"- Asset Type: {asset['asset_type']}",
        f"- TLS Version: {asset['protocol']['tls_version']}",
        f"- Cipher Suite: {asset['protocol']['cipher_suite']}",
        f"- Cryptographic Components: {summary['crypto_component_count']}",
        f"- Quantum-Vulnerable Components: {summary['quantum_vulnerable_component_count']}",
        "",
        "## Readiness Score Factors",
        "",
        *[
            f"- {factor['factor']} ({factor['impact']}): {factor['reason']}"
            for factor in summary.get("readiness_score_factors", [])
        ],
        "",
        "## Primary Cryptographic Component",
        "",
        f"- Component Type: {crypto['component_type']}",
        f"- Algorithm Family: {crypto['algorithm_family']}",
        f"- Algorithm: {crypto['algorithm']}",
        f"- Key Size: {crypto['key_size_bits'] or 'unknown'}",
        f"- Signature Algorithm: {crypto['signature_algorithm']}",
        f"- Quantum Vulnerable: {crypto['quantum_vulnerable']}",
        f"- Valid Until: {crypto['validity']['not_after']}",
        "",
        "## What This Means",
        "",
    ]

    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"- {finding['title']}: {finding['description']}",
                    f"- Recommended action: {finding['recommendation']}",
                ]
            )
    else:
        lines.append("- No findings were generated by this scan.")

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            *[f"{index}. {step}" for index, step in enumerate(recommended_next_steps(cbom), start=1)],
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
            "",
            "## Limits",
            "",
            "This evidence pack is generated from the CBOM provided to the tool. It is not a full security audit, penetration test, compliance attestation, or legal opinion.",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")


def crypto_snapshot(cbom: dict[str, Any]) -> dict[str, Any]:
    asset = first_asset(cbom)
    crypto = first_crypto(asset)
    summary = cbom["summary"]

    return {
        "asset_name": asset["name"],
        "asset_type": asset["asset_type"],
        "tls_version": asset["protocol"]["tls_version"],
        "cipher_suite": asset["protocol"]["cipher_suite"],
        "algorithm_family": crypto["algorithm_family"],
        "algorithm": crypto["algorithm"],
        "key_size_bits": crypto["key_size_bits"],
        "signature_algorithm": crypto["signature_algorithm"],
        "quantum_vulnerable": crypto["quantum_vulnerable"],
        "valid_until": crypto["validity"]["not_after"],
        "score": summary["quantum_readiness_score"],
        "highest_severity": summary["highest_severity"],
        "quantum_vulnerable_count": summary["quantum_vulnerable_component_count"],
    }


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    fields = [
        ("asset_name", "Asset"),
        ("score", "Quantum Readiness Score"),
        ("highest_severity", "Highest Severity"),
        ("tls_version", "TLS Version"),
        ("cipher_suite", "Cipher Suite"),
        ("algorithm_family", "Algorithm Family"),
        ("algorithm", "Algorithm"),
        ("key_size_bits", "Key Size"),
        ("signature_algorithm", "Signature Algorithm"),
        ("quantum_vulnerable", "Quantum Vulnerable"),
        ("valid_until", "Certificate Valid Until"),
        ("quantum_vulnerable_count", "Quantum-Vulnerable Components"),
    ]

    changes = []
    for key, label in fields:
        if before.get(key) != after.get(key):
            changes.append(
                {
                    "field": key,
                    "label": label,
                    "before": before.get(key),
                    "after": after.get(key),
                }
            )
    return changes


def diff_outcome(before: dict[str, Any], after: dict[str, Any], changes: list[dict[str, Any]]) -> str:
    if before["asset_name"] != after["asset_name"]:
        return "different_assets"

    score_delta = after["score"] - before["score"]
    vulnerable_delta = after["quantum_vulnerable_count"] - before["quantum_vulnerable_count"]

    if score_delta > 0 and vulnerable_delta <= 0:
        return "improved"
    if score_delta < 0 or vulnerable_delta > 0:
        return "worsened"
    if changes:
        return "changed"
    return "unchanged"


def write_cbom_diff(before_cbom: dict[str, Any], after_cbom: dict[str, Any], path: Path) -> None:
    before = crypto_snapshot(before_cbom)
    after = crypto_snapshot(after_cbom)
    changes = compare_snapshots(before, after)
    outcome = diff_outcome(before, after, changes)
    score_delta = after["score"] - before["score"]

    lines = [
        "# Qyrion CBOM Diff Report",
        "",
        "## Summary",
        "",
        f"- Before Asset: {before['asset_name']}",
        f"- After Asset: {after['asset_name']}",
        f"- Outcome: {outcome}",
        f"- Score Change: {score_delta:+}",
        f"- Before Score: {before['score']}",
        f"- After Score: {after['score']}",
        "",
        "## Plain-English Interpretation",
        "",
    ]

    if outcome == "different_assets":
        lines.append("These CBOMs are for different assets. Treat this as a comparison, not proof that one asset improved over time.")
    elif outcome == "improved":
        lines.append("The later CBOM appears to reduce quantum-readiness risk based on the current Qyrion scoring model.")
    elif outcome == "worsened":
        lines.append("The later CBOM appears to increase quantum-readiness risk and should be reviewed before being treated as progress.")
    elif outcome == "changed":
        lines.append("The cryptographic posture changed, but the current Qyrion score did not clearly improve or worsen.")
    else:
        lines.append("No tracked cryptographic changes were detected between these CBOM files.")

    lines.extend(
        [
            "",
            "## Detected Changes",
            "",
        ]
    )

    if changes:
        for change in changes:
            lines.append(f"- {change['label']}: `{change['before']}` -> `{change['after']}`")
    else:
        lines.append("- No tracked changes.")

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
        ]
    )

    if outcome == "different_assets":
        lines.extend(
            [
                "1. Compare assets only when the business goal is side-by-side prioritization.",
                "2. For historical tracking, compare two CBOMs from the same asset at different times.",
                "3. Use the detected changes to decide which asset needs more planning context.",
            ]
        )
    elif outcome == "worsened":
        lines.extend(
            [
                "1. Review why the newer CBOM reduced the readiness score or added quantum-vulnerable exposure.",
                "2. Confirm whether the change came from certificate renewal, infrastructure change, or scanner input differences.",
                "3. Add this asset to the migration plan if it protects sensitive or long-lived data.",
            ]
        )
    elif outcome == "improved":
        lines.extend(
            [
                "1. Record the improvement in the asset's quantum-readiness history.",
                "2. Confirm the change is expected and stable after certificate or infrastructure updates.",
                "3. Continue monitoring this asset after renewals and releases.",
            ]
        )
    else:
        lines.extend(
            [
                "1. Keep both CBOMs as a historical record.",
                "2. Re-run comparison after future certificate renewals or infrastructure changes.",
                "3. Add business context such as data sensitivity and confidentiality lifetime when available.",
            ]
        )

    lines.extend(
        [
            "",
            "## Limits",
            "",
            "This diff compares Qyrion CBOM metadata fields. It is not a full security audit, compliance attestation, or proof that production cryptography is safe.",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")


def evaluate_policy(cbom: dict[str, Any]) -> list[dict[str, Any]]:
    asset = first_asset(cbom)
    crypto = first_crypto(asset)
    summary = cbom["summary"]
    exposure = asset["exposure"]
    protocol = asset["protocol"]

    checks = []

    checks.append(
        {
            "rule_id": "QYR-PQC-001",
            "title": "Track quantum-vulnerable public-key cryptography",
            "status": "fail" if crypto["quantum_vulnerable"] else "pass",
            "severity": "medium" if crypto["quantum_vulnerable"] else "info",
            "reason": (
                f"{crypto['algorithm_family']} public-key cryptography should be tracked for post-quantum migration."
                if crypto["quantum_vulnerable"]
                else "No quantum-vulnerable public-key cryptography was identified by this CBOM."
            ),
            "recommendation": "Keep this asset in the CBOM and include it in post-quantum migration planning.",
        }
    )

    checks.append(
        {
            "rule_id": "QYR-PQC-002",
            "title": "Record confidentiality lifetime",
            "status": "warn" if exposure.get("data_lifetime") == "unknown" else "pass",
            "severity": "medium" if exposure.get("data_lifetime") == "unknown" else "info",
            "reason": (
                "Data confidentiality lifetime is unknown, so harvest-now-decrypt-later urgency cannot be ranked."
                if exposure.get("data_lifetime") == "unknown"
                else f"Data confidentiality lifetime is recorded as {exposure.get('data_lifetime')}."
            ),
            "recommendation": "Ask the asset owner how long protected data must remain confidential.",
        }
    )

    checks.append(
        {
            "rule_id": "QYR-PQC-003",
            "title": "Review internet-exposed cryptography",
            "status": "warn" if exposure.get("internet_exposed") else "pass",
            "severity": "low" if exposure.get("internet_exposed") else "info",
            "reason": (
                "This endpoint is internet-exposed, so its public cryptographic posture is externally visible."
                if exposure.get("internet_exposed")
                else "This asset is not marked as internet-exposed."
            ),
            "recommendation": "Prioritize ownership, monitoring, and renewal tracking for internet-exposed assets.",
        }
    )

    checks.append(
        {
            "rule_id": "QYR-TLS-001",
            "title": "Use modern TLS posture",
            "status": "pass" if protocol.get("tls_version") == "TLSv1.3" else "warn",
            "severity": "low" if protocol.get("tls_version") != "TLSv1.3" else "info",
            "reason": (
                "TLS 1.3 is present. This is modern classical TLS, though not automatically post-quantum safe."
                if protocol.get("tls_version") == "TLSv1.3"
                else f"{protocol.get('tls_version') or 'unknown TLS'} should be reviewed as part of TLS modernization."
            ),
            "recommendation": "Track TLS version as part of the broader post-quantum readiness roadmap.",
        }
    )

    checks.append(
        {
            "rule_id": "QYR-GOV-001",
            "title": "Maintain readiness scoring evidence",
            "status": "pass" if summary.get("readiness_score_factors") else "warn",
            "severity": "low",
            "reason": (
                "Readiness score factors are present and explain how the score was produced."
                if summary.get("readiness_score_factors")
                else "Readiness score factors are missing, making the score harder to explain."
            ),
            "recommendation": "Keep score factors in generated CBOMs so leadership can understand risk changes.",
        }
    )

    return checks


def policy_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for check in checks:
        counts[check["status"]] += 1

    if counts["fail"]:
        outcome = "attention_required"
    elif counts["warn"]:
        outcome = "review_recommended"
    else:
        outcome = "passing"

    return {"outcome": outcome, **counts}


def write_policy_report(cbom: dict[str, Any], path: Path) -> None:
    asset = first_asset(cbom)
    checks = evaluate_policy(cbom)
    summary = policy_summary(checks)

    lines = [
        "# Qyrion CBOM Policy Report",
        "",
        "## Summary",
        "",
        f"- Asset: {asset['name']}",
        f"- Outcome: {summary['outcome']}",
        f"- Passed: {summary['pass']}",
        f"- Warnings: {summary['warn']}",
        f"- Failed: {summary['fail']}",
        "",
        "## Plain-English Interpretation",
        "",
    ]

    if summary["outcome"] == "attention_required":
        lines.append("This CBOM has policy failures that should be reviewed as part of the quantum-readiness plan.")
    elif summary["outcome"] == "review_recommended":
        lines.append("This CBOM has warnings that should be reviewed, but no policy failures were detected.")
    else:
        lines.append("This CBOM passes the current Qyrion policy checks.")

    lines.extend(["", "## Policy Checks", ""])
    for check in checks:
        lines.extend(
            [
                f"### {check['rule_id']}: {check['title']}",
                "",
                f"- Status: {check['status']}",
                f"- Severity: {check['severity']}",
                f"- Reason: {check['reason']}",
                f"- Recommendation: {check['recommendation']}",
                "",
            ]
        )

    lines.extend(
        [
            "## Limits",
            "",
            "This policy report applies Qyrion's current prototype rules to one CBOM file. It is not a full compliance attestation, legal opinion, or production security certification.",
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


def evidence_command(args: argparse.Namespace) -> int:
    cbom_path = Path(args.cbom_json)
    cbom = json.loads(cbom_path.read_text(encoding="utf-8"))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cbom_name = cbom_path.stem.removeprefix("qyrion-cbom-")
    default_name = f"qyrion-evidence-{safe_filename(cbom_name)}.md"
    evidence_path = Path(args.output) if args.output else output_dir / default_name
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    write_evidence_pack(cbom, evidence_path)
    print(f"Evidence pack: {evidence_path}")
    return 0


def diff_command(args: argparse.Namespace) -> int:
    before_path = Path(args.before_cbom_json)
    after_path = Path(args.after_cbom_json)
    before_cbom = json.loads(before_path.read_text(encoding="utf-8"))
    after_cbom = json.loads(after_path.read_text(encoding="utf-8"))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    before_name = before_path.stem.removeprefix("qyrion-cbom-")
    after_name = after_path.stem.removeprefix("qyrion-cbom-")
    default_name = f"qyrion-diff-{safe_filename(before_name)}-to-{safe_filename(after_name)}.md"
    diff_path = Path(args.output) if args.output else output_dir / default_name
    diff_path.parent.mkdir(parents=True, exist_ok=True)

    write_cbom_diff(before_cbom, after_cbom, diff_path)
    print(f"CBOM diff: {diff_path}")
    return 0


def policy_command(args: argparse.Namespace) -> int:
    cbom_path = Path(args.cbom_json)
    cbom = json.loads(cbom_path.read_text(encoding="utf-8"))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cbom_name = cbom_path.stem.removeprefix("qyrion-cbom-")
    default_name = f"qyrion-policy-{safe_filename(cbom_name)}.md"
    policy_path = Path(args.output) if args.output else output_dir / default_name
    policy_path.parent.mkdir(parents=True, exist_ok=True)

    write_policy_report(cbom, policy_path)
    print(f"Policy report: {policy_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qyrion local CBOM scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cbom_parser = subparsers.add_parser("cbom", help="Generate a CBOM for a public TLS endpoint")
    cbom_parser.add_argument("hostnames", nargs="+", help="Hostnames to scan, such as example.com openai.com")
    cbom_parser.add_argument("--port", type=int, default=443, help="TLS port to scan")
    cbom_parser.add_argument("--output-dir", default="reports", help="Directory for generated reports")
    cbom_parser.set_defaults(func=cbom_command)

    evidence_parser = subparsers.add_parser("evidence", help="Generate an evidence pack from a CBOM JSON file")
    evidence_parser.add_argument("cbom_json", help="Path to a Qyrion CBOM JSON file")
    evidence_parser.add_argument("--output-dir", default="evidence", help="Directory for generated evidence packs")
    evidence_parser.add_argument("--output", help="Optional exact output Markdown path")
    evidence_parser.set_defaults(func=evidence_command)

    diff_parser = subparsers.add_parser("diff", help="Compare two Qyrion CBOM JSON files")
    diff_parser.add_argument("before_cbom_json", help="Path to the earlier Qyrion CBOM JSON file")
    diff_parser.add_argument("after_cbom_json", help="Path to the later Qyrion CBOM JSON file")
    diff_parser.add_argument("--output-dir", default="diffs", help="Directory for generated diff reports")
    diff_parser.add_argument("--output", help="Optional exact output Markdown path")
    diff_parser.set_defaults(func=diff_command)

    policy_parser = subparsers.add_parser("policy", help="Evaluate a Qyrion CBOM against prototype policy rules")
    policy_parser.add_argument("cbom_json", help="Path to a Qyrion CBOM JSON file")
    policy_parser.add_argument("--output-dir", default="policy", help="Directory for generated policy reports")
    policy_parser.add_argument("--output", help="Optional exact output Markdown path")
    policy_parser.set_defaults(func=policy_command)

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
