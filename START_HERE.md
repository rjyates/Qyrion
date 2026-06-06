# Qyrion Start Here

## Core Idea

Qyrion is a private AI platform for autonomous post-quantum cybersecurity.

It helps high-security organizations find quantum-vulnerable cryptography, understand risk, and prepare migration plans without sending sensitive data, code, keys, logs, infrastructure maps, or security posture to external AI systems.

## First Principle

Start small, stay changeable.

Qyrion should begin as a narrow, useful tool rather than a giant platform. Each version should teach us something about what customers actually need.

## Core Mentality

Have a plan before you need one.

Qyrion should make quantum security feel understandable, practical, and urgent without relying on fear. The company should teach businesses that post-quantum readiness is not about panic. It is about knowing where cryptography lives, understanding what is at risk, and preparing a migration path before the pressure arrives.

## Current Positioning

Private AI. Quantum-safe security. No data leaves.

More complete:

Qyrion is the private AI control plane for autonomous post-quantum cybersecurity, built for organizations that cannot expose their infrastructure, code, or security data to external AI.

Education-focused:

Qyrion helps businesses make a plan for quantum security before they need one.

## Initial Niche

Do not compete as a generic post-quantum cryptography scanner.

Qyrion's niche is private quantum security autonomy for organizations with strict data-control requirements:

- Defense contractors
- Critical infrastructure
- Banks and fintech companies
- Healthcare networks
- Aerospace and semiconductor companies
- Government suppliers
- Law firms with long-lived confidential data
- AI companies protecting models, infrastructure, and training data

## Product Wedge

Qyrion should focus on the CBOM: Cryptographic Bill of Materials.

An SBOM shows what software components a company uses. A CBOM shows what cryptography a company depends on:

- Algorithms
- Key types and sizes
- Certificates
- TLS configurations
- Cryptographic libraries
- Signing mechanisms
- Encryption dependencies
- Quantum-vulnerable assets
- Data protection lifetime
- Migration priority

The CBOM is the foundation for quantum readiness because companies cannot migrate cryptography they cannot see.

Qyrion's unique angle:

Create private, AI-generated CBOMs without exposing sensitive data to external AI.

## Smallest Useful Product

Start with Qyrion BlackBox Lite.

A local-first CBOM scanner and report generator that runs inside the customer's environment and produces a quantum-readiness report without uploading sensitive information.

### MVP Inputs

- Public domains
- TLS/certificate details
- Optional repository metadata
- Optional dependency/package metadata
- Optional cloud asset metadata

### MVP Outputs

- Cryptographic Bill of Materials
- Quantum Readiness Score
- List of quantum-vulnerable cryptography patterns
- Risk ranking
- "Harvest now, decrypt later" exposure notes
- Suggested migration priorities
- Executive summary
- Technical remediation checklist

## What We Avoid At First

- Full autonomous remediation
- Production cryptographic changes
- Enterprise integrations with everything
- Becoming a consulting-heavy company
- Building a giant AI platform before proving the wedge

## First 30 Days

1. Define the exact first customer profile.
2. Create the Qyrion brand basics.
3. Build a simple landing page.
4. Define the first CBOM schema.
5. Build a command-line scanner prototype for public TLS/certificate posture.
6. Generate a sample CBOM and quantum-readiness report from the scanner.
7. Create a mock dashboard image or clickable prototype.
8. Interview potential buyers or security professionals.

## First Prototype

The first technical prototype should scan a domain and produce a small CBOM containing:

- TLS versions
- Certificate algorithm
- Public key type and size
- Signature algorithm
- Expiration date
- Basic quantum-vulnerability notes
- Plain-English risk explanation

Example command:

`qyrion cbom example.com`

This is intentionally small. It creates a real artifact without requiring customer secrets.

## Flexible Product Path

Possible future modules:

- Qyrion BlackBox: private AI appliance
- Qyrion Atlas: cryptographic asset inventory and risk map
- Qyrion Sentinel: continuous monitoring
- Qyrion Switch: crypto-agility and remediation planning
- Qyrion Ledger: vendor quantum-risk tracking
- Qyrion Evidence: compliance and audit report generation

## New Idea Log

Use this section to capture ideas without derailing the current plan.

- Private AI security posture summarizer: converts raw scanner findings into sanitized executive summaries.
- Vendor quantum-risk questionnaire agent: asks vendors about PQC readiness and scores their answers.
- Air-gapped report generator: produces board-ready PDFs without internet access.
- CBOM diffing: compare cryptographic exposure between releases, vendors, or business units.
- CBOM policy engine: flag cryptography that violates internal, NIST, CISA, or customer-specific requirements.
- CBOM exchange format: a portable report customers can share with auditors, insurers, and enterprise buyers.
- Quantum-risk simulator: shows how risk changes if Q-day is estimated at 3, 5, or 10 years away.

## Next Best Step

Turn the scanner output into a first Qyrion Evidence Pack:

- executive summary
- CBOM summary
- readiness score
- trust receipt
- plain-English quantum security explanation
- recommended next steps

The product should keep proving the Qyrion promise:

useful quantum-security intelligence without exposing sensitive data.

## Related Planning Documents

- PROTECTION_AND_NEXT_STEPS.md: brand, IP, secrecy, and first founder actions.
- CBOM_SCHEMA.md: first draft of the Qyrion Cryptographic Bill of Materials format.
- INVENTION_LOG.md: dated internal record of Qyrion technical ideas.
- EDUCATION_STRATEGY.md: messaging and education plan for making quantum security understandable.
- VIDEO_SCRIPTS.md: first plain-English educational video scripts for the website.
- BUSINESS_STRENGTHENERS.md: additional product, moat, education, and revenue ideas.
- website/index.html: first Qyrion landing page prototype.
- qyrion.py: local CBOM scanner prototype.
- GIT_SETUP.md: instructions for initializing and managing the project in Git.

## Implemented Features

- Feature 1: Landing page, CBOM explainer, and local public TLS CBOM scanner.
- Feature 2: Evidence Pack generator from a Qyrion CBOM JSON file.
