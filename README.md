# Enterprise GenAI & LLM Security Gateway on AWS

[![CI - GenAI Security Gateway](https://github.com/KoshaG0hil/AWS-GenAI-Security-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/KoshaG0hil/AWS-GenAI-Security-Gateway/actions/workflows/ci.yml)
[![Cyber SOC Dashboard](https://img.shields.io/badge/Live_SOC_Console-GitHub_Pages-06b6d4?logo=github)](https://koshag0hil.github.io/AWS-GenAI-Security-Gateway/)
[![OWASP Top 10 for LLMs](https://img.shields.io/badge/OWASP-LLM_Top_10_2025-emerald)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Security Mesh](https://img.shields.io/badge/AWS-Bedrock_Zero--Trust-orange?logo=amazon-aws)](https://aws.amazon.com/bedrock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade **Zero-Trust Security Reverse Proxy & Threat Mesh** for foundation models hosted on **Amazon Bedrock** (Anthropic Claude 3, Amazon Titan), enforcing automated defense guardrails aligned with the **OWASP Top 10 for LLMs (2025)** and **NIST AI RMF 1.0**.

Architected by **[Kosha Gohil](https://www.linkedin.com/in/kosha-gohil/)**, AWS Cloud Security & DevSecOps Engineer.

---

## 🛡️ Core Security Capabilities

- **OWASP LLM01 - Prompt Injection & Jailbreak Defense:** Real-time multi-pattern heuristic screening detecting direct instruction overrides, persona spoofing (`DAN`, developer modes), and system prompt extraction attacks with sub-2ms latency.
- **OWASP LLM02 - Bidirectional PII & Credential Tokenization:** Deterministic regex sanitization scrubbing US SSNs, credit cards, active AWS Access Keys (`AKIA...`), and bearer tokens on both ingress requests and model egress outputs.
- **OWASP LLM04 - Model Denial of Service & Token Sliding Quotas:** Per-request token ceiling checks (4096 tokens) combined with per-tenant hourly sliding window token budgets backed by Amazon DynamoDB.
- **Tamper-Evident Audit Trails:** Cryptographically signed SHA-256 JSON audit manifests verifying 100% threat mitigation rates for regulatory compliance (NIST AI RMF 1.0, EU AI Act Art. 15).
- **Production-Ready Terraform IaC:** Complete infrastructure as code deploying Amazon API Gateway HTTP v2, AWS Lambda, AWS WAFv2, DynamoDB token tracker, and encrypted S3 audit storage with AWS CIS Benchmark hardening.

---

## 📊 Live Interactive Cyber SOC Console

Experience the interactive GenAI threat simulation console on GitHub Pages:  
👉 **[https://koshag0hil.github.io/AWS-GenAI-Security-Gateway/](https://koshag0hil.github.io/AWS-GenAI-Security-Gateway/)**

Explore live attack vectors including DAN jailbreaks, PII exfiltration, and token DoS with real-time token masking diffs and security verdict badges.

---

## 🏗️ Architecture Overview

```
                      +------------------------------------------+
                      |         AWS WAFv2 Web ACL                |
                      |  (Rate Limiting + Managed Common Rules)  |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       Amazon API Gateway (HTTP v2)       |
                      |    (Throttling + Access Logging)         |
                      +------------------------------------------+
                                           |
                                           v
    +----------------------------------------------------------------------------------+
    |                     AWS Lambda Security Mesh Proxy                               |
    |                                                                                  |
    |  [Prompt Ingestion] -> [Jailbreak Detector] -> [Rate Limiter] -> [PII Redactor]  |
    +----------------------------------------------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |          Amazon Bedrock Runtime          |
                      | (Anthropic Claude 3 / Amazon Titan LLM)  |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |  Egress Masking & SHA-256 Audit Manifest |
                      |       Archived to Encrypted Amazon S3    |
                      +------------------------------------------+
```

---

## ⚡ Quick Start

### 1. Prerequisites
- Python 3.10+
- Terraform 1.5+ (optional, for cloud provisioning)

### 2. Installation
```bash
git clone https://github.com/KoshaG0hil/AWS-GenAI-Security-Gateway.git
cd AWS-GenAI-Security-Gateway

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Threat Simulation CLI
```bash
python -m src.cli simulate
```

### 4. Run Pytest Suite
```bash
pytest -v
```

---

## 📁 Repository Structure

```
AWS-GenAI-Security-Gateway/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Pytest, Ruff linting & Terraform validation
│       └── pages.yml              # GitHub Pages deployment workflow
├── docs/
│   ├── ARCHITECTURE.md            # Topology and threat model specification
│   ├── OWASP_LLM_MATRIX.md        # OWASP Top 10 for LLMs mapping
│   └── RUNBOOKS.md                # Incident response runbooks for SecOps
├── reports/
│   └── genai_audit_manifest.json  # Cryptographic SHA-256 audit trail
├── src/
│   ├── core/                      # Pydantic data schemas & enums
│   ├── gateway/                   # Amazon Bedrock reverse proxy pipeline
│   ├── inspectors/                # Prompt injection, PII redactor & rate limiter
│   ├── reporters/                 # SHA-256 compliance manifest generator
│   ├── cli.py                     # Operator command-line interface
│   └── lambda_gateway_handler.py  # API Gateway Lambda integration handler
├── terraform/
│   ├── main.tf                    # Provider configuration & locals
│   ├── variables.tf               # Input parameters
│   ├── api_gateway_bedrock.tf     # API Gateway, Lambda, WAFv2, DynamoDB, S3
│   ├── outputs.tf                 # Resource ARNs and endpoints
│   └── terraform.tfvars.example   # Sample variable definitions
├── tests/                         # Pytest test suite (100% passing)
├── index.html                     # Interactive Cyber SOC Console
├── Dockerfile                     # Containerized proxy image
├── run.ps1 / run.sh / run.bat     # One-click execution scripts
└── pyproject.toml / requirements.txt
```

---

## 👩‍💻 Author

**Kosha Gohil**  
Cloud Security & DevSecOps Engineer  
- 💼 LinkedIn: [linkedin.com/in/kosha-gohil](https://www.linkedin.com/in/kosha-gohil/)  
- 🐙 GitHub: [@KoshaG0hil](https://github.com/KoshaG0hil)  
