# Architecture & Threat Model: Enterprise GenAI Security Gateway on AWS

This document outlines the architectural topology, threat modeling boundaries, and defense-in-depth inspection pipeline implemented in the **AWS GenAI Security Gateway**.

---

## 1. High-Level Architectural Topology

```
+---------------------------------------------------------------------------------------------------+
|                                      Enterprise Ingress Zone                                       |
|                                                                                                   |
|  [ Inbound Client Application ] ---> [ AWS WAFv2 Web ACL ] ---> [ Amazon API Gateway (HTTP v2) ]  |
|                                        - Rate Limiting                 - JWT Auth & CORS          |
|                                        - AWS Managed CRS               - Route Throttles          |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                 Zero-Trust Inspection Mesh (Lambda)                               |
|                                                                                                   |
|   +-----------------------+     +-----------------------+     +-------------------------------+   |
|   | 1. Jailbreak Detector | --> | 2. Rate Limit Enforcer| --> | 3. PII & Secret Redactor      |   |
|   |    (OWASP LLM01)      |     |    (OWASP LLM04)      |     |    (OWASP LLM02)              |   |
|   +-----------------------+     +-----------------------+     +-------------------------------+   |
|               |                             |                                 |                   |
|               v                             v                                 v                   |
|     [ HTTP 403 Reject ]           [ HTTP 429 Throttle ]             [ Tokenized Prompt Payload ]  |
+---------------------------------------------------------------------------------------------------+
                                                                                |
                                                                                v
+---------------------------------------------------------------------------------------------------+
|                                      Model Execution Tier                                         |
|                                                                                                   |
|   [ Amazon Bedrock Foundation Models ] <--------------------------------------+                   |
|   - Anthropic Claude 3 (Sonnet / Haiku)                                                           |
|   - Amazon Titan Text Express                                                                     |
|   - Zero-Data Retention Guarantee & Scoped IAM Role Credentials                                   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                  Egress Guard & Audit Persistence                                 |
|                                                                                                   |
|   +------------------------------+             +----------------------------------------------+   |
|   | Output Secret Scrubber (LLM02) | ---------> | Tamper-Evident S3 Audit Storage (SHA-256)   |   |
|   +------------------------------+             +----------------------------------------------+   |
|                 |                                                                                 |
|                 v                                                                                 |
|   [ Clean Inference Response to Client ]                                                          |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Modeling & OWASP Top 10 for LLMs Alignment

| OWASP Identifier | Vulnerability Name | Attack Vector Prevented | Gateway Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **LLM01** | Prompt Injection & Jailbreaks | Direct instruction overrides, DAN persona switches, guardrail evasion. | Heuristic regex parser scanning ingress payloads prior to Bedrock invocation. Terminates request with HTTP 403. |
| **LLM02** | Sensitive Information Disclosure | Accidental PII exfiltration (SSN, emails) or hardcoded cloud credentials. | Bidirectional deterministic regex tokenization engine (`[REDACTED_PII_SSN]`, `[REDACTED_AWS_KEY]`). |
| **LLM04** | Model Denial of Service | Unbounded token requests or high-frequency prompt bombing exhausting quota. | Single-request ceiling validation (4096 tokens) + DynamoDB tenant sliding-window rate limiting. |
| **LLM06** | Excessive Agency | LLM granted unconstrained cloud privileges or executing unauthorized actions. | Strict IAM execution boundaries, dedicated read-only foundation model invocations. |

---

## 3. Cryptographic Audit Manifest Specification

Every screened batch or real-time transaction creates a deterministic JSON structure conforming to the schema:

```json
{
  "gateway_name": "aws-genai-security-gateway-prod",
  "audit_timestamp": "2026-10-29T14:14:28.157474+00:00",
  "governance_frameworks": [
    "OWASP-Top-10-for-LLMs-2025",
    "NIST-AI-RMF-1.0",
    "EU-AI-Act-Article-15",
    "ISO-42001-AI-Management"
  ],
  "metrics": {
    "total_inferences_screened": 4,
    "clean_inferences_allowed": 1,
    "pii_masked_inferences": 1,
    "adversarial_jailbreaks_blocked": 2,
    "threat_mitigation_rate_pct": 100.0
  },
  "sha256_checksum": "876f4755d29226e4f1c2e9eb2f1c5277da17ef797d5f9f4ee8d413c7b59a6b61"
}
```

The SHA-256 checksum is computed over the canonical, key-sorted JSON serialization to guarantee tamper evidence when archived in Amazon S3 Object Lock.
