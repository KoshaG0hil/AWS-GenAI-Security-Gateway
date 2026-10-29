# Comprehensive Project Guide: Enterprise GenAI Security Gateway

This guide details the architectural decisions, design patterns, and engineering rationale underpinning the **Enterprise GenAI & LLM Security Gateway on AWS**.

---

## 1. Problem Statement & Motivation

Enterprise adoption of Generative AI and foundation models (Amazon Bedrock, Anthropic Claude 3, Amazon Titan) introduces unprecedented security vulnerabilities categorized by the **OWASP Top 10 for Large Language Model Applications**:
1. **Adversarial Jailbreaks (LLM01):** Crafted prompts instructing models to disregard safety boundaries or impersonate unrestricted personas (`DAN`).
2. **Sensitive Data Exposure (LLM02):** Unsanitized prompts containing Personally Identifiable Information (SSN, emails) or cloud infrastructure secrets (`AKIA...` keys) leaving the enterprise perimeter.
3. **Model Denial of Service (LLM04):** Attackers consuming token quotas through unbounded prompt loops or distributed request flooding.

The GenAI Security Gateway provides a cloud-native reverse proxy layer that intercepts, inspects, tokenizes, and rate-limits inference traffic before reaching Amazon Bedrock.

---

## 2. Engineering Architecture & Design Patterns

### Pipeline Pattern: Intercepting Filter
The gateway implements an intercepting filter pipeline:
- **Filter 1 (PromptInjectionDetector):** Evaluates regex heuristics and instruction override vectors. If malicious, terminates request immediately (`HTTP 403`).
- **Filter 2 (TokenRateLimiter):** Evaluates single-request ceiling and sliding-window tenant consumption. If exceeded, returns `HTTP 429`.
- **Filter 3 (PIIRedactor):** Identifies and tokenizes sensitive patterns into zero-knowledge tokens prior to model forwarding.
- **Filter 4 (EgressScrubber):** Inspects model response text before returning to caller to prevent accidental secret leakage.

### Cryptographic Tamper-Evidence
Audit logs are compiled into a canonical JSON structure, hashed using SHA-256, and written to versioned, encrypted Amazon S3 storage with Object Lock for non-repudiation.
