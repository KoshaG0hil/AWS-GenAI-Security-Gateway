# OWASP Top 10 for LLMs Enforcement Matrix

This matrix documents how the **Enterprise GenAI Security Gateway** addresses the official OWASP Top 10 for Large Language Models (LLMs) vulnerability taxonomy.

---

### Matrix Summary

| Rank | Vulnerability | Severity | Enforcement Tier | Mitigation Implementation |
| :--- | :--- | :--- | :--- | :--- |
| **LLM01** | Prompt Injections | **CRITICAL** | Ingress Reverse Proxy | `PromptInjectionDetector` scans for instruction override keywords, DAN personas, and jailbreak syntax before payload touches Bedrock. |
| **LLM02** | Sensitive Information Disclosure | **HIGH** | Ingress & Egress Filters | `PIIRedactor` replaces Social Security Numbers, AWS IAM Access Keys (`AKIA...`), and credit card patterns with redacted tokens. |
| **LLM03** | Supply Chain Vulnerabilities | **HIGH** | CI/CD Pipeline | Base image scanning via Trivy, pinned Python dependencies with SHA-256 hashes, and verified boto3 Bedrock SDK runtimes. |
| **LLM04** | Model Denial of Service | **HIGH** | Ingress WAF & Proxy | `TokenRateLimiter` enforces 4096-token single-request ceilings and hourly tenant token quotas backed by Amazon DynamoDB. |
| **LLM05** | Improper Output Handling | **HIGH** | Egress Scrubbing Filter | Ingress and egress sanitizers validate model output schemas to prevent indirect prompt injection execution. |
| **LLM06** | Excessive Agency | **CRITICAL** | IAM Permissions | Foundation models run with scoped, least-privilege IAM roles lacking direct write access to external AWS infrastructure. |
| **LLM07** | System Prompt Leakage | **MEDIUM** | Ingress Regex Filter | Blocks prompts containing `reveal system prompt`, `output initial instructions`, or configuration exfiltration queries. |
| **LLM08** | Vector & Embedding Weaknesses | **MEDIUM** | Data Preprocessing Tier | Cryptographic hash checks and access boundaries on RAG context documents. |
| **LLM09** | Misinformation & Hallucination | **MEDIUM** | Foundation Model Selection | Configured to use temperature-controlled models with factual grounding and system prompt system guardrails. |
| **LLM10** | Unbounded Consumption | **HIGH** | AWS Budget & Quotas | Amazon CloudWatch Alarms and API Gateway throttling stop runaway API spend before reaching upstream Bedrock limits. |

---

### Validation & Automated Verification

Run automated test suite verifying OWASP LLM01, LLM02, and LLM04 mitigations:

```bash
pytest -v tests/test_prompt_injection_detector.py tests/test_pii_redactor.py tests/test_token_rate_limiter.py
```
