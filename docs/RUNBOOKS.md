# SecOps Incident Response Runbooks: GenAI Security Gateway

This runbook guides Cloud Security Operations (SecOps) engineers in handling active adversarial attempts against Amazon Bedrock and LLM infrastructure.

---

## Runbook 01: High-Frequency Prompt Injection Wave Detected

### Symptoms
- CloudWatch Alarm `GenAISecurityGateway-PromptInjectionsSpike` triggers.
- Influx of HTTP 403 Forbidden responses with header `X-Security-Verdict: BLOCK`.
- Logs indicate rule `DIRECT_INSTRUCTION_OVERRIDE` or `JAILBREAK_PERSONA_OVERRIDE`.

### Remediation Steps
1. **Identify Offending Tenant / Source IP:**
   ```bash
   aws logs filter-log-events \
     --log-group-name "/aws/lambda/genai-sec-gateway-prod-proxy" \
     --filter-pattern '{ $.verdict = "BLOCK" }'
   ```
2. **Apply WAF IP Block Rule:**
   Add offending IP range to the regional WAF IP set:
   ```bash
   aws wafv2 update-ip-set \
     --name "AdversarialIPBlocklist" \
     --scope REGIONAL \
     --id "<IP-SET-ID>" \
     --addresses "<OFFENDER_CIDR>"
   ```
3. **Notify Tenant Owner:**
   Dispatch security advisory detailing the blocked adversarial payload.

---

## Runbook 02: PII / Secret Exfiltration Attempt

### Symptoms
- Gateway logs report `RULE_CREDENTIAL_AWS_ACCESS_KEY` or `RULE_PII_US_SSN`.
- Request is sanitized with `verdict: MASK_AND_ALLOW`.

### Remediation Steps
1. **Inspect Audit Manifest:**
   Locate corresponding audit ID in the S3 compliance manifest bucket:
   ```bash
   aws s3 cp s3://genai-sec-gateway-prod-audit-manifests-<ACCOUNT_ID>/reports/ . --recursive
   ```
2. **Determine Credential Scope:**
   If an active `AKIA...` key was submitted in the prompt, invoke AWS IAM credential rotation procedures immediately.
3. **Notify Developer Team:**
   Educate tenant engineering team on secret management using AWS Secrets Manager rather than embedding credentials in conversational prompts.

---

## Runbook 03: Tenant Quota Exhaustion & Token Denial-of-Service

### Symptoms
- Tenant receives HTTP 429 Too Many Requests.
- Audit rule `TENANT_TOKEN_BUDGET_EXHAUSTED` triggers.

### Remediation Steps
1. Verify if token consumption represents legitimate traffic surge or infinite loop prompt bombing.
2. If legitimate, elevate hourly token ceiling in DynamoDB table:
   ```bash
   python -m src.cli reset-quota --tenant-id "<TENANT_ID>"
   ```
