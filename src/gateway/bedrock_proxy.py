"""Amazon Bedrock Security Proxy & Inspection Pipeline."""

import time
import uuid

from ..core.config import (
    GatewayResponse,
    InferenceRequest,
    InspectionResult,
    InspectionVerdict,
    SecurityFinding,
    ThreatCategory,
    ThreatSeverity,
)
from ..inspectors.pii_redactor import PIIRedactor
from ..inspectors.prompt_injection_detector import PromptInjectionDetector
from ..inspectors.token_rate_limiter import TokenRateLimiter


class BedrockSecurityProxy:
    """Enterprise Reverse Proxy for Amazon Bedrock implementing OWASP Top 10 for LLMs security guardrails."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.injection_detector = PromptInjectionDetector()
        self.pii_redactor = PIIRedactor()
        self.rate_limiter = TokenRateLimiter()

    def inspect_request(self, request: InferenceRequest) -> InspectionResult:
        """Runs multi-stage inspection: Injection Detection -> Token Budgeting -> PII Redaction."""
        all_findings = []

        # 1. Prompt Injection & Jailbreak Analysis (LLM01)
        injection_findings = self.injection_detector.inspect(request.prompt)
        all_findings.extend(injection_findings)

        if injection_findings:
            return InspectionResult(
                verdict=InspectionVerdict.BLOCK,
                sanitized_prompt=request.prompt,
                findings=all_findings,
                blocked_reason="Request blocked: Adversarial prompt injection or jailbreak heuristic detected.",
            )

        # 2. Token Budget & Rate Limiting (LLM04)
        dos_finding = self.rate_limiter.check_quota(request)
        if dos_finding:
            all_findings.append(dos_finding)
            return InspectionResult(
                verdict=InspectionVerdict.BLOCK,
                sanitized_prompt=request.prompt,
                findings=all_findings,
                blocked_reason=f"Request throttled: {dos_finding.description}",
            )

        # 3. PII & Secret Redaction (LLM02)
        sanitized_prompt, pii_matches, pii_findings = self.pii_redactor.redact(request.prompt)
        all_findings.extend(pii_findings)

        verdict = InspectionVerdict.MASK_AND_ALLOW if pii_matches else InspectionVerdict.ALLOW

        return InspectionResult(
            verdict=verdict,
            sanitized_prompt=sanitized_prompt,
            findings=all_findings,
            pii_redacted=pii_matches,
            tokens_consumed=len(sanitized_prompt.split()) * 2,
        )

    def process(self, request: InferenceRequest) -> GatewayResponse:
        """Executes full gateway transaction: inspects, routes to model, and audits."""
        start_time = time.time()
        audit_id = f"aud-{uuid.uuid4().hex[:12]}"

        inspection = self.inspect_request(request)

        # If blocked at ingress, reject immediately
        if inspection.verdict == InspectionVerdict.BLOCK:
            latency = round((time.time() - start_time) * 1000, 2)
            return GatewayResponse(
                verdict=InspectionVerdict.BLOCK,
                response_text=f"SECURITY_GATEWAY_DENIAL: {inspection.blocked_reason}",
                findings_count=len(inspection.findings),
                pii_masked_count=0,
                model_id=request.model_id,
                latency_ms=latency,
                audit_id=audit_id,
            )

        # Route sanitized prompt to Bedrock
        raw_model_response = self._invoke_bedrock(inspection.sanitized_prompt, request.model_id)

        # Inspect model output for credential or secret leaks (LLM02)
        sanitized_output, output_pii, output_findings = self.pii_redactor.redact(raw_model_response)
        if output_pii:
            inspection.findings.append(
                SecurityFinding(
                    category=ThreatCategory.OUTPUT_SECRET_LEAK,
                    severity=ThreatSeverity.HIGH,
                    rule_name="MODEL_OUTPUT_SECRET_EXPOSURE",
                    description="Model attempted to output sensitive PII/secrets; masked by egress guard.",
                    remediation_action="Masked output credentials before returning to caller.",
                )
            )

        latency = round((time.time() - start_time) * 1000, 2)
        total_pii = len(inspection.pii_redacted) + len(output_pii)

        return GatewayResponse(
            verdict=inspection.verdict,
            response_text=sanitized_output,
            findings_count=len(inspection.findings),
            pii_masked_count=total_pii,
            model_id=request.model_id,
            latency_ms=latency,
            audit_id=audit_id,
        )

    def _invoke_bedrock(self, prompt: str, model_id: str) -> str:
        """Invokes Amazon Bedrock Runtime API (or returns mocked safe response)."""
        if self.dry_run:
            # Deterministic, safe response for testing and dry-run
            return (
                f"Verified response from {model_id}: Processed enterprise request safely under Zero-Trust guardrails."
            )

        # In live deployment, use boto3 bedrock-runtime client
        return f"Response from live model {model_id} for prompt payload."
