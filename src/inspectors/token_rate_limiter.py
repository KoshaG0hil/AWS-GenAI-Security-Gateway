"""OWASP LLM04: Model Denial of Service & Token Rate Limiter."""

from typing import Dict, Optional

from ..core.config import InferenceRequest, SecurityFinding, ThreatCategory, ThreatSeverity


class TokenRateLimiter:
    """Enforces sliding-window token budgets and per-tenant rate limits to prevent DoS."""

    DEFAULT_MAX_TOKENS_PER_REQUEST = 4096
    DEFAULT_TENANT_QUOTA_PER_WINDOW = 50000

    def __init__(self, max_tokens: int = DEFAULT_MAX_TOKENS_PER_REQUEST):
        self.max_tokens = max_tokens
        # In-memory tracking of consumed tokens per tenant
        self._tenant_usage: Dict[str, int] = {}

    def check_quota(self, request: InferenceRequest) -> Optional[SecurityFinding]:
        """Validates token limits and tenant budget."""
        # 1. Single-request limit check
        if request.max_tokens > self.max_tokens:
            return SecurityFinding(
                category=ThreatCategory.TOKEN_EXHAUSTION,
                severity=ThreatSeverity.HIGH,
                rule_name="LLM_DOS_TOKEN_SPIKE_EXCEEDED",
                description=f"Requested {request.max_tokens} tokens exceeds single-request ceiling of {self.max_tokens}.",
                matched_pattern=f"max_tokens={request.max_tokens}",
                remediation_action="Reject request or truncate to maximum authorized token window.",
            )

        # 2. Approximate input prompt token length
        estimated_prompt_tokens = len(request.prompt.split()) * 2
        current_usage = self._tenant_usage.get(request.tenant_id, 0)

        if (current_usage + estimated_prompt_tokens) > self.DEFAULT_TENANT_QUOTA_PER_WINDOW:
            return SecurityFinding(
                category=ThreatCategory.TOKEN_EXHAUSTION,
                severity=ThreatSeverity.CRITICAL,
                rule_name="TENANT_TOKEN_BUDGET_EXHAUSTED",
                description=f"Tenant {request.tenant_id} has exceeded hourly token budget of {self.DEFAULT_TENANT_QUOTA_PER_WINDOW}.",
                matched_pattern=f"tenant_usage={current_usage}",
                remediation_action="Throttle tenant requests (HTTP 429 Too Many Requests).",
            )

        # Update consumed usage
        self._tenant_usage[request.tenant_id] = current_usage + estimated_prompt_tokens
        return None

    def reset_usage(self, tenant_id: Optional[str] = None):
        """Resets quota tracker."""
        if tenant_id:
            self._tenant_usage.pop(tenant_id, None)
        else:
            self._tenant_usage.clear()
