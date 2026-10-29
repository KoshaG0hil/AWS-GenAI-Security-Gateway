"""Tests for OWASP LLM04 Token Rate Limiter."""

from src.core.config import InferenceRequest, ThreatCategory
from src.inspectors.token_rate_limiter import TokenRateLimiter


def test_request_within_limits():
    limiter = TokenRateLimiter(max_tokens=2048)
    req = InferenceRequest(
        tenant_id="tenant-alpha",
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        prompt="Analyze cloud spend trends for Q3.",
        max_tokens=1024,
    )
    finding = limiter.check_quota(req)
    assert finding is None


def test_single_request_token_spike_exceeded():
    limiter = TokenRateLimiter(max_tokens=1000)
    req = InferenceRequest(
        tenant_id="tenant-alpha",
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        prompt="Summarize documentation.",
        max_tokens=4000,
    )
    finding = limiter.check_quota(req)
    assert finding is not None
    assert finding.category == ThreatCategory.TOKEN_EXHAUSTION
    assert finding.rule_name == "LLM_DOS_TOKEN_SPIKE_EXCEEDED"


def test_tenant_hourly_quota_exhaustion():
    limiter = TokenRateLimiter(max_tokens=5000)
    # Artificially set usage near limit
    limiter._tenant_usage["tenant-beta"] = 49990

    req = InferenceRequest(
        tenant_id="tenant-beta",
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        prompt="A prompt with multiple words that will exceed the remaining ten token allowance easily.",
        max_tokens=1000,
    )
    finding = limiter.check_quota(req)
    assert finding is not None
    assert finding.rule_name == "TENANT_TOKEN_BUDGET_EXHAUSTED"


def test_reset_usage():
    limiter = TokenRateLimiter(max_tokens=2048)
    limiter._tenant_usage["tenant-gamma"] = 25000
    limiter.reset_usage("tenant-gamma")
    assert "tenant-gamma" not in limiter._tenant_usage
