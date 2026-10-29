"""Data Models and Constants for GenAI Security Gateway (OWASP Top 10 for LLMs)."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "LLM01_PROMPT_INJECTION"
    SENSITIVE_DATA_PII = "LLM02_SENSITIVE_DATA_LEAK"
    TOKEN_EXHAUSTION = "LLM04_MODEL_DOS_TOKEN_SPIKE"
    UNSAFE_TOOL_CALL = "LLM06_EXCESSIVE_AGENCY"
    OUTPUT_SECRET_LEAK = "LLM02_OUTPUT_CREDENTIAL_LEAK"


class ThreatSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InspectionVerdict(str, Enum):
    ALLOW = "ALLOW"
    MASK_AND_ALLOW = "MASK_AND_ALLOW"
    BLOCK = "BLOCK"


class SecurityFinding(BaseModel):
    """Represents a threat finding detected during prompt or output inspection."""

    category: ThreatCategory
    severity: ThreatSeverity
    rule_name: str
    description: str
    matched_pattern: Optional[str] = None
    remediation_action: str


class PIIMatch(BaseModel):
    """Represents a detected PII or credential token."""

    pii_type: str
    original_text: str
    masked_placeholder: str
    start_pos: int
    end_pos: int


class InferenceRequest(BaseModel):
    """Inbound client inference payload targeted for Amazon Bedrock / SageMaker."""

    tenant_id: str = "tenant-fintech-prod"
    model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0"
    prompt: str
    max_tokens: int = 1000
    temperature: float = 0.7
    metadata: Dict[str, str] = Field(default_factory=dict)


class InspectionResult(BaseModel):
    """Outcome of the multi-stage gateway security inspection."""

    verdict: InspectionVerdict
    sanitized_prompt: str
    findings: List[SecurityFinding] = Field(default_factory=list)
    pii_redacted: List[PIIMatch] = Field(default_factory=list)
    tokens_consumed: int = 0
    blocked_reason: Optional[str] = None


class GatewayResponse(BaseModel):
    """Final response returned to the client application."""

    verdict: InspectionVerdict
    response_text: Optional[str] = None
    findings_count: int = 0
    pii_masked_count: int = 0
    model_id: str
    latency_ms: float = 0.0
    audit_id: str
