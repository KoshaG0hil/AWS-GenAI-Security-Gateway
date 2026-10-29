"""OWASP LLM01: Prompt Injection & Adversarial Jailbreak Detector."""

import re
from typing import List

from ..core.config import SecurityFinding, ThreatCategory, ThreatSeverity


class PromptInjectionDetector:
    """Detects direct and indirect prompt injection attempts, system prompt leaks, and jailbreaks."""

    JAILBREAK_PATTERNS = [
        (
            r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|safety|security)?\s*(instructions|directions|rules|prompts|filters|guardrails)",
            "DIRECT_INSTRUCTION_OVERRIDE",
            "Attempts to wipe system guardrails and instruction boundaries.",
        ),
        (
            r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(DAN|do\s+anything\s+now|developer\s+mode|unrestricted\s+ai|jailbroken)",
            "JAILBREAK_PERSONA_OVERRIDE",
            "Attempts to force LLM into unrestricted DAN/developer persona.",
        ),
        (
            r"(?i)\b(reveal|output|display|show|repeat|dump)\s+(the\s+)?(system\s+prompt|initial\s+instructions|secret|api\s*keys?|internal\s+guidelines)",
            "SYSTEM_PROMPT_EXFILTRATION",
            "Attempts to extract proprietary system prompts and confidential configuration.",
        ),
        (
            r"(?i)\b(sudo|admin\s+mode|root\s+access|bypass\s+(safety|security)?\s*(filter|rules|guardrails)|disable\s+(safety|security)?\s*guardrails)\b",
            "GUARDRAIL_BYPASS_EXPLOIT",
            "Attempts to invoke elevated administrative commands or disable safety filters.",
        ),
    ]

    def inspect(self, prompt: str) -> List[SecurityFinding]:
        """Scans prompt string against compiled adversarial heuristic patterns."""
        findings: List[SecurityFinding] = []

        for pattern, rule_name, description in self.JAILBREAK_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                findings.append(
                    SecurityFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        severity=ThreatSeverity.CRITICAL,
                        rule_name=rule_name,
                        description=description,
                        matched_pattern=match.group(0),
                        remediation_action="Immediate request termination (HTTP 403 Forbidden).",
                    )
                )

        return findings
