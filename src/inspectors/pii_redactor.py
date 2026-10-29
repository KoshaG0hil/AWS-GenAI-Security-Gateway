"""OWASP LLM02: Sensitive Data & PII Masking Engine."""

import re
from typing import List, Tuple

from ..core.config import PIIMatch, SecurityFinding, ThreatCategory, ThreatSeverity


class PIIRedactor:
    """Detects, extracts, and tokenizes PII, credentials, and financial identifiers."""

    PII_RULES = [
        (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "PII_US_SSN",
            "[REDACTED_PII_SSN]",
            ThreatSeverity.HIGH,
        ),
        (
            r"\b(AKIA[0-9A-Z]{16})\b",
            "CREDENTIAL_AWS_ACCESS_KEY",
            "[REDACTED_AWS_KEY]",
            ThreatSeverity.CRITICAL,
        ),
        (
            r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            "FINANCIAL_CREDIT_CARD",
            "[REDACTED_CREDIT_CARD]",
            ThreatSeverity.CRITICAL,
        ),
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "PII_EMAIL_ADDRESS",
            "[REDACTED_EMAIL]",
            ThreatSeverity.MEDIUM,
        ),
        (
            r"\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36})\b",
            "CREDENTIAL_API_SECRET",
            "[REDACTED_API_SECRET]",
            ThreatSeverity.CRITICAL,
        ),
    ]

    def redact(self, text: str) -> Tuple[str, List[PIIMatch], List[SecurityFinding]]:
        """Masks detected PII in text and returns sanitized text along with metadata."""
        sanitized = text
        matches: List[PIIMatch] = []
        findings: List[SecurityFinding] = []

        for pattern, pii_type, placeholder, severity in self.PII_RULES:
            for match in re.finditer(pattern, sanitized):
                original = match.group(0)
                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        original_text=original,
                        masked_placeholder=placeholder,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    )
                )
                findings.append(
                    SecurityFinding(
                        category=ThreatCategory.SENSITIVE_DATA_PII,
                        severity=severity,
                        rule_name=f"RULE_{pii_type}",
                        description=f"Detected sensitive {pii_type} in prompt payload.",
                        matched_pattern=original[:4] + "****",
                        remediation_action=f"Tokenized to placeholder {placeholder}.",
                    )
                )

            sanitized = re.sub(pattern, placeholder, sanitized)

        return sanitized, matches, findings
