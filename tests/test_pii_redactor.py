"""Tests for Sensitive Data & PII Redactor."""

from src.inspectors.pii_redactor import PIIRedactor


def test_redact_ssn():
    redactor = PIIRedactor()
    text = "The user SSN is 123-45-6789."
    sanitized, matches, findings = redactor.redact(text)

    assert "[REDACTED_PII_SSN]" in sanitized
    assert "123-45-6789" not in sanitized
    assert len(matches) == 1
    assert matches[0].pii_type == "PII_US_SSN"


def test_redact_aws_access_key():
    redactor = PIIRedactor()
    text = "Deploying with key AKIA1234567890ABCDEF in us-east-1."
    sanitized, matches, findings = redactor.redact(text)

    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "AKIA1234567890ABCDEF" not in sanitized
    assert len(matches) == 1


def test_redact_multiple_pii_types():
    redactor = PIIRedactor()
    text = "Contact admin@corp.com with SSN 999-88-7777 regarding card 4111-2222-3333-4444."
    sanitized, matches, _ = redactor.redact(text)

    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_PII_SSN]" in sanitized
    assert "[REDACTED_CREDIT_CARD]" in sanitized
    assert len(matches) == 3
