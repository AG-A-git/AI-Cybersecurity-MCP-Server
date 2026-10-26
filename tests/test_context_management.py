from ai.llm import limit_code_context, normalize_vulnerability
from ai.models import VulnerabilityInput
from ai.config import MAX_CODE_LENGTH


def test_short_code_is_unchanged():
    code = "print('hello')"

    result = limit_code_context(code)

    assert result == code


def test_large_code_is_truncated():
    code = "A" * (MAX_CODE_LENGTH + 500)

    result = limit_code_context(code)

    assert len(result) > MAX_CODE_LENGTH
    assert "[CODE TRUNCATED FOR AI CONTEXT SAFETY]" in result


def test_beginning_of_large_code_is_preserved():
    code = "IMPORTANT_START\n" + (
        "A" * (MAX_CODE_LENGTH + 500)
    )

    result = limit_code_context(code)

    assert result.startswith("IMPORTANT_START")


def test_normalization_limits_code_size():
    vulnerability = VulnerabilityInput(
        file="test.py",
        line=10,
        vulnerability="SQL Injection",
        severity="High",
        confidence=90,
        code="A" * (MAX_CODE_LENGTH + 500),
    )

    normalized = normalize_vulnerability(
        vulnerability
    )

    assert "[CODE TRUNCATED FOR AI CONTEXT SAFETY]" in normalized.code