from ai.llm import normalize_ai_response
from ai.models import VulnerabilityInput


def make_vulnerability():
    return VulnerabilityInput(
        file="example.py",
        line=10,
        vulnerability="SQL Injection",
        severity="High",
        confidence=95.0,
        code="query = 'SELECT * FROM users WHERE id=' + user_input",
    )


def test_valid_structured_ai_response():
    vulnerability = make_vulnerability()

    response = normalize_ai_response(
        {
            "explanation": (
                "User-controlled input can affect a database query."
            ),
            "recommendation": (
                "Use parameterized queries."
            ),
            "owasp": "A03:2021 Injection",
            "cwe": "CWE-89",
        },
        vulnerability,
        expected_owasp="A03:2021 Injection",
        expected_cwe="CWE-89",
    )

    assert response.explanation
    assert response.recommendation
    assert response.owasp == "A03:2021 Injection"
    assert response.cwe == "CWE-89"


def test_ai_cannot_override_owasp_or_cwe():
    vulnerability = make_vulnerability()

    response = normalize_ai_response(
        {
            "explanation": "SQL injection vulnerability.",
            "recommendation": "Use parameterized queries.",
            "owasp": "FAKE CATEGORY",
            "cwe": "CWE-999",
        },
        vulnerability,
        expected_owasp="A03:2021 Injection",
        expected_cwe="CWE-89",
    )

    assert response.owasp == "A03:2021 Injection"
    assert response.cwe == "CWE-89"


def test_missing_explanation_is_rejected():
    vulnerability = make_vulnerability()

    try:
        normalize_ai_response(
            {
                "recommendation": "Use parameterized queries.",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
            },
            vulnerability,
            expected_owasp="A03:2021 Injection",
            expected_cwe="CWE-89",
        )

        assert False, "Expected ValueError"

    except ValueError as exc:
        assert "explanation" in str(exc)


def test_missing_recommendation_is_rejected():
    vulnerability = make_vulnerability()

    try:
        normalize_ai_response(
            {
                "explanation": "SQL injection vulnerability.",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
            },
            vulnerability,
            expected_owasp="A03:2021 Injection",
            expected_cwe="CWE-89",
        )

        assert False, "Expected ValueError"

    except ValueError as exc:
        assert "recommendation" in str(exc)