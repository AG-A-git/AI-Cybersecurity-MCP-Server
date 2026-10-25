from ai.prompts import build_prompt


def test_build_prompt_accepts_canonical_scanner_fields():
    scanner_result = {
        "file_name": "src/login.py",
        "line_number": 22,
        "vulnerability_type": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    prompt = build_prompt(scanner_result)

    assert "Vulnerability: SQL Injection" in prompt
    assert "File: src/login.py" in prompt
    assert "Line: 22" in prompt
    assert "cursor.execute(query)" in prompt


def test_build_prompt_preserves_legacy_field_support():
    scanner_result = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    prompt = build_prompt(scanner_result)

    assert "Vulnerability: SQL Injection" in prompt
    assert "File: login.py" in prompt
    assert "Line: 22" in prompt
