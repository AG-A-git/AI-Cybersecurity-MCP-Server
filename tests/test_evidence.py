from scanner.evidence import build_evidence, build_explainability


def test_build_evidence():
    evidence = build_evidence(
        source='request.args.get("username")',
        source_line=1,
        tainted_variable="username",
        sink="cursor.execute(query)",
        sink_line=3,
        reason="User-controlled input reaches a SQL execution sink.",
    )

    assert evidence["source"] == 'request.args.get("username")'
    assert evidence["source_line"] == 1
    assert evidence["tainted_variable"] == "username"
    assert evidence["sink"] == "cursor.execute(query)"
    assert evidence["sink_line"] == 3
    assert evidence["reason"] == (
        "User-controlled input reaches a SQL execution sink."
    )


def test_build_evidence_omits_missing_values():
    evidence = build_evidence(
        tainted_variable="username",
    )

    assert evidence == {
        "tainted_variable": "username"
    }
def test_build_evidence_with_context_and_quality():
    evidence = build_evidence(
        source="request.args.get('url')",
        source_line=2,
        sink="requests.get(url)",
        sink_line=3,
        context={
            "source": {"line": 2},
            "sink": {"line": 3},
        },
        quality="high",
    )

    assert evidence["context"]["source"]["line"] == 2
    assert evidence["context"]["sink"]["line"] == 3
    assert evidence["quality"] == "high"


def test_build_evidence_preserves_existing_fields():
    evidence = build_evidence(
        source="user_input",
        source_line=1,
        tainted_variable="url",
        sink="requests.get(url)",
        sink_line=2,
        reason="User-controlled URL reaches a network sink.",
        quality="medium",
    )

    assert evidence["source"] == "user_input"
    assert evidence["source_line"] == 1
    assert evidence["tainted_variable"] == "url"
    assert evidence["sink"] == "requests.get(url)"
    assert evidence["sink_line"] == 2
    assert evidence["reason"] == (
        "User-controlled URL reaches a network sink."
    )
    assert evidence["quality"] == "medium"
def test_build_explainability():
    explanation = build_explainability(
        reason="User input reaches SQL sink.",
        source_type="http_request",
        sink_type="sql",
        data_flow="request -> variable -> SQL sink",
        confidence_basis=[
            "user-controlled source",
            "dynamic SQL construction",
        ],
    )

    assert explanation["reason"] == "User input reaches SQL sink."
    assert explanation["source_type"] == "http_request"
    assert explanation["sink_type"] == "sql"
    assert explanation["data_flow"] == (
        "request -> variable -> SQL sink"
    )
    assert explanation["confidence_basis"] == [
        "user-controlled source",
        "dynamic SQL construction",
    ]


def test_build_explainability_omits_missing_values():
    explanation = build_explainability(
        reason="Potential SQL injection."
    )

    assert explanation == {
        "reason": "Potential SQL injection."
    }
