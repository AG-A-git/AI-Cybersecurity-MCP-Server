from scanner.evidence import build_evidence


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