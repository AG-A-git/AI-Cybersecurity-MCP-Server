from scanner.scan import scan_file


def test_task4_multiline_parameterized_query_is_not_flagged(tmp_path):
    source = tmp_path / "task4_safe_sql.py"
    source.write_text(
        'username = input("Username: ")\n'
        'cursor.execute(\n'
        '    "SELECT * FROM users WHERE username = ?",\n'
        '    (username,)\n'
        ')\n',
        encoding="utf-8",
    )

    findings = scan_file(str(source))

    assert not any(
        f["vulnerability_type"] == "SQL Injection"
        for f in findings
    )


def test_task4_untrusted_sql_concatenation_is_flagged(tmp_path):
    source = tmp_path / "task4_unsafe_sql.py"
    source.write_text(
        'username = input("Username: ")\n'
        'query = "SELECT * FROM users WHERE username = \'" + username + "\'"\n'
        'cursor.execute(query)\n',
        encoding="utf-8",
    )

    findings = scan_file(str(source))

    assert any(
        f["vulnerability_type"] == "SQL Injection"
        for f in findings
    )
