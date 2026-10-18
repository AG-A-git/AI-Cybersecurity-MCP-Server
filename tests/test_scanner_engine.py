from scanner.engine import scan_project


def test_detects_sql_injection_in_f_string(tmp_path):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        'query = f"SELECT * FROM users WHERE name = {username}"\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["file"] == "sample.py"
        and finding["line"] == 1
        and finding["vulnerability"] == "SQL Injection"
        for finding in findings
    )


def test_detects_sql_injection_in_string_concatenation(tmp_path):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["file"] == "sample.py"
        and finding["line"] == 1
        and finding["vulnerability"] == "SQL Injection"
        for finding in findings
    )
