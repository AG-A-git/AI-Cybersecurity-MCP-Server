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

def test_detects_sql_injection_in_multiline_f_string(tmp_path):
    source_file = tmp_path / "multiline_sample.py"
    source_file.write_text(
        'query = f"""\n'
        '    SELECT * FROM users\n'
        '    WHERE name = {username}\n'
        '"""\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["file"] == "multiline_sample.py"
        and finding["vulnerability"] == "SQL Injection"
        for finding in findings
    )

def test_multiline_sql_detector_does_not_cross_string_boundaries(tmp_path):
    source_file = tmp_path / "separate_strings.py"
    source_file.write_text(
        'first = f"""SELECT * FROM users"""\n'
        'second = f"""ordinary text {username}"""\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert not any(
        finding["file"] == "separate_strings.py"
        and finding["vulnerability"] == "SQL Injection"
        for finding in findings
    )
