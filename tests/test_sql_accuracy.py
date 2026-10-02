from scanner.rules.sql import scan_sql


def test_sql_vulnerable():
    findings = scan_sql(
        "scanner/test_files/sql_accuracy_test.py"
    )

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings


def test_sql_safe():
    findings = scan_sql(
        "test_files/safe/sql_safe.py"
    )

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert not sql_findings


def test_sql_detects_multi_hop_tainted_variable(tmp_path):
    test_file = tmp_path / "sql_multi_hop.py"

    test_file.write_text(
        '''user_command = request.args.get("username")
user = user_command
query = "SELECT * FROM users WHERE name='" + user
''',
        encoding="utf-8",
    )

    findings = scan_sql(str(test_file))

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings
    assert sql_findings[0]["confidence"] == 90

def test_sql_detects_concatenation_inside_execute(tmp_path):
    test_file = tmp_path / "sql_execute.py"

    test_file.write_text(
        '''user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
''',
        encoding="utf-8",
    )

    findings = scan_sql(str(test_file))

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings

def test_sql_helper_built_query_not_detected(tmp_path):
    test_file = tmp_path / "sql_helper_safe.py"

    test_file.write_text(
        '''def build_query():
    return "SELECT * FROM users"

query = build_query()
''',
        encoding="utf-8",
    )

    findings = scan_sql(str(test_file))

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert not sql_findings

def test_sql_multi_hop_username_gets_tracked_confidence(tmp_path):
    test_file = tmp_path / "sql_username_flow.py"

    test_file.write_text(
        '''username = request.args.get("username")
user = username
query = "SELECT * FROM users WHERE name='" + user
''',
        encoding="utf-8",
    )

    findings = scan_sql(str(test_file))

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings
    assert sql_findings[0]["confidence"] == 90
