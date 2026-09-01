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
