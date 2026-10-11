
from mcp_server.tools import run_ai_analysis


def print_result(title, result):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)

    for label, key in [
        ("Severity", "severity"),
        ("Risk Score", "risk_score"),
        ("OWASP", "owasp"),
        ("CWE", "cwe"),
        ("Explanation", "explanation"),
        ("Recommendation", "recommendation"),
    ]:
        print(f"\n{label}:")
        print(result[key])


def main():
    sql_injection = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    xss = {
        "file": "profile.html",
        "line": 15,
        "vulnerability": "XSS",
        "severity": "High",
        "confidence": 91,
        "code": "element.innerHTML = user_input",
    }

    hardcoded_credentials = {
        "file": "config.py",
        "line": 8,
        "vulnerability": "Hardcoded Credentials",
        "severity": "High",
        "confidence": 93,
        "code": "password = 'admin123'",
    }

    scenarios = [
        ("TEST 1 - SQL INJECTION", sql_injection),
        ("TEST 2 - XSS", xss),
        ("TEST 3 - HARDCODED CREDENTIALS", hardcoded_credentials),
    ]

    for title, finding in scenarios:
        result = run_ai_analysis(finding)
        print_result(title, result)


if __name__ == "__main__":
    main()
