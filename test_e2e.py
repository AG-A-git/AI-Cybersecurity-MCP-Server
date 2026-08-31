from mcp_server.tools import run_ai_analysis


def print_result(title, result):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)

    print("\nSeverity:")
    print(result["severity"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nOWASP:")
    print(result["owasp"])

    print("\nCWE:")
    print(result["cwe"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nRecommendation:")
    print(result["recommendation"])


# --------------------------------------------------
# Test 1: SQL Injection
# --------------------------------------------------

sql_injection = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}

sql_result = run_ai_analysis(sql_injection)

print_result(
    "TEST 1 - SQL INJECTION",
    sql_result
)


# --------------------------------------------------
# Test 2: XSS
# --------------------------------------------------

xss = {
    "file": "profile.html",
    "line": 15,
    "vulnerability": "XSS",
    "severity": "High",
    "confidence": 91,
    "code": "element.innerHTML = user_input"
}

xss_result = run_ai_analysis(xss)

print_result(
    "TEST 2 - XSS",
    xss_result
)


# --------------------------------------------------
# Test 3: Hardcoded Credentials
# --------------------------------------------------

hardcoded_credentials = {
    "file": "config.py",
    "line": 8,
    "vulnerability": "Hardcoded Credentials",
    "severity": "High",
    "confidence": 93,
    "code": "password = 'admin123'"
}

credentials_result = run_ai_analysis(
    hardcoded_credentials
)

print_result(
    "TEST 3 - HARDCODED CREDENTIALS",
    credentials_result
)