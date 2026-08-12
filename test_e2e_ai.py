from mcp_server.tools import analyze_scan


findings = [
    {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)"
    },
    {
        "file": "script.js",
        "line": 15,
        "vulnerability": "XSS",
        "severity": "High",
        "confidence": 90,
        "code": "element.innerHTML=data"
    },
    {
        "file": "config.py",
        "line": 8,
        "vulnerability": "Hardcoded Credentials",
        "severity": "High",
        "confidence": 88,
        "code": "PASSWORD = 'admin123'"
    },
    {
        "file": "crypto.py",
        "line": 31,
        "vulnerability": "Weak Cryptography",
        "severity": "Medium",
        "confidence": 85,
        "code": "hashlib.md5(password.encode())"
    }
]


print("\n==============================")
print("END-TO-END AI SECURITY TEST")
print("==============================")


try:

    results = analyze_scan(findings)

    print(f"\nTotal findings analyzed: {len(results)}")

    for index, result in enumerate(results, start=1):

        print(f"\n--- Finding {index} ---")

        print("File:", result["file"])
        print("Line:", result["line"])
        print("Vulnerability:", result["vulnerability"])
        print("Severity:", result["severity"])
        print("Confidence:", result["confidence"])
        print("Risk Score:", result["risk_score"])
        print("OWASP:", result["owasp"])
        print("CWE:", result["cwe"])

        print("\nExplanation:")
        print(result["explanation"])

        print("\nImpact:")
        print(result["impact"])

        print("\nRecommendation:")
        print(result["recommendation"])

except Exception as error:

    print("\nE2E TEST FAILED")
    print(type(error).__name__)
    print(error)