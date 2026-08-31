from ai.analysis import analyze_vulnerabilities


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
    }
]


results = analyze_vulnerabilities(findings)


print("\n==============================")
print("BATCH AI VULNERABILITY ANALYSIS")
print("==============================")


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
    print("Explanation:", result["explanation"])
    print("Impact:", result["impact"])
    print("Recommendation:", result["recommendation"])