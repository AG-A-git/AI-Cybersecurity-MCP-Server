import json


with open("client_report.json", "r", encoding="utf-8") as f:
    report = json.load(f)


scan_id = report.get("report", {}).get("scan_id")
findings = report.get("report", {}).get("findings", [])


print("=" * 70)
print("AI CYBERSECURITY SECURITY REPORT")
print("=" * 70)

print(f"\nScan ID: {scan_id}")
print(f"Total Findings: {len(findings)}")


severity_counts = {}

for finding in findings:
    severity = finding.get("severity", "Unknown")
    severity_counts[severity] = severity_counts.get(severity, 0) + 1


print("\nSEVERITY SUMMARY")
print("-" * 70)

for severity, count in severity_counts.items():
    print(f"{severity}: {count}")


print("\nVULNERABILITY FINDINGS")
print("-" * 70)

for i, finding in enumerate(findings, 1):

    print(f"\nFinding #{i}")

    print(f"File: {finding.get('file')}")
    print(f"Line: {finding.get('line')}")
    print(f"Vulnerability: {finding.get('vulnerability')}")
    print(f"Severity: {finding.get('severity')}")
    print(f"Confidence: {finding.get('confidence')}")
    print(f"Risk Score: {finding.get('risk_score')}")
    print(f"Risk Level: {finding.get('risk_level')}")
    print(f"OWASP: {finding.get('owasp')}")
    print(f"CWE: {finding.get('cwe')}")

    analysis = finding.get("ai_analysis", {})

    if isinstance(analysis, dict):
        print(f"Explanation: {analysis.get('explanation')}")
        print(f"Recommendation: {analysis.get('recommendation')}")


print("\n" + "=" * 70)
print("REPORT COMPLETE")
print("=" * 70)