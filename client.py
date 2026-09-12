import requests
import json


SERVER_URL = "http://127.0.0.1:8000"


def scan_project(project_path="."):
    response = requests.post(
        f"{SERVER_URL}/scan",
        json={
            "project_path": project_path
        },
        timeout=60
    )

    response.raise_for_status()
    return response.json()


def get_scan_results(scan_id):
    response = requests.get(
        f"{SERVER_URL}/scan/{scan_id}",
        timeout=30
    )

    response.raise_for_status()
    return response.json()


def generate_report(scan_id):
    response = requests.post(
        f"{SERVER_URL}/report",
        json={
            "scan_id": scan_id,
            "format": "json"
        },
        timeout=30
    )

    response.raise_for_status()
    return response.json()


def main():
    print("=" * 60)
    print("AI CYBERSECURITY MCP CLIENT")
    print("=" * 60)

    print("\n[1] Starting project scan...")

    scan = scan_project(".")

    print("\nScan status:", scan.get("status"))
    print("Scan ID:", scan.get("scan_id"))
    print("Total findings:", scan.get("total_findings"))

    scan_id = scan.get("scan_id")

    if not scan_id:
        print("ERROR: Server did not return a scan ID.")
        return

    print("\n[2] Getting scan results...")

    results = get_scan_results(scan_id)

    print("Results status:", results.get("status"))

    findings = results.get("findings", [])

    print("Findings returned:", len(findings))

    for index, finding in enumerate(findings, start=1):
        print("\n" + "-" * 60)
        print(f"Finding #{index}")
        print("-" * 60)

        print("File:", finding.get("file"))
        print("Line:", finding.get("line"))
        print("Vulnerability:", finding.get("vulnerability"))
        print("Severity:", finding.get("severity"))
        print("Confidence:", finding.get("confidence"))
        print("Risk Score:", finding.get("risk_score"))
        print("Risk Level:", finding.get("risk_level"))
        print("OWASP:", finding.get("owasp"))
        print("CWE:", finding.get("cwe"))

    print("\n[3] Generating report...")

    report = generate_report(scan_id)

    print("Report status:", report.get("status"))

    with open("client_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved as:")
    print("client_report.json")

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()