from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


def main():
    scanner_result = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    vulnerability = VulnerabilityInput(**scanner_result)

    result = analyze_vulnerability(vulnerability)

    print("\n===== AI ANALYSIS =====")
    print(result)


if __name__ == "__main__":
    main()
