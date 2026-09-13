import json

from scanner.engine import scan_project
from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


PROJECT_PATH = "./pipeline_test_files"


print("\n======================================")
print("TASK 12: FINAL SECURITY REPORT")
print("======================================")


# ======================================================
# STEP 1: Scan project
# ======================================================

print("\n[1] Scanning project...")

scanner_results = scan_project(PROJECT_PATH)

print(
    f"Findings detected: {len(scanner_results)}"
)


# ======================================================
# STEP 2: Analyze findings with AI
# ======================================================

print("\n[2] Running AI analysis...")

results = []

for finding in scanner_results:

    print(
        f"Analyzing: "
        f"{finding['file']}:{finding['line']} "
        f"- {finding['vulnerability']}"
    )

    try:

        vulnerability = VulnerabilityInput(
            **finding
        )

        result = analyze_vulnerability(
            vulnerability
        )

        results.append(result)

    except Exception as exc:

        print(
            f"Analysis failed: {exc}"
        )


# ======================================================
# STEP 3: Build final report
# ======================================================

report = {
    "project": PROJECT_PATH,
    "total_findings": len(results),
    "findings": results
}


# ======================================================
# STEP 4: Display report
# ======================================================

print("\n======================================")
print("FINAL SECURITY REPORT")
print("======================================")

print(
    json.dumps(
        report,
        indent=2
    )
)


# ======================================================
# STEP 5: Save report
# ======================================================

output_file = "final_security_report.json"

with open(
    output_file,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=2
    )


print("\n======================================")
print("REPORT COMPLETE")
print("======================================")

print(
    f"Report saved to: {output_file}"
)