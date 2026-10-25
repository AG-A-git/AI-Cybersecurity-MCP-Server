import json
import os

from scanner.engine import scan_project
from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


PROJECT_PATH = "./pipeline_test_files"
OUTPUT_FILE = "end_to_end_report.json"


print("\n======================================")
print("TASK 15: END-TO-END SECURITY TEST")
print("======================================")


# ======================================================
# STEP 1: SCAN PROJECT
# ======================================================

print("\nSTEP 1: SCANNING PROJECT")

try:
    scanner_results = scan_project(PROJECT_PATH)

    print(
        f"Scanner findings detected: {len(scanner_results)}"
    )

except Exception as e:
    print(f"Scanner failed: {e}")
    raise


# ======================================================
# STEP 2: AI ANALYSIS
# ======================================================

print("\nSTEP 2: AI ANALYSIS")

ai_results = []


for index, scanner_result in enumerate(
    scanner_results,
    start=1
):

    print(
        f"\nAnalyzing finding {index}: "
        f"{scanner_result['vulnerability']}"
    )

    try:

        vulnerability = VulnerabilityInput(
            **scanner_result
        )

        result = analyze_vulnerability(
            vulnerability
        )

        ai_results.append(result)

        print(
            f"AI Status: {result.get('ai_status')}"
        )

    except Exception as e:

        print(
            f"AI analysis failed: {e}"
        )


# ======================================================
# STEP 3: BUILD FINAL REPORT
# ======================================================

print("\nSTEP 3: BUILDING FINAL REPORT")

report = {
    "total_findings": len(ai_results),
    "findings": ai_results
}


# ======================================================
# STEP 4: SAVE REPORT
# ======================================================

print("\nSTEP 4: SAVING REPORT")

try:

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2
        )

    print(
        f"Report saved to: {os.path.abspath(OUTPUT_FILE)}"
    )

except Exception as e:

    print(
        f"Failed to save report: {e}"
    )

    raise


# ======================================================
# STEP 5: VERIFY REPORT
# ======================================================

print("\nSTEP 5: VERIFYING REPORT")

if not os.path.exists(OUTPUT_FILE):

    print("ERROR: Report file was not created.")

    raise SystemExit(1)


with open(
    OUTPUT_FILE,
    "r",
    encoding="utf-8"
) as file:

    saved_report = json.load(file)


print(
    f"Total findings in report: "
    f"{saved_report['total_findings']}"
)

print(
    f"Findings stored: "
    f"{len(saved_report['findings'])}"
)


# ======================================================
# FINAL RESULT
# ======================================================

print("\n======================================")

if (
    saved_report["total_findings"]
    == len(saved_report["findings"])
):

    print("TASK 15: PASSED")

else:

    print("TASK 15: FAILED")

print("======================================")