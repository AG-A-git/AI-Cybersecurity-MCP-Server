import json

from scanner.engine import scan_project

from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# STEP 1: Scan the project
# ======================================================

PROJECT_PATH = "./pipeline_test_files"


print("\n======================================")
print("STEP 1: RUNNING MEMBER 2 SCANNER")
print("======================================")

scanner_results = scan_project(PROJECT_PATH)


print(
    f"\nScanner findings detected: "
    f"{len(scanner_results)}"
)


# ======================================================
# STEP 2: Display scanner findings
# ======================================================

print("\n======================================")
print("STEP 2: SCANNER JSON")
print("======================================")

for finding in scanner_results:

    print(
        json.dumps(
            finding,
            indent=2
        )
    )


# ======================================================
# STEP 3: Send findings to AI
# ======================================================

print("\n======================================")
print("STEP 3: AI ANALYSIS")
print("======================================")


ai_results = []


for index, scanner_result in enumerate(
    scanner_results,
    start=1
):

    print(
        f"\nAnalyzing finding {index}..."
    )

    try:

        # --------------------------------------------------
        # Convert scanner result to AI input model
        # --------------------------------------------------

        vulnerability = VulnerabilityInput(
            **scanner_result
        )

        # --------------------------------------------------
        # Run AI analysis
        # --------------------------------------------------

        result = analyze_vulnerability(
            vulnerability
        )

        ai_results.append(
            result
        )

    except Exception as e:

        print(
            f"AI analysis failed: {e}"
        )


# ======================================================
# STEP 4: Display structured AI results
# ======================================================

print("\n======================================")
print("STEP 4: STRUCTURED AI RESULTS")
print("======================================")


print(
    json.dumps(
        ai_results,
        indent=2
    )
)


# ======================================================
# STEP 5: Save results
# ======================================================

output_file = "ai_pipeline_results.json"


with open(
    output_file,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        ai_results,
        file,
        indent=2
    )


print("\n======================================")
print("PIPELINE COMPLETE")
print("======================================")

print(
    f"\nAI results saved to: "
    f"{output_file}"
)