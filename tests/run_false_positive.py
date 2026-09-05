from scanner.engine import scan_project

results = scan_project("tests")

for result in results:
    if "false_positive_test.py" in result.get("file", ""):
        print(result)