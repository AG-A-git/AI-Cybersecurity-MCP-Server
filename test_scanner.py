from scanner.parser import read_file
from utils import run_all_rules
from scanner.severity import get_severity
import json


file_path = "test_files/sql_test.py"


# 1. FILE READING
code = read_file(file_path)

if code:
    print("✅ 1. File content is read successfully")
else:
    print("❌ 1. File reading failed")


# 2. RULE EXECUTION
results = run_all_rules(file_path, code)

if results:
    print("✅ 2. SQL Injection rule executed successfully")
else:
    print("❌ 2. No vulnerability detected")


# 3. SEVERITY ASSIGNMENT
if results and results[0]["severity"] == get_severity("SQL Injection"):
    print("✅ 3. Severity assigned successfully")
    print("   Severity:", results[0]["severity"])
else:
    print("❌ 3. Severity assignment failed")


# 4. JSON GENERATION
json_output = json.dumps(results, indent=4)

print("✅ 4. JSON generated successfully")
print("\nFinal JSON Report:")
print(json_output)