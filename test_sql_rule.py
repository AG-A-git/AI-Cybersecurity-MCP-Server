from scanner.parser import read_file
from scanner.rules.sql import detect_sql_injection
file_path = "test_files/sql_test.py"

code = read_file(file_path)

results = detect_sql_injection(file_path, code)

for result in results:
    print(result)