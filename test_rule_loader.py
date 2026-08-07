from scanner.parser import read_file
from utils import run_all_rules


file_path = "test_files/sql_test.py"

code = read_file(file_path)

results = run_all_rules(file_path, code)


for finding in results:
    print(finding)