Task 4 — SQL Injection False Positive Investigation

1\. Objective



Investigate whether the scanner incorrectly reports SQL injection for parameterized SQL queries, compare safe and unsafe query patterns, and add regression tests.



2\. Source Code Inspected

scanner/rules/sql.py

scanner/rules/input\_validation.py

tests/test\_sql\_accuracy.py

tests/test\_central\_scanner.py



The SQL detection rule uses regular expressions to identify potentially unsafe SQL construction, including string concatenation, f-strings, and .format().



The input-validation rule uses Python AST analysis to recognize literal SQL queries with supported placeholders and separate parameter arguments. It accounts for multiline execution calls.



Supported placeholder styles include %s, ?, :name, $1, and %(name)s.



3\. Reproduction Results



Two temporary Python fixtures were scanned through the full scanner API.



Safe parameterized query

python

username = input("Username: ")

cursor.execute(

&#x20;   "SELECT \* FROM users WHERE username = ?",

&#x20;   (username,)

)





Actual result: No findings (\[]).



Unsafe string concatenation

python

username = input("Username: ")

query = "SELECT \* FROM users WHERE username = '" + username + "'"

cursor.execute(query)





Actual result: SQL Injection finding.



Severity: Critical

Confidence: 90

CWE: CWE-89

Reported source line: 2

Evidence: User-controlled username is concatenated into the SQL statement.

4\. Regression Tests Added



Created tests/test\_task4\_sql\_parameterization.py with two tests:



test\_task4\_multiline\_parameterized\_query\_is\_not\_flagged

test\_task4\_untrusted\_sql\_concatenation\_is\_flagged



Both tests passed.



5\. Test Evidence



Focused test command:



powershell

python -m pytest -v tests/test\_task4\_sql\_parameterization.py tests/test\_sql\_accuracy.py tests/test\_central\_scanner.py





Result: 17 passed in 1.31 seconds.



Additional earlier verification:



Combined SQL, input-validation, and file-handling tests: 26 passed.

Central scanner tests: 5 passed.

New Task 4 regression tests: 2 passed.

6\. Root-Cause Analysis



The inspected SQL rule uses line-based regular expressions for parameterized-query recognition, which may not recognize every valid multiline or driver-specific query pattern.



The input-validation rule uses AST-based call analysis and recognizes supported literal SQL queries with separate parameter arguments.



The controlled tests demonstrated that the scanner correctly distinguishes the tested safe parameterized query from the unsafe concatenation case.



However, the exact original reported finding was not provided, and the suspected false positive was not reproduced. Therefore, no confirmed root cause or scanner fix can be claimed.



7\. Conclusion



The tested parameterized query generated no SQL injection finding, while the unsafe control query was detected. Both new regression tests and all 17 tests in the final focused test run passed.



The verification demonstrates correct behavior for the tested cases. Further investigation of the original finding is required to establish whether a pre-existing false positive exists and identify its precise cause.

