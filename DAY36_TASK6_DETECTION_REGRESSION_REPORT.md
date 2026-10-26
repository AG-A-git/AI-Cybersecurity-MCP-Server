# Day 36 — Task 6: Detection Regression Suite

## Environment
- Branch: `member2-scanner`
- Python: 3.11.2
- Platform: Windows
- Test runner: pytest 9.1.1

## Full Regression Results
- Tests collected and executed: 257
- Passed: 256
- Skipped: 1
- Failed: 0
- Runtime: 16.67 seconds
- Exit code: 0

## Focused Regression Results
- Detection tests: 48 passed in 2.30 seconds; exit code 0.
- Scanner, deduplication, parser, and project-scanning tests: 55 passed, 1 skipped, 1 warning in 5.86 seconds; exit code 0.
- Safe-input and false-positive tests: 40 passed in 2.03 seconds; exit code 0.

## Coverage Observations
The source search found explicit OWASP/CWE mappings for SQL injection, command injection, LDAP injection, XSS, SSRF, weak cryptography, sensitive data exposure, authentication/access control, hardcoded credentials, insecure deserialization, and security misconfiguration.

These mappings demonstrate the presence of those rule categories, not exhaustive coverage of the OWASP Top 10.

## Exceptions and Limitations
- `test_scan_denies_symlink_escape` was skipped because symlink privileges were unavailable in the Windows environment (`WinError 1314`). This protection still requires verification in a suitable environment.
- Pytest emitted a `UserWarning` for a duplicate ZIP member named `app.py` in `test_zip_status_duplicate_member_names`. The test passed.
- No test failures were reported.

## Git Safety
- Branch: `member2-scanner`
- Initial status showed the branch ahead of `origin/member2-scanner` by 2 commits.
- Existing untracked files were preserved and not staged or deleted.
- No production code or test files were changed as part of this verification.

## Conclusion
The complete pytest suite passed with 256 passed, 1 skipped, and 0 failed. Regression verification succeeded with exit code 0, subject to the documented symlink-test limitation.
