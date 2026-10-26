# Day 36 — Task 3: Member 2 Negative-Test Verification

## Objective
Verify safe-code behavior using existing negative tests and dedicated SQL fixtures. No scanner rules were changed.

## Results

### Negative-test subset
Command:
`python -m pytest -q tests/test_sql_accuracy.py tests/test_xss.py tests/test_command.py tests/test_credentials_safe.py tests/test_crypto_safe.py tests/test_insecure_deserialization.py tests/test_ldap.py tests/test_authentication_access_control.py tests/test_security_misconfiguration.py tests/test_ssrf.py`

Result: **79 passed in 3.16 seconds**.

### Safe parameterized SQL
Fixture: `tests/fixtures/negative/sql_parameterized_safe.py`

Scanner output: `[]`

Result: No findings for this tested parameterized query.

### Unsafe SQL concatenation
Fixture: `tests/fixtures/negative/sql_concatenation_unsafe.py`

Result: One SQL Injection finding at line 4; Critical severity, confidence 90, CWE-89, OWASP A03: Injection. The reported source was `username`, and the sink was SQL statement construction.

### Full test suite
Command: `python -m pytest -q tests/`

Result: **300 passed, 1 skipped in 18.76 seconds**.

## Assessment
The tested parameterized SQL fixture produced no findings, while the unsafe concatenation fixture produced a finding at the expected location. The selected negative-test subset and full suite completed successfully.

These results establish observed behavior for the tested cases only; they do not prove complete detection or negative-test coverage for every vulnerability category.

## Limitations and follow-up
- Record any additional false positives observed during further safe-fixture testing.
- Verify category support against actual tests and scanner behavior before claiming full coverage.
- The full-suite result does not establish complete security-category coverage.

## Final status
**Task 3 verification evidence collected.** SQL safe/unsafe comparison behaved as expected. Full suite: 300 passed, 1 skipped. No scanner rules changed.
