# Day 36 — Task 8: Finding Quality Verification

## Objective
Verify finding severity, source location, confidence, schema validity, deduplication, and evidence quality.

## Verification Results

### Verified
- Full test suite: 279 passed, 1 skipped (22.92 seconds).
- Focused Task 8 and related finding-quality tests: 34 passed (3.81 seconds).
- SQL location tests verify the reported file, line number, and matching source line.
- Tested findings satisfy the finding schema, including severity, positive line numbers, and confidence bounds.
- Deduplication tests verify that higher-confidence findings win and equal-confidence ties prefer greater severity.
- SQL tests cover vulnerable queries, safe cases, f-strings, formatting, parameterized queries, and dynamic queries with unconfirmed sources.
- `git diff --check` reported no whitespace errors; Git displayed an LF-to-CRLF line-ending warning for `tests/test_sql_accuracy.py`.

### Not Fully Verified
- Severity consistency across all active detectors has not been comprehensively tested.
- Structured evidence coverage across all active detectors has not been comprehensively verified. A new focused test verifies structured evidence on SQL findings and confirms that evidence remains optional in the finding schema.
- Description and remediation completeness are not comprehensively tested.
- The tracked MCP analysis function's compatibility with canonical scanner finding fields needs coordination with its owner. No changes were made to `mcp_server.py`.

## Observations
A test confirms that a dynamic SQL query with an unconfirmed user-input source is currently reported as Critical with 85% confidence. This is observed behavior, not proof that the severity policy is appropriate in every context.

## Conclusion
The current regression suite passes. The tested finding-quality behaviors are verified within their test scope. The outstanding items above remain limitations and should not be interpreted as confirmed defects.
