# Day 36 Task 13 — Final Regression Test Report

## Environment
- OS: Windows
- Python: 3.11.2
- pytest: 9.1.1
- Branch: member2-scanner

## Full Regression Suite
Command:
`python -m pytest -v`

Result:
- Collected: 264 tests
- Passed: 263
- Skipped: 1
- Failed: 0
- Warnings: 1
- Runtime: 14.91 seconds

## Skip and Warning
- `test_scan_denies_symlink_escape` was skipped because symlink capability was unavailable in the Windows environment (`WinError 1314`).
- `test_zip_status_duplicate_member_names` emitted a duplicate ZIP member warning for `app.py`, as expected from the duplicate-member test case.

## Additional Test Groups
- Core scanner/schema/evidence/confidence: 26 passed
- Detection and safe-input: 66 passed
- Persistence/state/project/ZIP: 53 passed, 1 skipped, 1 warning
- MCP integration: 15 passed

These focused test groups overlap with the full suite; their counts must not be added to the full-suite total.

## Repository Checks
- `git status -sb`: branch remained `member2-scanner`, 10 commits ahead of origin; existing untracked files remained listed.
- `git diff --check`: no output, indicating no whitespace errors in the tracked diff.

## Scope and Limitations
- No implementation code was changed for this regression run.
- The Task 11 tool tests use the untracked `mcp_server_task11_working.py` working copy; their success does not independently establish identical behavior in the tracked `mcp_server.py`.
- The symlink-escape test could not be exercised in this Windows environment.
- This report records the tests and checks run; it does not claim production deployment or live external API verification.
