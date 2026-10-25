# MCP Report Field Mapping Verification

## Objective
Verify canonical finding fields, legacy field normalization, and canonical field precedence in the tracked MCP Markdown report.

## Environment
- Operating system: Windows
- Python: 3.11.2
- pytest: 9.1.1
- Branch: member2-scanner

## Test Command
`python -m pytest -v tests/test_tracked_mcp_report.py`

## Results
- `test_tracked_mcp_markdown_report_uses_canonical_finding_fields` — PASSED
- `test_legacy_finding_fields_are_normalized` — PASSED
- `test_canonical_fields_take_precedence` — PASSED

**Summary:** 3 passed in 2.34 seconds; 0 failures.

## Conclusion
All three targeted tests passed. The tested cases verify that the report handles canonical finding fields, normalizes legacy field names, and prioritizes canonical values when both canonical and legacy fields are present.

This result applies to the tested cases and does not establish full MCP integration correctness.

## Repository Safety
Unrelated untracked files were not included in this verification and must be preserved.
