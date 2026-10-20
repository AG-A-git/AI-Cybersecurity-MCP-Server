# Day 36 — Task 12: Frontend Contract Verification

## Scope and limitations

This verification inspected the tracked scanner finding schema, persistence layer,
MCP server, integration tests, and `docs/scanner_api.md`.

No frontend source, package manifest, or clear production FastAPI/Flask route
implementation was found in the current branch during this inspection. The MCP
server is not treated as proof of a separate frontend-facing production API.
Frontend behavior and live end-to-end integration are therefore marked **Not
verified**, not passed.

## Verified contracts

### Standardized finding

The canonical finding fields are:

- `file_name`
- `line_number`
- `vulnerability_type`
- `severity`
- `confidence`
- `code`

The standardized finding creator also supplies `owasp`, `cwe`, and
`fingerprint`; `evidence` is optional. Confidence is finite and in the range
0–100. Line numbers are positive, one-based integers.

### Scan history and persistence

The persistence layer records project path, status, start and finish timestamps,
files scanned, error count, total findings, severity counts, and a message.
Retrieved scan records include decoded severity counts and persisted findings.

### MCP responses

The tracked MCP server exposes `scan_code`, `scan_project`,
`get_scan_results`, `get_risk_score`, `generate_report`, and
`analyze_vulnerability`.

The risk score is a severity-weighted heuristic capped at 100 and reports
`ai_provider_used: false`. Vulnerability remediation guidance is deterministic
rule-based output and also reports `ai_provider_used: false`.

Missing scan lookups return `found: false` with the requested scan ID.

## Findings and ownership

### T12-01 — Markdown report field mapping defect

**Status:** Confirmed by focused runtime reproduction.

A standardized finding containing `vulnerability_type: "SQL Injection"`,
`file_name: "src/example.py"`, and `line_number: 17` was persisted to a
temporary verification database. The generated Markdown instead displayed
`Finding`, `File: Unknown`, and `Line: Unknown`.

The report generator reads legacy aliases (`type`/`name`, `file`/`file_path`,
and `line`) rather than the canonical documented fields.

**Impact:** Report consumers can lose the finding type, source path, and line
number even when the persisted finding contains them.

**Suggested owner:** Backend/MCP implementation owner.

**Recommendation:** Align report generation with `vulnerability_type`,
`file_name`, and `line_number`; add regression tests asserting those exact
values appear in Markdown output. No implementation change was made during
this cross-team verification.

### T12-02 — Severity contract inconsistency

**Status:** Confirmed by source/document inspection.

`docs/scanner_api.md` and `scanner/finding.py` define valid standardized
severities as `Critical`, `High`, `Medium`, and `Low`. However,
`scanner/severity.py` maps some vulnerability types to `Info`, while MCP
risk/report logic also recognizes `Info`.

**Impact:** Producers or consumers may disagree about whether `Info` is a valid
standard finding severity.

**Suggested owner:** Scanner/backend contract owners.

**Recommendation:** Agree on one severity contract and make the mapping,
validation, persistence expectations, report generation, tests, and docs
consistent. No implementation change was made during this verification.

### T12-03 — Frontend/API integration unavailable in this branch

**Status:** Not verified.

No frontend components or package manifest were found by the repository
inspection. Searches for production FastAPI/Flask route definitions returned
only test fixtures, examples, or scanner rule examples; the MCP server is
available, but that alone does not establish the frontend's API contract.

**Suggested owner:** Frontend/API integration owners.

**Needed evidence:** Frontend repository/branch, API client and response types,
a reachable development API, and a real response captured from that API.

### T12-04 — UI states and stale data behavior

**Status:** Not verified.

Loading, empty results, scan failure, network failure, authentication failure,
stale results, refresh behavior, and history navigation could not be assessed
without the frontend source and a runnable integration environment.

**Suggested owner:** Frontend owner, coordinated with API/backend owner.

**Needed evidence:** UI source or test build, state-handling tests, and integration
tests against the actual development API. Do not substitute mock data for
real integration evidence.

## Test evidence

Command:

`python -m pytest .\tests\test_mcp_integration.py -q`

Result:

`8 passed in 1.68s`

The existing tests cover scanner/MCP scanning behavior, invalid findings,
missing paths, and JSON round-trip. They do not assert that Markdown reports
preserve the canonical finding type, file path, and line number.

A separate focused runtime check against the tracked `mcp_server.py`
reproduced T12-01. Its temporary SQLite database triggered a Windows file-lock
cleanup error, leaving a temporary directory under the user's local Temp path.
That file was inspected and found to contain only `verification.sqlite`.
It was intentionally left untouched rather than forcibly deleted. This cleanup
issue is separate from the report-mapping defect.

## Verification matrix

| Requirement | Status | Evidence |
|---|---|---|
| Finding fields and confidence | Verified in source/docs | `scanner/finding.py`, `docs/scanner_api.md` |
| History summary contract | Verified in source | `scanner/scan_persistence.py` |
| Risk score representation | Verified in source | `mcp_server.py` |
| AI versus deterministic output | Verified in source | `mcp_server.py` |
| Markdown finding fields | Failed | Focused runtime reproduction |
| Severity consistency | Inconsistent | Validator, severity map, docs, MCP logic |
| Frontend field mapping | Not verified | Frontend source unavailable in current branch |
| Loading/empty/error/stale states | Not verified | Frontend source unavailable |
| Live API response integration | Not verified | No reachable frontend-facing API established |

## Changes made

No scanner, MCP, frontend, API, database, or test implementation was modified
as part of this verification. This report is a new artifact only.
