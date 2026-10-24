# Day 36 — Task 12: Frontend Contract Verification

## 1. Scope and Limitations

This verification reviewed the tracked scanner finding schema, scan persistence layer, MCP server, automated tests, scanner documentation, and available repository artifacts.

No frontend source code, frontend package manifest, or confirmed production FastAPI/Flask route implementation was established in the inspected branch. The MCP server alone does not establish the existence of a separate frontend-facing HTTP API.

Therefore, frontend behavior, production API integration, and live end-to-end functionality remain **Not Verified**.

Passing automated tests does not establish complete vulnerability detection, frontend integration, or production readiness.

## 2. Verified Contracts

### 2.1 Standardized Finding Schema

The canonical required finding fields are:

* `file_name`
* `line_number`
* `vulnerability_type`
* `severity`
* `confidence`
* `code`

The standardized finding creator also supplies:

* `owasp`
* `cwe`
* `fingerprint`

The `evidence` field is optional.

The implementation in `scanner/finding.py` validates that:

* A finding is a dictionary containing all required fields.
* `file_name` and `vulnerability_type` are non-empty strings.
* `line_number` is a positive, one-based integer. Boolean values are rejected.
* `severity` is one of `Critical`, `High`, `Medium`, or `Low`.
* `confidence` is a finite numeric value between 0 and 100, inclusive. Boolean values are rejected.
* `code` is a string.
* If supplied, `evidence` is a dictionary.

A deterministic SHA-256 fingerprint is generated from the file name, line number, vulnerability type, and code.

**Status:** Verified by source inspection and automated finding-schema tests.

### 2.2 Scan History and Persistence

The persistence layer records scan information, including project path, scan status, timestamps, files scanned, error count, total findings, severity counts, and a message.

Retrieved scan records include persisted findings and decoded severity counts.

**Status:** Verified by source inspection and available automated tests. Integration with an external production database has not been established.

### 2.3 MCP Tool Contracts

The tracked MCP server exposes the following tools:

* `scan_code`
* `scan_project`
* `get_scan_results`
* `get_risk_score`
* `generate_report`
* `analyze_vulnerability`

The risk score is a severity-weighted heuristic capped at 100. Relevant deterministic analysis responses report `ai_provider_used: false`.

Vulnerability remediation guidance is rule-based. The implementation does not establish live AI-provider integration.

Missing scan lookups return `found: false` with the requested scan ID.

**Status:** Verified by source inspection and available MCP integration tests. Live deployment and external-service behavior remain unverified.

## 3. Findings and Ownership

### T12-01 — Markdown Report Field Mapping

**Status:** Fix implemented; regression tests passing.

The original report generator did not correctly read the canonical finding fields, potentially causing the vulnerability type, source file, and line number to be omitted from generated Markdown reports.

The canonical fields are:

* `vulnerability_type`
* `file_name`
* `line_number`

The tracked `mcp_server.py` implementation was inspected for support of these canonical fields and legacy aliases.

The regression tests in `tests/test_tracked_mcp_report.py` verify report-generation behavior.

**Required assertions:**

* The generated Markdown contains the actual vulnerability type, such as `SQL Injection`.
* The generated Markdown contains the actual source file, such as `src/example.py`.
* The generated Markdown contains the correct line number, such as `17`.
* Empty findings are handled safely.
* Legacy finding formats remain compatible where required.

**Focused verification command:**

`python -m pytest -q tests/test_tracked_mcp_report.py tests/test_finding_schema.py`

**Recorded result:** 11 passed.

**Impact:** Incorrect field mapping can cause reports to omit or misrepresent important vulnerability details.

**Suggested owner:** Backend/MCP implementation owner.

### T12-02 — Severity Contract Consistency

**Status:** Contract validation and regression tests implemented; informational categories remain explicitly mapped.

The standardized finding validator in `scanner/finding.py` accepts the following security severities:

* `Critical`
* `High`
* `Medium`
* `Low`

The severity mapping in `scanner/severity.py` also contains informational categories:

* `Code Style` → `Info`
* `Unused Variable` → `Info`

These informational categories are not valid standardized security-finding severities under the current validator contract.

The implementation was updated so that `get_severity()` returns the mapped severity for known vulnerability categories and raises `ValueError` for unknown categories instead of silently assigning `Info`.

The regression tests in `tests/test_severity_contract.py` cover:

* Known vulnerability-to-severity mappings.
* Rejection of unknown, empty, and non-string vulnerability types.
* Rejection of `Info` by the standardized finding validator.
* Acceptance of a valid standardized security finding.

**Focused verification command:**

`python -m pytest -q tests/test_severity_contract.py tests/test_tracked_mcp_report.py tests/test_finding_schema.py`

**Recorded result:** 27 passed.

**Full-suite verification command:**

`python -m pytest -q`

**Recorded result:** 300 passed, 1 skipped.

**Implementation commit:** `edff402` — `fix: align scanner severity contract`

**Impact:** Inconsistent severity definitions can cause findings to be rejected or interpreted differently by scanner components and report consumers.

**Suggested owner:** Scanner/backend contract owners.

**Remaining consideration:** If informational findings must be exposed as standardized findings, the schema, severity validation, persistence, risk scoring, reports, and documentation must be updated together. Do not introduce `Info` into the security severity contract without that coordinated change.

### T12-03 — Frontend/API Integration Not Verified

**Status:** Not Verified.

No frontend source code, frontend package manifest, or confirmed production frontend-facing HTTP API was established during this inspection.

The available MCP server and its tests do not prove that a frontend can connect to a deployed API or consume its responses correctly.

**Impact:** Frontend compatibility, authentication behavior, network handling, and actual end-to-end operation cannot be confirmed from the available evidence.

**Suggested owners:** Frontend and backend/API integration owners.

**Evidence required to close this finding:**

* Frontend repository or branch containing the actual UI implementation.
* API client and request/response type definitions.
* A reachable development API or integration environment.
* Captured responses from the actual API.
* Integration tests against the real frontend/API connection.

### T12-04 — Frontend UI States and Stale Data

**Status:** Not Verified.

The following frontend behaviors could not be assessed without the frontend source and a runnable integration environment:

* Loading state.
* Empty scan results.
* Scan failure.
* Network failure.
* Authentication failure.
* Stale results after a new scan.
* Refresh behavior.
* Scan-history navigation.
* Error presentation and recovery.

**Impact:** The user experience and correctness of frontend state transitions remain unknown.

**Suggested owner:** Frontend owner, coordinated with the backend/API owner.

**Evidence required to close this finding:**

* UI implementation or test build.
* State-handling tests.
* Tests for loading, empty, success, and failure states.
* Integration tests against the actual development API.

Mock responses alone are insufficient to establish live integration.

## 4. Verification Matrix

| Requirement                               | Status                                            | Evidence                                                  |
| ----------------------------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| Standardized finding fields               | Verified                                          | `scanner/finding.py`                                      |
| Finding confidence and line validation    | Verified                                          | Finding validation implementation and tests               |
| Finding fingerprint generation            | Verified                                          | SHA-256 fingerprint implementation                        |
| Scan-history persistence contract         | Verified by source inspection and available tests | Persistence implementation and tests                      |
| MCP tool definitions                      | Verified by source inspection                     | `mcp_server.py`                                           |
| Markdown report field mapping             | Fix implemented; focused tests pass               | `tests/test_tracked_mcp_report.py`                        |
| Severity mapping for known categories     | Verified by recorded tests                        | `scanner/severity.py`, `tests/test_severity_contract.py`  |
| Unknown severity-category handling        | Verified by recorded tests                        | `tests/test_severity_contract.py`                         |
| Standardized security severity validation | Verified by recorded tests                        | `scanner/finding.py`, `tests/test_severity_contract.py`   |
| Frontend field mapping                    | Not Verified                                      | Frontend source unavailable                               |
| Frontend loading and error states         | Not Verified                                      | Frontend source unavailable                               |
| Live frontend/API integration             | Not Verified                                      | Production integration evidence unavailable               |
| External production database integration  | Not Verified                                      | No external production integration established            |
| Live AI-provider integration              | Not Verified                                      | Deterministic behavior does not establish a live provider |

## 5. Test Evidence

The following results were recorded during the verification work.

### Focused report and finding tests

Command:

`python -m pytest -q tests/test_tracked_mcp_report.py tests/test_finding_schema.py`

Result:

`11 passed`

### Severity contract tests

Command:

`python -m pytest -q tests/test_severity_contract.py tests/test_tracked_mcp_report.py tests/test_finding_schema.py`

Result:

`27 passed`

### Full regression suite

Command:

`python -m pytest -q`

Recorded result after the severity-contract changes:

`300 passed, 1 skipped`

The skipped test is not counted as a pass. Its reason should be reviewed separately if full execution is required.

These are recorded results from the development session; rerun the commands against the current working tree before submitting the final report.

## 6. Changes and Commit References

The following commits were recorded during this work:

* `0a76e52` — `test: add scanner regression and failure handling coverage`
* `edff402` — `fix: align scanner severity contract`

The severity-contract change adds regression coverage and updates unknown vulnerability-category handling.

The report documents verification findings and distinguishes implemented fixes from integration work that remains unverified.

This document does not claim that frontend source code, a production HTTP API, external production database integration, or live AI-provider integration has been implemented.

## 7. Final Assessment

**Backend contract and regression-test work:** Verified to the extent supported by the recorded source inspection and test results.

**Markdown report mapping:** Fix and regression coverage recorded; rerun focused tests before submission.

**Severity contract:** Updated and covered by regression tests; the recorded full suite passed with one skipped test.

**Frontend integration:** Not Verified.

**Live end-to-end production behavior:** Not Verified.

Task 12 should not be described as fully end-to-end verified until the actual frontend, API integration, and relevant UI state behavior have been inspected and tested.

The next step is to rerun the focused and full test suites, review the final diff, and commit the completed Task 12 report separately.
