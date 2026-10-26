# Scanner API and Handover Guide

## 1. Overview

The scanner provides an entry point for scanning a supported source file, a project directory, or a ZIP archive. The MCP server exposes scanning through the `scan_code(path: str)` tool.

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

The scanner uses static, rule-based analysis. Detection results are not a guarantee that every vulnerability will be identified.

## 2. Supported Files and Scan Scope

Supported source-code extensions:

- `.py`
- `.js`

The scanner ignores directories named:

- `venv`
- `node_modules`
- `.git`
- `__pycache__`

ZIP archive scanning is supported. Archive handling includes checks for unsafe paths, symbolic-link entries, entry counts, and declared uncompressed size.

The scanner is intended for static source-code analysis. It does not replace dynamic testing, manual security review, dependency auditing, or runtime monitoring.

## 3. Supported Vulnerability Categories

The active rule loader registers these 12 rule functions:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Hardcoded Credentials
4. Weak Cryptography
5. Improper Input Validation
6. Command Injection
7. LDAP Injection
8. Insecure Deserialization
9. Security Misconfiguration
10. Authentication and Access Control
11. Server-Side Request Forgery (SSRF)
12. Sensitive Data Exposure

These are rule categories, not a guarantee of complete vulnerability coverage. False positives and false negatives are possible.

## 4. Setup and Dependencies

Use Python 3.11 or later. From the repository root, activate the project's virtual environment and install the declared dependencies:

```powershell
python -m pip install -r requirements.txt
```

The current `requirements.txt` declares:

```text
mcp>=1.23.3
```

Pytest is used for testing but is not declared in `requirements.txt`. Install it separately in the development environment if it is not already available.

## 5. Scan Authorization and Usage

The scanner uses `SCANNER_ALLOWED_ROOTS` to restrict which filesystem paths may be scanned. Configure it to include the intended approved directory before running a scan.

Example for PowerShell:

```powershell
$env:SCANNER_ALLOWED_ROOTS = "C:\path\to\approved-projects"
```

Replace the example with an existing directory approved for scanning. On Windows, separate multiple roots with semicolons.

### Run the scanner CLI

```powershell
python .\scanner\scan.py .\tests
```

The requested path must be within a configured approved root.

### Start the MCP server

```powershell
python .\mcp_server.py
```

The server exposes the `scan_code(path: str)` tool. MCP client configuration and transport details depend on the client environment.

### Use the Python API

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

`project_path` should identify an approved source file, directory, or supported ZIP archive. The engine may raise `FileNotFoundError` or `PermissionError` for missing or unauthorized paths. Other invalid inputs and scan failures may be handled through the engine's status and error-handling paths.

## 6. Finding Output Schema

The scanner returns a list of finding dictionaries. Standardized findings include these fields:

| Field | Type | Description |
|---|---|---|
| `file_name` | string | Source file associated with the finding |
| `line_number` | integer | One-based source line number |
| `vulnerability_type` | string | Detected vulnerability category |
| `severity` | string | Normalized severity level |
| `confidence` | number | Confidence score from 0 through 100 |
| `code` | string | Relevant source-code snippet |
| `owasp` | string | Associated OWASP category |
| `cwe` | string | Associated CWE identifier |
| `fingerprint` | string | SHA-256 fingerprint used to identify a finding |

Additional context or evidence fields may be present depending on the analysis path. Consumers should tolerate additional fields and should not assume optional fields appear in every result.

The standardized finding creator validates required fields, line numbers, severity, confidence, code type, and the type of `evidence` when supplied.

## 7. Severity and Confidence

The standardized finding schema accepts these severity values:

- `Critical`
- `High`
- `Medium`
- `Low`

Confidence must be a finite numeric value from `0` through `100`, inclusive. Boolean values are not accepted as confidence scores.

Other scanner or reporting components may use additional informational labels. Verify severity compatibility at integration boundaries rather than assuming all components accept identical values.

## 8. Deduplication and Error Handling

The rule utilities deduplicate findings using vulnerability type, file name, line number, and code. Where duplicate findings have different confidence values, the highest-confidence finding is retained.

A source file that cannot be parsed or processed may produce no findings. Individual rule failures may also result in incomplete findings while other rules continue. An empty result list should therefore not be interpreted as proof that the scanned project is vulnerability-free.

## 9. Testing and Verification

The repository's `pytest.ini` configures test discovery under `tests/` for files named `test_*.py`.

Run the test suite from the repository root:

```powershell
python -m pytest -v
```

Useful focused commands include:

```powershell
python -m pytest tests -q
```

```powershell
python -m pytest --collect-only -q
```

The first runs the configured test suite in quiet mode. The second lists collected tests without executing them.

### Recorded test evidence

The Day 36 Task 14 report records a historical test run with:

- 264 tests collected
- 263 passed
- 1 skipped
- 0 failed
- 1 warning

The skipped test involved symlink behavior unavailable under that Windows environment's permissions. The warning concerned duplicate ZIP member names.

These figures describe that recorded run only. Rerun the tests after changes and record the new output before making claims about the current checkout.

## 10. Known Integration Limitations

### MCP Markdown report field mapping

The Day 36 Task 12 review identified a mismatch in the tracked MCP Markdown report-generation path. It reads legacy keys such as `type`, `file` or `file_path`, and `line`, whereas standardized findings use `vulnerability_type`, `file_name`, and `line_number`.

Consequently, generated Markdown reports may display generic finding names or unknown file and line values. Correct and regression-test this mapping before relying on those reports.

### Severity compatibility

The standardized finding schema accepts `Critical`, `High`, `Medium`, and `Low`. Other scanner or reporting paths may use `Info` for informational results. Confirm consistent handling across components before treating severity values as interchangeable.

### End-to-end integration

Repository-level tests and reports do not, by themselves, establish production readiness. Frontend integration, live external-service behavior, production HTTP API behavior, and deployment configuration must be verified in their intended environments before being described as fully tested.

## 11. Team Ownership

- **Member 1 — Backend and MCP:** Backend APIs, persistence, authentication, and MCP integration.
- **Member 2 — Scanner:** Detection rules, input handling, finding generation, and scanner regression tests.
- **Member 3 — AI analysis:** AI-assisted finding analysis and enrichment.
- **Member 4 — Frontend:** Finding display and user interaction.

Coordinate changes to finding fields, severity values, API contracts, and MCP responses across the relevant owners. Add or update regression tests when integration contracts change.

## 12. Handover and Release Checklist

Before release:

- [ ] Run the full test suite and record the actual result.
- [ ] Review scanner findings and regression-test important detection cases.
- [ ] Correct and test the MCP Markdown report field mapping.
- [ ] Verify severity compatibility across scanner and reporting components.
- [ ] Test path authorization and ZIP handling in the target environment.
- [ ] Verify frontend, backend, AI, and MCP integration separately.
- [ ] Review documentation against the implementation.
- [ ] Review tracked changes and untracked files before deciding what belongs in a release.

Do not interpret successful unit tests as proof of complete vulnerability detection or production readiness. Release readiness requires resolving the known integration issues and completing the relevant environment-specific checks.

This handover task documents the existing implementation and its known limitations. It does not authorize deleting local artifacts, staging files, committing changes, or pushing to a remote branch.
