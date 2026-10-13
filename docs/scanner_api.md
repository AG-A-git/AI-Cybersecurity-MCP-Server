# Scanner API

## Overview

The scanner provides an entry point for scanning a supported source file, a project directory, or a ZIP archive.

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

The MCP server exposes the scanner through the `scan_code(path: str)` tool.

## Supported Files

The scanner supports these source-code extensions:

- `.py`
- `.js`

The engine ignores files within directories named:

- `venv/`
- `node_modules/`
- `.git/`
- `__pycache__/`

ZIP archive scanning is also supported by the scanner implementation.

## Supported Vulnerabilities

Detection depends on the rules available in the project. Categories include:

- SQL Injection
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Hardcoded Credentials
- Weak Cryptography
- Improper Input Validation
- LDAP Injection
- Insecure Deserialization
- Security Misconfiguration

Detection is rule-based; this list does not guarantee detection of every vulnerability variant.

## Input

`scan_project()` accepts a path to a supported source file, project directory, or ZIP archive.

Example:

```python
from scanner.engine import scan_project

results = scan_project("tests")
```

The engine raises `FileNotFoundError` when the supplied path does not exist.

## Output

The scanner returns a list of finding dictionaries. Each finding contains these required fields:

| Field | Type | Description |
|---|---|---|
| `file_name` | string | Source file associated with the finding |
| `line_number` | integer | One-based source line number |
| `vulnerability_type` | string | Detected vulnerability category |
| `severity` | string | Normalized severity level |
| `confidence` | integer or float | Confidence score from 0 to 100 |
| `code` | string | Relevant source-code snippet |

The standardized finding creator also supplies these fields:

| Field | Type | Description |
|---|---|---|
| `owasp` | string | Associated OWASP category |
| `cwe` | string | Associated CWE identifier |
| `fingerprint` | string | SHA-256 fingerprint used to identify a finding |

Additional fields may be supplied by scanning or context-aware analysis. For example, results may include `source_context` with surrounding source lines. The optional `evidence` field, when present in a standardized finding, must be a dictionary.

Consumers should tolerate additional fields and should not assume that optional context fields appear in every result.

## Severity Values

The standardized finding schema accepts these exact values:

- `Critical`
- `High`
- `Medium`
- `Low`

Severity must be a string matching one of these values.

## Confidence

Confidence must be a finite numeric value from `0` through `100`, inclusive. Boolean values are not accepted as confidence scores.

## Finding Validation

Standardized findings are validated by `create_finding()` before they are returned.

Validation checks required fields, non-empty file names and vulnerability types, positive integer line numbers, severity, confidence, code type, and the type of `evidence` when supplied.

## Backend and MCP Integration

For Python integration:

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

The MCP server exposes this tool:

```python
scan_code(path: str) -> list
```

The MCP tool delegates scanning to `scanner.engine.scan_project()` and returns its result list.

The backend should use the scanner entry point rather than importing individual vulnerability rules.

## Compatibility Note

The canonical finding field names are `file_name`, `line_number`, and `vulnerability_type`. Integrations should use these names rather than older aliases such as `file`, `line`, or `vulnerability`.
