# Scanner API

## Overview

The scanner provides a single entry point for scanning an individual source
file or an entire project directory.

The backend can use:

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

## Supported Files

The scanner supports the following source-code extensions:

- `.py`
- `.js`

The scanner ignores these directories:

- `venv/`
- `node_modules/`
- `.git/`
- `__pycache__/`

## Supported Vulnerabilities

The scanner currently detects:

- SQL Injection
- Cross Site Scripting (XSS)
- Hardcoded Credentials
- Weak Cryptography
- Improper Input Validation

## Input

`scan_project()` accepts a file path or project directory path.

Example:

```python
results = scan_project("tests")
```

## Output

The scanner returns a list of JSON-compatible vulnerability dictionaries.

Example:

```json
[
  {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
  }
]
```

## Finding Fields

Each finding contains the following fields:

| Field | Type | Description |
|---|---|---|
| `file` | string | Source file containing the finding |
| `line` | integer | Line number of the finding |
| `vulnerability` | string | Detected vulnerability type |
| `severity` | string | Severity level |
| `confidence` | integer | Detection confidence from 0 to 100 |
| `code` | string | Relevant source-code snippet |

## Severity Values

The scanner uses the following standardized severity values:

- `Critical`
- `High`
- `Medium`
- `Low`

## Confidence

Confidence is represented as an integer from `0` to `100`.

## Backend Integration

The backend should use only the scanner entry point:

```python
from scanner.engine import scan_project

results = scan_project(project_path)
```

The backend does not need to import individual vulnerability rules.

The scanner engine handles file discovery, rule execution, and result standardization.