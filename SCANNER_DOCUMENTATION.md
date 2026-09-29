# Scanner Documentation

## 1. Overview

The vulnerability scanner analyzes source-code projects and produces standardized security findings.

The scanner currently supports Python and JavaScript source files and uses a central scanning pipeline containing 12 vulnerability detection rules.

The scanner is designed as a lightweight static-analysis component.

## 2. Supported File Types

The scanner currently supports:

* `.py` — Python
* `.js` — JavaScript

Python files receive the strongest AST-based context analysis.

JavaScript files are recognized by the parser and context layer, while most current vulnerability rules are primarily Python-oriented.

Common directories such as the following should be excluded from project scans:

* `venv`
* `node_modules`
* `.git`
* `__pycache__`

## 3. Standard Finding Format

Each detected vulnerability uses the following core structure:

```json
{
  "file_name": "example.py",
  "line_number": 10,
  "vulnerability_type": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "query = \"SELECT ...\" + username",
  "owasp": "A03: Injection",
  "cwe": "CWE-89"
}
```

## 4. Vulnerability Detection Rules

The scanner currently contains 12 vulnerability detection rules:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Hardcoded Credentials
4. Weak Cryptography
5. Input Validation
6. Command Injection
7. LDAP Injection
8. Insecure Deserialization
9. Security Misconfiguration
10. Authentication and Access Control
11. Server-Side Request Forgery (SSRF)
12. Sensitive Data Exposure

Each rule is implemented as a separate scanner module and is executed by the central scanning pipeline.

## 5. Scanner Pipeline

The central scanner loads all available detection rules and executes them against the target source file.

The general flow is:

Source File → Context Builder → Detection Rules → Findings → Backend / MCP → AI Analysis

The scanner context layer collects information such as:

* Source lines
* Programming language
* Imports
* Functions
* Variables
* Variable references
* Variable line numbers

This context helps detection rules provide more useful evidence.

## 6. Context-Aware Analysis

Python files are parsed using Python's Abstract Syntax Tree (AST).

The context layer identifies:

* Imported modules
* Function definitions
* Variable assignments
* Referenced variables
* Source-code line numbers

A small amount of surrounding source code is also attached to findings using source context.

For JavaScript files, the scanner recognizes the language and builds the basic source context. Most current detection rules remain primarily Python-oriented.

## 7. Evidence-Based Findings

Findings can contain an evidence object with information such as:

* Source
* Source line
* Tainted variable
* Sink
* Sink line
* Detection reason

Example:

```json
{
  "source": "username",
  "source_line": 5,
  "tainted_variable": "username",
  "sink": "SQL statement construction",
  "sink_line": 5,
  "reason": "SQL statement contains string concatenation with a variable or expression."
}
```

Evidence is intended to help the AI analysis layer explain why a vulnerability was detected.

## 8. SQL Injection Detection

The SQL Injection rule detects suspicious SQL statement construction involving variable concatenation.

Example pattern:

```python
query = "SELECT * FROM users WHERE name = '" + username
```

The scanner reports:

* Vulnerability type: SQL Injection
* OWASP: A03: Injection
* CWE: CWE-89
* Severity: Critical
* Confidence: 95

Safe parameterized SQL should not be reported by this rule.

## 9. Finding Validation

All findings are validated before being returned.

The required fields are:

* `file_name`
* `line_number`
* `vulnerability_type`
* `severity`
* `confidence`
* `code`

Severity values currently supported are:

* Critical
* High
* Medium
* Low

Confidence values must be between 0 and 100.

## 10. Deduplication

The scanner provides finding deduplication.

Findings are compared using:

* Vulnerability type
* File name
* Line number
* Code

When duplicate findings are detected, the finding with the higher confidence is retained.

## 11. Testing

The scanner is tested using the Python `pytest` framework.

The regression suite covers:

* Context analysis
* Evidence generation
* SQL detection accuracy
* Central scanner execution
* Multi-language handling
* Large-project scanning
* Performance
* Finding validation
* Integration behavior

The current regression suite contains 96 passing tests.

## 12. Performance

The scanner has been tested against larger temporary projects to verify that scanning remains practical.

A temporary project containing multiple Python files was successfully scanned during regression testing.

Performance testing is intended to detect unexpected slowdowns as additional rules and analysis features are added.

## 13. Integration

The scanner exposes standardized findings to the rest of the project.

The central pipeline is:

```text
run_all_rules(file_path)
        ↓
Detection Rules
        ↓
Standardized Findings
        ↓
Backend / MCP Integration
        ↓
AI Explanation and Risk Analysis
```

The scanner itself focuses on detection and evidence generation.

The AI layer is responsible for providing deeper explanations, OWASP/CWE enrichment, and risk analysis.

## 14. Limitations and Future Improvements

The scanner is a lightweight static-analysis system and is not intended to replace mature security-analysis platforms.

Current limitations include:

* Most detection rules are primarily Python-oriented.
* JavaScript support is currently focused on language recognition and context handling.
* Taint tracking is basic rather than full interprocedural analysis.
* Detection relies on rule-based patterns and AST context.
* Complex framework-specific behavior may not be detected.

Future improvements may include:

* Expanded JavaScript vulnerability rules
* Stronger taint tracking
* More precise data-flow analysis
* Additional security rules
* Better framework awareness
* Improved false-positive reduction
* Deeper project-level analysis
