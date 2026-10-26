# Scanner Documentation

## 1. Overview

The vulnerability scanner analyzes source-code projects and produces standardized security findings.

The scanner currently supports Python and JavaScript source files and uses a central scanning pipeline containing 12 vulnerability detection rules.

The scanner is designed as a lightweight static-analysis component with context-aware analysis, basic taint/data-flow tracking, evidence generation, confidence calibration, and finding deduplication.

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

The required public finding fields are:

* `file_name`
* `line_number`
* `vulnerability_type`
* `severity`
* `confidence`
* `code`

Additional fields such as `evidence` may be present without changing the core finding contract.

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

## 5. Scanner Architecture

The scanner processing architecture is:

```text
Source
  ↓
Language Detection
  ↓
AST / Context Extraction
  ↓
Symbol / Variable Tracking
  ↓
Source Classification
  ↓
Sink Classification
  ↓
Taint / Data Flow
  ↓
Sanitization Awareness
  ↓
Rule Correlation
  ↓
Contextual Evidence
  ↓
Confidence Calibration
  ↓
Fingerprint / Deduplication
  ↓
Findings
  ↓
Backend / MCP Integration
```

The scanner context layer collects information such as:

* Source lines
* Programming language
* Imports
* Functions
* Classes
* Variables
* Variable assignments
* Variable references
* Variable line numbers
* Assignment history
* Source context windows
* Function and class context
* Source classification
* Sink classification
* Vulnerability-specific context

This information allows detection rules to reason about how potentially unsafe data moves through source code instead of relying only on isolated syntax patterns.

## 6. AST and Context-Aware Analysis

Python files are parsed using Python's Abstract Syntax Tree (AST).

The context layer identifies:

* Imported modules
* Function definitions
* Async functions
* Class definitions
* Variable assignments
* Variable references
* Function calls
* Return statements
* Conditional and loop context
* Source-code line numbers

The scanner also maintains assignment history so that reassignment can replace stale taint information.

For example:

```python
username = request.args.get("username")
query = username

query = "SELECT * FROM users"

cursor.execute(query)
```

The final constant assignment is treated as the current value of `query`, preventing stale taint from being carried forward.

The context layer also tracks simple multi-hop flows such as:

```text
username → user → query → SQL sink
```

This is intentionally lightweight and does not attempt full symbolic execution or complete interprocedural analysis.

## 7. Source Classification

Potential input sources are classified internally to improve contextual analysis.

Current source categories include:

* `HTTP_INPUT`
* `FILE_INPUT`
* `ENV_INPUT`
* `CLI_INPUT`
* `USER_INPUT`
* `UNKNOWN`

Examples include:

```python
request.args.get("name")
request.form.get("name")
request.json
request.data
os.environ.get("URL")
open(path).read()
input()
```

Function arguments are not automatically treated as user-controlled input.

## 8. Sink Classification

Potential security-sensitive operations are classified internally.

Current sink categories include:

* `SQL_SINK`
* `HTML_SINK`
* `COMMAND_SINK`
* `NETWORK_SINK`
* `DESERIALIZATION_SINK`
* `AUTHORIZATION_SINK`

Examples include:

```python
cursor.execute(query)
os.system(command)
requests.get(url)
pickle.loads(data)
```

Sink classification is combined with source and propagation information to improve contextual detection.

## 9. Taint and Data-Flow Analysis

The scanner performs lightweight taint tracking.

The general reasoning model is:

```text
Source
  ↓
Propagation / Assignment
  ↓
Vulnerability-Relevant Construction
  ↓
Sensitive Sink
```

The scanner can detect simple multi-hop propagation and recognizes certain sanitization or safe-use patterns.

Unknown sources are not automatically considered tainted.

Reassignment is tracked so that stale taint does not remain attached to a variable after it receives a safe value.

## 10. Vulnerability Contextual Analysis

### SQL Injection

SQL Injection analysis considers the relationship between:

```text
HTTP source
  ↓
Tainted variable
  ↓
SQL construction
  ↓
SQL execution
```

Examples involving concatenation or f-strings with tainted input can be detected.

Parameterized SQL and constant SQL statements should not be reported solely because `execute()` is present.

### Cross-Site Scripting

XSS analysis considers:

```text
HTTP source
  ↓
Tainted value
  ↓
HTML construction
  ↓
HTML output
```

Known escaping such as `html.escape()` is considered during contextual analysis.

### Command Injection

Command Injection analysis distinguishes between:

* Tainted command construction
* Constant commands
* Argument-array execution
* `shell=True` execution involving tainted data

For example, tainted request data reaching `os.system()` can produce a finding, while a constant command is not reported merely because `os.system()` is present.

### SSRF

SSRF analysis considers whether a network request destination originates from potentially attacker-controlled input.

For example:

```text
HTTP source
  ↓
URL variable
  ↓
requests.get(url)
```

Constant URLs and unrelated tainted variables should not automatically produce SSRF findings.

## 11. Authentication and Authorization Context

The scanner includes contextual checks for authentication and authorization patterns.

Examples of recognized security evidence include:

* Authentication decorators
* Authorization decorators
* `current_user`
* FastAPI `Depends()`
* Role checks
* Permission checks
* `abort(403)`
* Administrative route protection

The scanner distinguishes protected administrative routes from routes where sensitive functionality is exposed without an appropriate authorization check.

A health or public informational endpoint is not considered vulnerable merely because it does not require authentication.

## 12. Evidence and Explainability

Findings may include structured evidence describing why a vulnerability was detected.

Evidence can capture information such as:

* Source
* Source line
* Tainted variable
* Sink
* Sink line
* Detection reason
* Propagation path
* Sanitization information
* Function context
* Class context

The internal explainability model can represent information such as:

```text
source_type
source_line
sink_type
sink_line
function_name
taint_path
sanitizer_applied
evidence_reason
```

Example reasoning:

```text
Source type: HTTP_INPUT
Source line: 4
Sink type: SQL_SINK
Sink line: 7
Taint path: username → query
Reason: User-controlled HTTP input reaches SQL execution without parameterization.
```

These details are intended to improve scanner transparency and help the AI analysis layer explain why a finding was generated.

## 13. Finding Validation

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

## 14. Confidence and Deduplication

The scanner uses confidence values to represent detection certainty.

Findings are fingerprinted using:

* Vulnerability type
* File name
* Line number
* Code

The fingerprint does not depend on confidence or evidence.

When duplicate findings are detected, the higher-confidence finding is retained.

This allows additional contextual evidence to improve a finding without creating duplicate results.

## 15. Testing

The scanner is tested using the Python `pytest` framework.

The regression suite covers:

* Context analysis
* AST analysis
* Function and class context
* Variable tracking
* Variable reassignment
* Source classification
* Sink classification
* Taint propagation
* Sanitization awareness
* SQL detection accuracy
* XSS detection
* Command Injection detection
* SSRF detection
* LDAP detection
* Authentication and authorization analysis
* Evidence generation
* Explainability
* Central scanner execution
* Multi-language handling
* Large-project scanning
* Finding validation
* Deduplication
* Confidence handling
* Integration behavior

Current regression result:

```text
172 passed
```

## 16. Performance

The full regression suite was measured using:

```powershell
Measure-Command { pytest -q }
```

Observed runtime:

```text
TotalSeconds : 1.6603695
```

The scanner is also tested against larger temporary projects to verify that project scanning remains practical as additional rules and context analysis are introduced.

Performance testing is intended to detect unexpected slowdowns as scanner functionality grows.

## 17. Integration

The scanner exposes standardized findings to the rest of the project.

The central integration flow is:

```text
Scanner
  ↓
Standardized Findings
  ↓
Backend / MCP Integration
  ↓
AI Explanation and Risk Analysis
```

The scanner focuses on source-code detection, contextual analysis, evidence generation, confidence handling, and finding normalization.

The AI layer can provide deeper explanations, OWASP/CWE enrichment, and risk analysis.

## 18. Limitations and Future Improvements

The scanner is a lightweight static-analysis system and is not intended to replace mature security-analysis platforms.

Current limitations include:

* Most detection rules are primarily Python-oriented.
* JavaScript support is currently focused on language recognition and context handling.
* Taint tracking is lightweight rather than full interprocedural analysis.
* Detection relies on rule-based patterns and AST/context information.
* Complex framework-specific behavior may not be detected.
* Advanced symbolic execution is outside the current scope.

Future improvements may include:

* Expanded JavaScript vulnerability rules
* Stronger interprocedural taint tracking
* More precise project-level data-flow analysis
* Additional security rules
* Better framework awareness
* Improved false-positive reduction
* Deeper cross-file analysis
* More advanced vulnerability correlation
