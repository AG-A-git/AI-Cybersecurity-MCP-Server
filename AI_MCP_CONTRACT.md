# Backend-AI Integration Contract

## 1. Purpose

This document defines the contract between the backend scanner and the AI security-analysis layer.

The contract provides a consistent interface for:

- scanner findings
- vulnerability normalization
- OWASP/CWE mapping
- deterministic risk calculation
- Llama 3 analysis
- AI response validation
- final security-analysis results

---

## 2. Endpoint

POST `/analyze`

Content-Type:

`application/json`

---

## 3. Request Contract

### Required Fields

| Field | Type | Required | Description |
|---|---|---:|---|
| `file` | string | Yes | Source file containing the vulnerability |
| `line` | integer | Yes | Source line containing the vulnerability |
| `vulnerability` | string | Yes | Scanner vulnerability type |
| `severity` | string | Yes | Scanner-provided severity |
| `confidence` | number | Yes | Scanner confidence from 0 to 100 |
| `code` | string | Yes | Vulnerable source-code snippet |

### Example

```json
{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
4. Input Validation

The scanner finding is validated before AI processing.

Required validation includes:

file must be present.
line must be present.
vulnerability must be present.
severity must be present.
confidence must be between 0 and 100.
code must be present.

Invalid request data is rejected by FastAPI/Pydantic.

Expected HTTP status:

422 Unprocessable Entity

5. Vulnerability Normalization

Scanner vulnerability names may use different terminology.

The AI layer normalizes these values to one canonical vulnerability name before mapping and risk analysis.

Examples:

SQLi
SQL injection
SQL Injection Vulnerability
        ↓
SQL Injection
XSS
Cross Site Scripting
Cross-Site Scripting
        ↓
XSS
SSRF
Server-Side Request Forgery
Server Side Request Forgery
        ↓
SSRF

The canonical vulnerability name is used by:

OWASP/CWE mapping
risk analysis
AI prompts
final security results
future MCP integration
6. Supported Vulnerability Scope

The fixed Day 11 scope contains 12 canonical vulnerability categories:

SQL Injection
XSS
Command Injection
LDAP Injection
Hardcoded Credentials/Secrets
Weak Cryptography
Broken Access Control
Security Misconfiguration
Insecure Authentication
Insecure Deserialization
Sensitive Data Exposure
SSRF
7. OWASP/CWE Mapping

OWASP and CWE classifications are supplied by deterministic application logic.

The LLM does not determine the final OWASP or CWE values.

Vulnerability	OWASP	CWE
SQL Injection	A03:2021 Injection	CWE-89
XSS	A03:2021 Injection	CWE-79
Command Injection	A03:2021 Injection	CWE-78
LDAP Injection	A03:2021 Injection	CWE-90
Hardcoded Credentials/Secrets	A07:2021 Identification and Authentication Failures	CWE-798
Weak Cryptography	A02:2021 Cryptographic Failures	CWE-327
Broken Access Control	A01:2021 Broken Access Control	CWE-862
Security Misconfiguration	A05:2021 Security Misconfiguration	CWE-16
Insecure Authentication	A07:2021 Identification and Authentication Failures	CWE-287
Insecure Deserialization	A08:2021 Software and Data Integrity Failures	CWE-502
Sensitive Data Exposure	A02:2021 Cryptographic Failures	CWE-200
SSRF	A10:2021 Server-Side Request Forgery	CWE-918
8. Deterministic Risk Model

The initial project risk model is:

Base Severity Score
        ×
Confidence Factor
        ×
Vulnerability Impact Factor
        ↓
Risk Score
Severity Weights
Critical = 90
High     = 75
Medium   = 50
Low      = 25
Confidence

Confidence is represented as a value from 0 to 100.

Example:

High severity = 75
Confidence = 90%

75 × 0.90 = 67.5
Initial Vulnerability Impact Factors
SQL Injection                  = 1.15
XSS                            = 1.05
Command Injection              = 1.15
LDAP Injection                 = 1.10
Hardcoded Credentials/Secrets  = 1.15
Weak Cryptography              = 1.05
Broken Access Control          = 1.15
Security Misconfiguration      = 1.00
Insecure Authentication        = 1.10
Insecure Deserialization       = 1.15
Sensitive Data Exposure        = 1.10
SSRF                           = 1.15

This is an initial model and is subject to refinement.

Example:

High = 75
Confidence = 90%
SQL Injection Impact = 1.15

75 × 0.90 × 1.15 = 77.625
Final score = 77.62

The final score is constrained to the range:

0–100

9. AI Responsibilities

Llama 3 is responsible for:

severity assessment
vulnerability explanation
remediation recommendation

The LLM must analyze only the supplied scanner finding.

The LLM must not invent:

file names
line numbers
source code
programming languages
frameworks
libraries
databases
application architecture
10. Deterministic Application Responsibilities

Application logic is responsible for:

canonical vulnerability name
file
line
vulnerable code
confidence
OWASP
CWE
risk score
risk level

The final risk score must come from the deterministic risk engine.

The final OWASP/CWE values must come from the centralized mapping.

11. AI Response Contract

The LLM is expected to return only:

{
  "severity": "High",
  "explanation": "The supplied code contains the reported vulnerability.",
  "recommendation": "Apply the appropriate secure coding practice to remediate the vulnerability."
}

The AI response must not provide:

risk_score
risk_level
owasp
cwe

Those values are calculated by application logic.

12. AI Response Validation

The returned AI JSON is:

extracted from the LLM response
parsed as JSON
validated using the AIAnalysisResponse model

The implementation also handles cases where Llama adds surrounding text before or after the JSON object.

13. Final Security Analysis Response

The backend receives the final standardized security-analysis result.

Example
{
  "file": "app.py",
  "line": 25,
  "code": "query = user_input",
  "vulnerability": "SQL Injection",
  "severity": "High",
  "confidence": 90,
  "risk_score": 77.62,
  "risk_level": "High",
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "ai_status": "success",
  "ai_analysis": {
    "severity": "High",
    "explanation": "The supplied code is vulnerable to SQL injection.",
    "recommendation": "Use parameterized queries."
  },
  "recommendation": "Use parameterized queries."
}
14. Field Definitions
Field	Source	Description
file	Scanner	Source file
line	Scanner	Vulnerable line
code	Scanner	Vulnerable code snippet
vulnerability	Normalization	Canonical vulnerability type
severity	Scanner/AI	Severity used in analysis
confidence	Scanner	Confidence from 0 to 100
risk_score	Risk Engine	Deterministic score from 0 to 100
risk_level	Risk Engine	Critical/High/Medium/Low/Informational
owasp	Central Mapping	Deterministic OWASP classification
cwe	Central Mapping	Deterministic CWE identifier
ai_status	Application	AI processing status
ai_analysis	LLM	Validated AI-generated analysis
recommendation	LLM/Application	Remediation recommendation
15. Successful Response

HTTP status:

200 OK

The final response must preserve important scanner information:

file
line
vulnerable code
vulnerability type
severity
confidence

The deterministic security information must also be present:

risk score
risk level
OWASP
CWE

The AI-generated information must be available through:

explanation
recommendation
16. Error Handling
Invalid Request

HTTP status:

422 Unprocessable Entity

Example:

{
  "file": "login.py",
  "vulnerability": "SQL Injection"
}

Missing required fields are rejected by validation.

Invalid Confidence

Confidence values outside the range 0–100 are rejected.

Example:

{
  "confidence": 150
}

Expected behavior:

Validation error.

Invalid Severity

Unsupported severity values are rejected by the deterministic risk engine.

Unknown Vulnerability

An unsupported vulnerability type is handled in a controlled manner.

The application must not crash.

AI Service Failure

When Ollama/Llama 3 is unavailable, the application returns a controlled AI failure response rather than exposing an internal traceback.

Example:

{
  "detail": "AI analysis unavailable"
}

Expected HTTP status:

503 Service Unavailable

Invalid LLM JSON

If the LLM response cannot be parsed or validated:

the application catches the error
ai_status is marked as failed
the application does not crash
17. Multiple-Finding Support

The AI layer supports multiple findings.

Architecture:

Scan
 ↓
Multiple Findings
 ↓
Analyze each finding
 ↓
Normalize each vulnerability
 ↓
Calculate each risk score
 ↓
Generate each AI analysis
 ↓
Return individual results

Each finding maintains its own:

file
line
code
vulnerability
severity
confidence
risk score
OWASP
CWE
AI analysis
18. Integration Flow
Scanner
   ↓
Standardized Finding
   ↓
AI Input Validation
   ↓
Vulnerability Normalization
   ↓
Central OWASP/CWE Mapping
   ↓
Deterministic Risk Engine
   ↓
Llama 3 Analysis
   ↓
AI Response Validation
   ↓
Final Security Analysis
   ↓
Backend / Dashboard / Reports
   ↓
Future MCP Integration
19. Known Limitations
The risk formula is an initial project model and may be refined later.
Llama 3 may occasionally add text around JSON; the application extracts and validates the JSON object.
The current scanner contract uses file, line, and vulnerability.
Batch analysis currently processes findings independently and provides lightweight aggregation.
MCP integration is prepared for the larger scan workflow.