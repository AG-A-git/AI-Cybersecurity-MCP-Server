# Backend-AI Integration Contract

## Endpoint

POST /analyze

The backend sends scanner vulnerability information to the AI
analysis service.

---

## Request

### Content-Type

application/json

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
HTTP Status

200 OK

Example
{
  "severity": "Critical",
  "risk_score": 97,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "...",
  "recommendation": "..."
}
Response Fields
Field	Type	Description
severity	string	Final vulnerability severity
risk_score	number	Calculated risk score
owasp	string	OWASP classification
cwe	string	CWE classification
explanation	string	AI-generated vulnerability explanation
recommendation	string	AI-generated remediation
Error Response

If required request fields are missing:

HTTP Status:

422 Unprocessable Entity

The backend should handle validation errors appropriately.

Integration Flow

Scanner
↓
Backend
↓
POST /analyze
↓
FastAPI MCP Server
↓
AI Analysis Pipeline
↓
Risk Score
↓
OWASP/CWE Mapping
↓
AI Explanation
↓
AI Recommendation
↓
Response Formatter
↓
Backend

Supported Vulnerabilities

The current AI module supports:

SQL Injection
XSS
Command Injection
Hardcoded Credentials
Example SQL Injection
Request
{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
Response
{
  "severity": "Critical",
  "risk_score": 97,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "...",
  "recommendation": "..."
}

---

## Step 3 — Save

Press:

```text
Ctrl + S