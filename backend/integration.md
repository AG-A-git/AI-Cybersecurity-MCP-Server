# AI Cybersecurity MCP Server
# Backend Integration Documentation

## 1. Overview

The backend integrates the vulnerability scanner with the AI analysis
pipeline and stores the enhanced security analysis in the database.

The complete workflow is:

Upload Source Code
        ↓
Uploaded Files
        ↓
Vulnerability Scanner
        ↓
Scanner Findings
        ↓
AI Analysis
        ↓
Risk Score + OWASP + CWE
        ↓
Database
        ↓
Scan Results API
        ↓
Frontend / MCP Server

---

## 2. System Components

### Backend

Technology:

- FastAPI
- SQLAlchemy
- SQLite
- Uvicorn
- Pydantic

Backend responsibilities:

- User authentication
- Project management
- File upload
- Scan management
- Scanner integration
- AI integration
- Vulnerability persistence
- Scan result APIs

---

### Scanner

The scanner is located in the root `scanner` package.

The backend communicates with the scanner through:

```text
backend/scanner_client.py

Example :
{
    "file": "uploads\\xss_test.js",
    "line": 1,
    "vulnerability": "Cross Site Scripting",
    "severity": "High",
    "confidence": 80,
    "code": "document.write(userInput);"
}

3. Scanner Contract

Every scanner finding should contain the following fields:

Field	Description
file	Vulnerable source file
line	Line containing the vulnerability
vulnerability	Vulnerability type
severity	Severity level
confidence	Scanner confidence from 0–100
code	Vulnerable source code

The scanner output is passed directly to the AI analysis layer.

4. AI Analysis Integration

The backend AI adapter is:

backend/services/ai_client.py

The adapter imports the canonical AI analysis pipeline from:

ai/analysis.py

The backend uses:

from services.ai_client import analyze_vulnerabilities

The AI pipeline validates scanner findings before analysis.

5. AI Analysis Workflow

For every scanner finding:

Validate the vulnerability input.
Build the structured AI prompt.
Send the prompt to the local Ollama service.
Use the configured Llama model for analysis.
Parse the AI response.
Map the vulnerability to OWASP and CWE.
Calculate the risk score.
Return the enriched vulnerability result.

The AI result contains:

{
    "file": "uploads\\xss_test.js",
    "line": 1,
    "vulnerability": "Cross Site Scripting",
    "severity": "High",
    "confidence": 80,
    "risk_score": 60.0,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-79",
    "explanation": "...",
    "impact": "...",
    "recommendation": "...",
    "secure_practice": "..."
}
6. Risk Score

Risk score is calculated using severity and scanner confidence.

Current severity weights:

Critical = 90
High     = 75
Medium   = 50
Low      = 25

Formula:

Risk Score = Severity Weight × (Confidence / 100)

Example:

Severity = Critical
Confidence = 95

Risk Score = 90 × (95 / 100)
           = 85.5

Another example:

Severity = High
Confidence = 80

Risk Score = 75 × (80 / 100)
           = 60

The final score is restricted to the range:

0–100
7. OWASP and CWE Mapping

The AI analysis layer maps detected vulnerabilities to security standards.

Examples:

Vulnerability	OWASP	CWE
SQL Injection	A03:2021 Injection	CWE-89
Cross Site Scripting	A03:2021 Injection	CWE-79
Command Injection	A03:2021 Injection	CWE-78
Hardcoded Credentials	A07:2021 Identification and Authentication Failures	CWE-798
Weak Cryptography	A02:2021 Cryptographic Failures	CWE-327
Insecure Deserialization	A08:2021 Software and Data Integrity Failures	CWE-502
SSRF	A10:2021 Server-Side Request Forgery	CWE-918

The mapping layer is responsible for maintaining standardized security
classification.

8. Scan Lifecycle

A scan follows this lifecycle:

pending
   ↓
running
   ↓
scanner execution
   ↓
AI analysis
   ↓
database persistence
   ↓
completed

If an error occurs:

running
   ↓
failed

The scan model contains:

status
started_at
completed_at
created_at

Possible statuses:

pending
running
completed
failed
9. Database Integration

Vulnerability results are stored in the:

vulnerabilities

table.

The table contains:

id
scan_id
file_name
line_number
vulnerability_type
severity
confidence
code
risk_score
owasp_category
cwe_id
explanation
impact
recommendation

This allows both scanner-level information and AI-enhanced security
information to be persisted together.

10. Scan Creation API

Endpoint:

POST /scans/

Request:

{
    "project_id": 1
}

The endpoint:

Validates the project.
Finds uploaded files.
Creates a pending scan.
Changes the scan to running.
Runs the vulnerability scanner.
Sends scanner findings to AI analysis.
Stores enriched vulnerabilities.
Marks the scan as completed.
Returns the scan result.

If an exception occurs, the scan is marked as failed.

11. Scan Results API

Endpoint:

GET /scans/{scan_id}

Example:

GET /scans/13

The response contains:

{
    "id": 13,
    "project_id": 1,
    "status": "completed",
    "started_at": "...",
    "completed_at": "...",
    "created_at": "...",
    "vulnerability_count": 7,
    "vulnerabilities": []
}

Each vulnerability contains:

id
file_name
line_number
vulnerability_type
severity
confidence
code
risk_score
owasp_category
cwe_id
explanation
impact
recommendation
12. Current Integration Test

The integration has been tested using Scan 13.

The test produced:

Scan ID: 13
Project ID: 1
Status: completed
Vulnerability Count: 7

Detected vulnerability types included:

SQL Injection
Cross Site Scripting

Example SQL Injection result:

Severity: Critical
Confidence: 95
Risk Score: 85.5
OWASP: A03:2021 Injection
CWE: CWE-89

Example XSS result:

Severity: High
Confidence: 80
Risk Score: 60
OWASP: A03:2021 Injection
CWE: CWE-79

The AI-generated explanation, impact, and recommendation were also
successfully stored and returned through the scan results API.

13. Important Architecture Decision

The root ai package is the canonical AI implementation.

The backend does not maintain a separate AI implementation.

The integration layer is:

FastAPI Backend
      ↓
backend/services/ai_client.py
      ↓
ai/analysis.py
      ↓
ai/input.py
ai/prompts.py
ai/llm.py
ai/response.py
ai/risk_score.py
ai/mapping.py
      ↓
Ollama / Llama

This prevents duplicate AI implementations and keeps the architecture
modular.

14. Performance Consideration

The current scan workflow performs AI analysis sequentially.

For each vulnerability:

Scanner Finding
      ↓
AI Request
      ↓
AI Response
      ↓
Next Finding

Therefore, scan duration increases as the number of findings increases.

This is acceptable for the current integration stage, but future
optimization should consider:

Deduplicating identical scanner findings
Reducing unnecessary AI calls
Batch analysis where appropriate
Parallel AI processing where safe
Prompt optimization
Background scan processing
Progress reporting
Asynchronous task execution
Caching repeated analysis results

These optimizations should be implemented only after the current
integration is stable.

15. Current Status
Completed
Scanner contract verified
AI client integration completed
Scanner → AI pipeline connected
Vulnerability database extended
Pydantic vulnerability response extended
Scan results endpoint verified
Scan lifecycle implemented
End-to-end vulnerability scan tested
AI risk scoring verified
OWASP mapping verified
CWE mapping verified
AI explanations verified
Database persistence verified
Next Integration Areas

Future work will include:

Frontend integration
MCP server integration
Complete 12-vulnerability coverage
Scan performance optimization
Clean-file testing
Report generation
Security hardening
Integration testing

### After saving

Your file structure should now contain:

```text
AI-Cybersecurity-MCP-Server/
│
├── ai/
├── scanner/
├── backend/
│   ├── routers/
│   ├── services/
│   │   └── ai_client.py
│   ├── models.py
│   ├── schemas.py
│   ├── scanner_client.py
│   ├── integration.md
│   └── ...

