# AI Integration Contract

## Overview

This document defines the interface between the security scanner,
AI analysis module, MCP layer, and backend.

The AI module accepts standardized vulnerability findings from the
scanner and returns structured security analysis results.

---

# Architecture

```text
Source Code
    |
    v
Member 2 Scanner
    |
    v
Standardized Vulnerability JSON
    |
    v
MCP Tool: analyze_scan()
    |
    v
AI Analysis Pipeline
    |
    +--> Input Validation
    |
    +--> Prompt Generation
    |
    +--> Ollama / LLM
    |
    +--> AI Response Validation
    |
    +--> Risk Scoring
    |
    +--> OWASP / CWE Mapping
    |
    v
Structured AI Results
    |
    v
Member 1 Backend
    |
    v
Member 4 Frontend
# AI Integration Contract

## 1. Input

The AI module accepts standardized scanner vulnerability findings.

```json
{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "code": "cursor.execute(query)"
}
Input fields
Field	Type	Description
file	string	Vulnerable source file
line	integer	Vulnerable line number
vulnerability	string	Vulnerability type
severity	string	Severity from scanner
confidence	float	Scanner confidence from 0 to 100
code	string	Vulnerable source code
2. Single Vulnerability Analysis
from ai.analysis import analyze_vulnerability

result = analyze_vulnerability(finding)
3. Batch Analysis

Multiple findings can be analyzed using:

from ai.analysis import analyze_vulnerabilities

results = analyze_vulnerabilities(findings)
4. MCP Interface

The backend should use:

from mcp_server.tools import analyze_scan

results = analyze_scan(findings)

The MCP workflow is:

Backend
   ↓
analyze_scan()
   ↓
AI Analysis
   ↓
Risk Analysis
   ↓
Structured Results
5. Output

The AI module returns:

{
  "file": "login.py",
  "line": 22,
  "vulnerability": "SQL Injection",
  "severity": "Critical",
  "confidence": 95,
  "risk_score": 90.25,
  "owasp": "A03:2021 Injection",
  "cwe": "CWE-89",
  "explanation": "...",
  "impact": "...",
  "recommendation": "..."
}
6. Risk Score

Risk scoring is deterministic.

Risk Score = Severity Score × Confidence

Severity scores:

Critical = 95
High     = 80
Medium   = 55
Low      = 25

Example:

Critical + 95% confidence

95 × 0.95 = 90.25

The LLM does not generate the risk score.

7. OWASP and CWE Mapping
Vulnerability	OWASP	CWE
SQL Injection	A03:2021 Injection	CWE-89
XSS	A03:2021 Injection	CWE-79
Hardcoded Credentials	A07:2021 Identification and Authentication Failures	CWE-798
Weak Cryptography	A02:2021 Cryptographic Failures	CWE-327
8. AI Response Fields

Every successful analysis should contain:

Explanation
Impact
Recommendation
Risk Score
OWASP
CWE
9. Error Handling

The AI layer handles:

Invalid scanner input
Empty AI response
Invalid JSON
Missing AI fields
Ollama unavailable
AI response validation errors
10. Integration Boundary
Member 2 Scanner
       ↓
Standardized Findings
       ↓
MCP analyze_scan()
       ↓
Member 3 AI Analysis
       ↓
Structured Results
       ↓
Member 1 Backend
       ↓
Member 4 Frontend

The backend should call analyze_scan() and should not directly call Ollama or parse raw LLM responses.


### Save it

Press:

```text