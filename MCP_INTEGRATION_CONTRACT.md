# AI → MCP Integration Contract

## 1. Purpose

This document defines the interface between the future MCP
(Model Context Protocol) server and the cybersecurity components.

The MCP server will expose cybersecurity capabilities as tools
that an AI agent can call.

Architecture:

AI Agent
    ↓
MCP Server
    ↓
Cybersecurity Tools
    ↓
Scanner / AI Analysis / Risk Engine / Reports


## 2. Design Principles

The MCP layer should:

- Provide standardized tool names.
- Accept structured JSON input.
- Return structured JSON output.
- Reuse existing scanner, AI, and risk-analysis modules.
- Avoid duplicating vulnerability mappings.
- Avoid duplicating risk calculations.
- Return controlled errors.
- Keep tool responsibilities clearly separated.


## 3. MCP Tools

The initial MCP tool set contains:

1. scan_project
2. analyze_vulnerability
3. get_scan_results
4. get_risk_score
5. generate_report


## 4. Tool: scan_project

### Purpose

Scan a project and return standardized vulnerability findings.

### Input

```json
{
    "project_path": "C:/projects/example"
}
Output
{
    "status": "success",
    "findings": [
        {
            "file": "login.py",
            "line": 22,
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "confidence": 95,
            "code": "cursor.execute(query)"
        }
    ]
}
Error
{
    "status": "error",
    "message": "Project could not be scanned"
}
5. Tool: analyze_vulnerability
Purpose

Send a standardized scanner finding to the AI analysis pipeline.

Input
{
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}
Processing

VulnerabilityInput
↓
Llama 3
↓
AIAnalysisResponse
↓
OWASP/CWE Mapping
↓
Risk Analysis

Output
{
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "risk_score": 85.5,
    "risk_level": "High",
    "ai_status": "success",
    "ai_analysis": {
        "severity": "High",
        "risk_score": 90,
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "explanation": "The code executes a query without adequate protection against SQL injection.",
        "recommendation": "Use parameterized queries or prepared statements."
    },
    "recommendation": "Use parameterized queries or prepared statements."
}
Error
{
    "status": "error",
    "message": "AI analysis service unavailable"
}
6. Tool: get_scan_results
Purpose

Retrieve vulnerability findings from a previous scan.

Input
{
    "scan_id": "scan-001"
}
Output
{
    "status": "success",
    "scan_id": "scan-001",
    "findings": [
        {
            "file": "login.py",
            "line": 22,
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "confidence": 95,
            "code": "cursor.execute(query)"
        }
    ]
}
Error
{
    "status": "error",
    "message": "Scan results not found"
}
7. Tool: get_risk_score
Purpose

Return the risk assessment for a vulnerability finding.

Input
{
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95
}
Output
{
    "status": "success",
    "risk_score": 85.5,
    "risk_level": "High"
}
Important

The initial risk model is deterministic and will be refined later.

The MCP tool must call the existing risk-analysis module rather
than implementing a second risk formula.

8. Tool: generate_report
Purpose

Generate a security report from scan and analysis results.

Input
{
    "scan_id": "scan-001",
    "format": "json"
}
Supported formats
json
pdf
html
Output
{
    "status": "success",
    "report": {
        "scan_id": "scan-001",
        "total_findings": 1,
        "findings": [
            {
                "file": "login.py",
                "line": 22,
                "vulnerability": "SQL Injection",
                "severity": "Critical",
                "confidence": 95,
                "risk_score": 85.5,
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "recommendation": "Use parameterized queries or prepared statements."
            }
        ]
    }
}
Error
{
    "status": "error",
    "message": "Report generation failed"
}
9. Standard Vulnerability Input

The MCP layer must use the same vulnerability structure used
by the AI module.

{
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}

The AI module validates this using:

VulnerabilityInput

10. Standard AI Analysis Output

The AI module returns structured security analysis.

{
    "severity": "High",
    "risk_score": 90,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-89",
    "explanation": "The provided code is vulnerable to SQL Injection.",
    "recommendation": "Use parameterized queries or prepared statements."
}

The output must be validated using:

AIAnalysisResponse

11. OWASP/CWE Mapping

OWASP and CWE mappings are centralized.

The MCP server must not create its own vulnerability mapping.

The existing mapping layer should be reused.

Example:

SQL Injection
↓
OWASP: A03:2021 Injection
CWE: CWE-89

This ensures consistent results across:

Scanner
AI
Risk Engine
MCP
Reports
Dashboard
12. Risk Analysis

The MCP server must reuse the existing risk-analysis layer.

Initial model:

Severity
+
Confidence
↓
Risk Score
↓
Risk Level

The initial risk formula is not considered the final project formula.

It will be refined during later testing and implementation.

13. Error Handling

MCP tools must return controlled errors.

Scanner unavailable
{
    "status": "error",
    "message": "Scanner service unavailable"
}
AI unavailable
{
    "status": "error",
    "message": "AI analysis service unavailable"
}
Invalid input
{
    "status": "error",
    "message": "Invalid vulnerability input"
}
Scan not found
{
    "status": "error",
    "message": "Scan results not found"
}
Report failure
{
    "status": "error",
    "message": "Report generation failed"
}
14. Tool Responsibility
MCP Tool	Responsible Component
scan_project	Scanner
analyze_vulnerability	AI Analysis
get_scan_results	Scan Result Store
get_risk_score	Risk Engine
generate_report	Report Generator
15. AI Agent Interaction

Example interaction:

AI Agent
|
| scan_project
↓
MCP Server
|
↓
Scanner
|
↓
Standardized Findings
|
↓
AI Agent
|
| analyze_vulnerability
↓
MCP Server
|
↓
AI Analysis
|
↓
OWASP/CWE
|
↓
Risk Engine
|
↓
Structured Result

16. Example End-to-End Flow

Input:

Project:
C:/projects/example

Step 1:

scan_project

Result:

SQL Injection found in login.py line 22

Step 2:

analyze_vulnerability

Result:

OWASP: A03:2021 Injection
CWE: CWE-89

Step 3:

get_risk_score

Result:

Risk Score: 85.5
Risk Level: High

Step 4:

generate_report

Result:

Security report containing the finding,
AI analysis, OWASP/CWE mapping,
risk score, and recommendation.

17. Future MCP Architecture
                AI Agent
                   |
                   v
             +-----------+
             | MCP Server|
             +-----------+
              /    |    \
             /     |     \
            v      v      v
      Scanner     AI     Risk Engine
         |         |          |
         |         |          |
         +---------+----------+
                   |
                   v
            Security Results
                   |
                   v
              Report Engine
18. Implementation Status

Current status:

Scanner → AI input validation: Implemented
Llama 3 analysis: Implemented
AI response validation: Implemented
Risk analysis: Initial implementation
OWASP/CWE mapping: Implemented
AI failure handling: Implemented
MCP contract: Defined
MCP server implementation: Not yet implemented
Final risk formula: To be refined
Report generation integration: Future implementation
19. Important Integration Rule

The MCP server should act as an integration layer.

It should NOT duplicate the business logic already implemented
inside:

AI module
Risk Engine
Vulnerability Mapping
Scanner
Report Generator

Instead:

MCP Tool
↓
Existing Module
↓
Existing Validation / Logic
↓
Structured Result

This keeps the architecture modular and prevents inconsistent
security results.