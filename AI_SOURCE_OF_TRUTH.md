@"
# AI Cybersecurity MCP Server
# Source-of-Truth Architecture

## Scanner owns

The scanner is authoritative for:

- file
- line
- vulnerable code
- vulnerability type

AI must not overwrite these values.

## Application / Risk Layer owns

The application is authoritative for:

- OWASP
- CWE
- risk score
- risk level
- scan risk
- risk summary

These values must be deterministic and application-controlled.

## AI owns

AI is primarily responsible for:

- explanation
- impact
- recommendation
- secure practice
- contextual analysis

AI output is untrusted and must be validated before use.

## AI severity and confidence

AI may suggest severity or confidence, but these values must be validated before persistence or risk calculation.

Invalid AI values must be rejected or safely normalized.

## Canonical Finding

The pipeline is:

Scanner Finding
    ↓
Canonical Finding
    ↓
AI Analysis
    ↓
AI Response Validation
    ↓
OWASP / CWE Mapping
    ↓
Risk Engine
    ↓
Finding Risk
    ↓
Scan Risk
    ↓
Risk Summary
    ↓
Database
    ↓
MCP / Dashboard / Reports

## Source-of-truth example

If the scanner reports:

file = app.py
line = 25

and AI reports:

line = 42

the final finding must retain:

line = 25

The scanner location is authoritative.

## Risk Engine

Risk calculation must be:

- deterministic
- repeatable
- bounded
- documented

Risk scores must remain between 0 and 100.

The same validated finding input must produce the same risk score.

## Scan Risk

Scan-level risk must be calculated from actual stored findings.

The AI must not count findings or determine the final scan risk.

## Risk Summary

The risk summary must be generated from stored findings and deterministic risk information.

Example:

{
    "scan_id": 45,
    "risk_score": 82,
    "risk_level": "Critical",
    "total_findings": 8,
    "critical": 1,
    "high": 3,
    "medium": 3,
    "low": 1
}

The summary should be reusable by:

- Dashboard
- PDF reports
- HTML reports
- JSON export
- MCP

## MCP

MCP is an interface to the existing security system.

MCP must not duplicate:

- scanner logic
- AI implementation
- risk calculation
- database authorization logic

MCP should call the appropriate backend/service layer.

## Security principle

AI is an analysis component, not an authoritative security database.

The application remains responsible for:

- validating AI output
- preserving scanner metadata
- calculating deterministic risk
- enforcing authorization
- controlling persistence
"@ | Set-Content AI_SOURCE_OF_TRUTH.md