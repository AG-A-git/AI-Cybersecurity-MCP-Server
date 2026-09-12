import os
import uuid
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from scanner import scan_project


app = FastAPI(
    title="AI Cybersecurity MCP Server",
    version="1.0.0"
)


# ---------------------------------------------------------
# In-memory scan storage
# ---------------------------------------------------------

SCAN_RESULTS: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------
# Request models
# ---------------------------------------------------------

class ScanRequest(BaseModel):
    project_path: str = "."


class RiskScoreRequest(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float


class AnalyzeRequest(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float
    code: str


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "json"


# ---------------------------------------------------------
# Risk calculation
# ---------------------------------------------------------

def calculate_risk_score(
    severity: str,
    confidence: float
) -> float:

    severity_values = {
        "Critical": 10.0,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 2.0,
        "Info": 1.0
    }

    severity_score = severity_values.get(
        severity,
        1.0
    )

    confidence_score = max(
        0.0,
        min(float(confidence), 100.0)
    )

    score = (
        severity_score * 0.8
        + confidence_score * 0.2
    ) * 10

    return round(
        min(score, 100.0),
        2
    )


def get_risk_level(score: float) -> str:

    if score >= 90:
        return "Critical"

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"


# ---------------------------------------------------------
# OWASP / CWE mapping
# ---------------------------------------------------------

def map_vulnerability(
    vulnerability: str
):

    name = vulnerability.lower()

    if "sql injection" in name:
        return "A03:2021 Injection", "CWE-89"

    if "command injection" in name:
        return "A03:2021 Injection", "CWE-78"

    if "cross-site scripting" in name or "xss" in name:
        return "A03:2021 Injection", "CWE-79"

    if "path traversal" in name:
        return "A01:2021 Broken Access Control", "CWE-22"

    if "hardcoded password" in name or "hardcoded secret" in name:
        return "A07:2021 Identification and Authentication Failures", "CWE-798"

    if "weak cryptography" in name:
        return "A02:2021 Cryptographic Failures", "CWE-327"

    return "A05:2021 Security Misconfiguration", "CWE-16"


# ---------------------------------------------------------
# AI analysis
# ---------------------------------------------------------

def analyze_with_ai(
    vulnerability: str,
    severity: str,
    code: str
):

    name = vulnerability.lower()

    if "sql injection" in name:

        explanation = (
            "The supplied code is vulnerable to SQL Injection "
            "because it executes a query without properly "
            "separating SQL instructions from user-controlled data. "
            "An attacker may manipulate input to alter the SQL "
            "statement."
        )

        recommendation = (
            "Use parameterized queries or prepared statements "
            "instead of constructing SQL queries from untrusted "
            "input. Validate input where appropriate and avoid "
            "building SQL statements through string concatenation."
        )

    elif "command injection" in name:

        explanation = (
            "The code may allow untrusted input to reach a system "
            "command, potentially allowing an attacker to execute "
            "arbitrary operating-system commands."
        )

        recommendation = (
            "Avoid shell execution when possible. Use safe APIs "
            "with argument arrays and strictly validate allowed "
            "input values."
        )

    elif "cross-site scripting" in name or "xss" in name:

        explanation = (
            "The code may place untrusted input into a web response "
            "without appropriate output encoding, allowing injected "
            "script content to execute in a user's browser."
        )

        recommendation = (
            "Apply context-appropriate output encoding and use "
            "framework-supported escaping. Validate untrusted "
            "input and consider an appropriate Content Security Policy."
        )

    else:

        explanation = (
            f"The supplied code has been identified as "
            f"{vulnerability}. Further review is recommended "
            f"to determine how untrusted data reaches this code."
        )

        recommendation = (
            "Review the affected data flow, validate untrusted "
            "input, apply the appropriate secure coding controls, "
            "and follow the relevant OWASP guidance."
        )

    return {
        "severity": severity,
        "explanation": explanation,
        "recommendation": recommendation
    }


# ---------------------------------------------------------
# Scanner normalization
# ---------------------------------------------------------

def normalize_finding(
    finding: Any
) -> Dict[str, Any]:

    if not isinstance(finding, dict):
        finding = {
            "file": "",
            "line": 0,
            "vulnerability": "Unknown",
            "severity": "Low",
            "confidence": 50,
            "code": str(finding)
        }

    file = finding.get(
        "file",
        ""
    )

    line = finding.get(
        "line",
        0
    )

    vulnerability = finding.get(
        "vulnerability",
        finding.get(
            "type",
            "Unknown"
        )
    )

    severity = finding.get(
        "severity",
        "Medium"
    )

    confidence = finding.get(
        "confidence",
        80
    )

    code = finding.get(
        "code",
        ""
    )

    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 80.0

    try:
        line = int(line)
    except (ValueError, TypeError):
        line = 0

    risk_score = finding.get(
        "risk_score"
    )

    if risk_score is None:
        risk_score = calculate_risk_score(
            severity,
            confidence
        )

    try:
        risk_score = float(risk_score)
    except (ValueError, TypeError):
        risk_score = calculate_risk_score(
            severity,
            confidence
        )

    risk_level = finding.get(
        "risk_level",
        get_risk_level(risk_score)
    )

    owasp, cwe = map_vulnerability(
        vulnerability
    )

    return {
        "file": file,
        "line": line,
        "code": code,
        "vulnerability": vulnerability,
        "severity": severity,
        "confidence": confidence,
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "owasp": finding.get(
            "owasp",
            owasp
        ),
        "cwe": finding.get(
            "cwe",
            cwe
        )
    }


# ---------------------------------------------------------
# Scanner helper
# ---------------------------------------------------------

def run_scanner(
    project_path: str
) -> List[Dict[str, Any]]:

    try:

        result = scan_project(
            project_path
        )

    except TypeError:

        result = scan_project()

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Scanner error: {exc}"
        )


    if isinstance(result, dict):

        findings = result.get(
            "findings",
            []
        )

    elif isinstance(result, list):

        findings = result

    else:

        findings = []


    return [
        normalize_finding(f)
        for f in findings
    ]


# ---------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# ---------------------------------------------------------
# Scan endpoint
# ---------------------------------------------------------

@app.post("/scan")
def scan_project_endpoint(
    request: ScanRequest
):

    project_path = request.project_path

    if not os.path.exists(project_path):

        raise HTTPException(
            status_code=400,
            detail="Project path does not exist"
        )


    findings = run_scanner(
        project_path
    )


    scan_id = (
        "scan-"
        + uuid.uuid4().hex[:8]
    )


    SCAN_RESULTS[scan_id] = {
        "scan_id": scan_id,
        "project_path": project_path,
        "total_findings": len(findings),
        "findings": findings
    }


    return {
        "status": "success",
        "scan_id": scan_id,
        "project_path": project_path,
        "total_findings": len(findings),
        "findings": findings
    }


# ---------------------------------------------------------
# Get scan results
# ---------------------------------------------------------

@app.get("/scan/{scan_id}")
def get_scan_results(
    scan_id: str
):

    if scan_id not in SCAN_RESULTS:

        raise HTTPException(
            status_code=404,
            detail="Scan ID not found"
        )


    return {
        "status": "success",
        **SCAN_RESULTS[scan_id]
    }


# ---------------------------------------------------------
# Risk score endpoint
# ---------------------------------------------------------

@app.post("/risk-score")
def get_risk_score(
    request: RiskScoreRequest
):

    score = calculate_risk_score(
        request.severity,
        request.confidence
    )

    level = get_risk_level(
        score
    )


    return {
        "status": "success",
        "file": request.file,
        "line": request.line,
        "vulnerability": request.vulnerability,
        "risk_score": score,
        "risk_level": level
    }


# ---------------------------------------------------------
# AI vulnerability analysis
# ---------------------------------------------------------

@app.post("/analyze")
def analyze_vulnerability(
    request: AnalyzeRequest
):

    ai_result = analyze_with_ai(
        request.vulnerability,
        request.severity,
        request.code
    )

    risk_score = calculate_risk_score(
        request.severity,
        request.confidence
    )

    risk_level = get_risk_level(
        risk_score
    )

    owasp, cwe = map_vulnerability(
        request.vulnerability
    )


    return {
        "file": request.file,
        "line": request.line,
        "code": request.code,
        "vulnerability": request.vulnerability,
        "severity": request.severity,
        "confidence": request.confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "owasp": owasp,
        "cwe": cwe,
        "ai_status": "success",
        "ai_analysis": ai_result,
        "recommendation": ai_result[
            "recommendation"
        ]
    }


# ---------------------------------------------------------
# Generate report
# ---------------------------------------------------------

@app.post("/report")
def generate_report(
    request: ReportRequest
):

    if request.scan_id not in SCAN_RESULTS:

        raise HTTPException(
            status_code=404,
            detail="Scan ID not found"
        )


    scan = SCAN_RESULTS[
        request.scan_id
    ]


    if request.format.lower() != "json":

        raise HTTPException(
            status_code=400,
            detail="Only JSON report format is currently supported"
        )


    return {
        "status": "success",
        "report": {
            "scan_id": scan["scan_id"],
            "project_path": scan["project_path"],
            "total_findings": scan["total_findings"],
            "findings": scan["findings"]
        },
        "format": "json"
    }


# ---------------------------------------------------------
# MCP-style tool functions
# ---------------------------------------------------------
# These functions are intentionally exported so that
# test_mcp_tools.py can import them directly.

def scan_project_tool(
    project_path: str = "."
):

    return scan_project_endpoint(
        ScanRequest(
            project_path=project_path
        )
    )


def get_scan_results_tool(
    scan_id: str
):

    return get_scan_results(
        scan_id
    )


def get_risk_score_tool(
    file: str,
    line: int,
    vulnerability: str,
    severity: str,
    confidence: float
):

    return get_risk_score(
        RiskScoreRequest(
            file=file,
            line=line,
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence
        )
    )


def analyze_vulnerability_tool(
    file: str,
    line: int,
    code: str,
    vulnerability: str,
    severity: str,
    confidence: float
):

    return analyze_vulnerability(
        AnalyzeRequest(
            file=file,
            line=line,
            code=code,
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence
        )
    )


def generate_report_tool(
    scan_id: str,
    format: str = "json"
):

    return generate_report(
        ReportRequest(
            scan_id=scan_id,
            format=format
        )
    )