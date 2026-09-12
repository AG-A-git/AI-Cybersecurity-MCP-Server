"""
AI Cybersecurity MCP Server

FastAPI server for:
    - Project scanning
    - Vulnerability analysis
    - Risk scoring
    - Scan result retrieval
    - Report generation
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from scanner import scan_project

from ai.llm import analyze_vulnerability
from ai.risk_score import calculate_risk, classify_risk
from ai.vulnerability_mapping import get_vulnerability_mapping


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="AI Cybersecurity MCP Server",
    version="1.0.0",
    description="AI-powered cybersecurity vulnerability analysis server",
)


# ============================================================
# STORAGE
# ============================================================

# Stores scan results while the server is running.
SCANS: dict[str, dict[str, Any]] = {}


# ============================================================
# REQUEST MODELS
# ============================================================

class AnalyzeRequest(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float
    code: str


class ScanRequest(BaseModel):
    project_path: str = "."


class RiskScoreRequest(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float
    code: str


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "json"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def calculate_finding_risk(
    severity: str,
    confidence: float,
) -> tuple[float, str]:
    """
    Calculate risk score and risk level.

    Supports the risk_score module already present
    in the project.
    """

    try:
        score = calculate_risk(
            severity=severity,
            confidence=confidence,
        )
    except TypeError:
        score = calculate_risk(
            severity,
            confidence,
        )

    try:
        level = classify_risk(score)
    except Exception:
        level = severity

    return round(float(score), 2), level


def get_mapping(
    vulnerability: str,
) -> tuple[str | None, str | None]:
    """
    Get OWASP and CWE mapping.
    """

    try:
        mapping = get_vulnerability_mapping(
            vulnerability
        )

        if isinstance(mapping, dict):
            return (
                mapping.get("owasp"),
                mapping.get("cwe"),
            )

    except Exception:
        pass

    return None, None


def enrich_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Add risk and vulnerability mapping information
    to a scanner finding.
    """

    result = dict(finding)

    severity = str(
        result.get("severity", "Medium")
    )

    try:
        confidence = float(
            result.get("confidence", 0)
        )
    except (TypeError, ValueError):
        confidence = 0.0

    vulnerability = str(
        result.get("vulnerability", "")
    )

    risk_score, risk_level = calculate_finding_risk(
        severity,
        confidence,
    )

    owasp, cwe = get_mapping(
        vulnerability
    )

    result["risk_score"] = risk_score
    result["risk_level"] = risk_level

    if owasp is not None:
        result["owasp"] = owasp

    if cwe is not None:
        result["cwe"] = cwe

    return result


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/health")
def health() -> dict[str, str]:
    """
    Health check.
    """

    return {
        "status": "ok"
    }


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root() -> dict[str, str]:
    """
    Root endpoint.
    """

    return {
        "status": "success",
        "message": "AI Cybersecurity MCP Server is running",
    }


# ============================================================
# ANALYZE VULNERABILITY
# ============================================================

@app.post("/analyze")
def analyze(
    request: AnalyzeRequest,
) -> dict[str, Any]:
    """
    Analyze one vulnerability using the AI layer.
    """

    finding = request.model_dump()

    # Calculate risk
    risk_score, risk_level = calculate_finding_risk(
        request.severity,
        request.confidence,
    )

    finding["risk_score"] = risk_score
    finding["risk_level"] = risk_level

    # OWASP / CWE mapping
    owasp, cwe = get_mapping(
        request.vulnerability
    )

    if owasp is not None:
        finding["owasp"] = owasp

    if cwe is not None:
        finding["cwe"] = cwe

    # AI analysis
    try:
        ai_result = analyze_vulnerability(
            finding
        )

    except TypeError:
        try:
            ai_result = analyze_vulnerability(
                request.file,
                request.line,
                request.code,
                request.vulnerability,
                request.severity,
                request.confidence,
            )

        except Exception as exc:
            ai_result = {
                "severity": request.severity,
                "explanation": (
                    "AI analysis failed."
                ),
                "recommendation": (
                    "Review the vulnerability manually."
                ),
                "error": str(exc),
            }

    except Exception as exc:
        ai_result = {
            "severity": request.severity,
            "explanation": (
                "AI analysis failed."
            ),
            "recommendation": (
                "Review the vulnerability manually."
            ),
            "error": str(exc),
        }

    finding["ai_status"] = (
        "success"
        if isinstance(ai_result, dict)
        and "error" not in ai_result
        else "failed"
    )

    finding["ai_analysis"] = ai_result

    if isinstance(ai_result, dict):
        recommendation = ai_result.get(
            "recommendation"
        )

        if recommendation:
            finding["recommendation"] = (
                recommendation
            )

    return finding


# ============================================================
# SCAN PROJECT
# ============================================================

@app.post("/scan")
def scan(
    request: ScanRequest,
) -> dict[str, Any]:
    """
    Scan a project using the real scanner package.
    """

    scan_id = (
        "scan-"
        + uuid.uuid4().hex[:8]
    )

    project_path = request.project_path

    try:
        findings = scan_project(
            project_path
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": "Project scan failed",
                "error": str(exc),
            },
        )

    # Make sure findings is a list
    if findings is None:
        findings = []

    if not isinstance(findings, list):
        try:
            findings = list(findings)
        except Exception:
            findings = []

    # Enrich scanner findings
    enriched_findings = []

    for finding in findings:

        if isinstance(finding, dict):

            try:
                enriched = enrich_finding(
                    finding
                )
            except Exception:
                enriched = dict(finding)

            enriched_findings.append(
                enriched
            )

    # Store scan
    scan_result = {
        "status": "success",
        "scan_id": scan_id,
        "project_path": project_path,
        "findings": enriched_findings,
    }

    SCANS[scan_id] = scan_result

    return scan_result


# ============================================================
# GET SCAN RESULTS
# ============================================================

@app.get("/scan/{scan_id}")
def get_scan_results(
    scan_id: str,
) -> dict[str, Any]:
    """
    Retrieve previously generated scan results.
    """

    if scan_id not in SCANS:
        raise HTTPException(
            status_code=404,
            detail="Scan ID not found",
        )

    return SCANS[scan_id]


# ============================================================
# RISK SCORE
# ============================================================

@app.post("/risk-score")
def risk_score(
    request: RiskScoreRequest,
) -> dict[str, Any]:
    """
    Calculate risk score for a vulnerability.
    """

    score, level = calculate_finding_risk(
        request.severity,
        request.confidence,
    )

    return {
        "status": "success",
        "file": request.file,
        "line": request.line,
        "vulnerability": request.vulnerability,
        "risk_score": score,
        "risk_level": level,
    }


# ============================================================
# GENERATE REPORT
# ============================================================

@app.post("/report")
def generate_report(
    request: ReportRequest,
) -> dict[str, Any]:
    """
    Generate a JSON or Markdown report.
    """

    if request.scan_id not in SCANS:
        raise HTTPException(
            status_code=404,
            detail="Scan ID not found",
        )

    scan_data = SCANS[
        request.scan_id
    ]

    findings = scan_data.get(
        "findings",
        [],
    )

    output_format = (
        request.format.lower()
    )

    # --------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------

    if output_format == "json":

        report = {
            "scan_id": request.scan_id,
            "total_findings": len(findings),
            "findings": findings,
        }

        return {
            "status": "success",
            "report": report,
            "format": "json",
        }

    # --------------------------------------------------------
    # MARKDOWN REPORT
    # --------------------------------------------------------

    if output_format == "markdown":

        lines = [
            "# AI Cybersecurity Scan Report",
            "",
            f"**Scan ID:** {request.scan_id}",
            "",
            f"**Total Findings:** {len(findings)}",
            "",
        ]

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            lines.extend(
                [
                    f"## Finding {index}",
                    "",
                    f"- **File:** "
                    f"{finding.get('file', 'N/A')}",
                    f"- **Line:** "
                    f"{finding.get('line', 'N/A')}",
                    f"- **Vulnerability:** "
                    f"{finding.get('vulnerability', 'N/A')}",
                    f"- **Severity:** "
                    f"{finding.get('severity', 'N/A')}",
                    f"- **Confidence:** "
                    f"{finding.get('confidence', 'N/A')}",
                    f"- **Risk Score:** "
                    f"{finding.get('risk_score', 'N/A')}",
                    f"- **Risk Level:** "
                    f"{finding.get('risk_level', 'N/A')}",
                    f"- **OWASP:** "
                    f"{finding.get('owasp', 'N/A')}",
                    f"- **CWE:** "
                    f"{finding.get('cwe', 'N/A')}",
                    "",
                    "**Code:**",
                    "",
                    "```",
                    str(
                        finding.get(
                            "code",
                            "",
                        )
                    ),
                    "```",
                    "",
                ]
            )

        return {
            "status": "success",
            "report": "\n".join(lines),
            "format": "markdown",
        }

    # --------------------------------------------------------
    # INVALID FORMAT
    # --------------------------------------------------------

    raise HTTPException(
        status_code=400,
        detail=(
            "Unsupported report format. "
            "Use 'json' or 'markdown'."
        ),
    )