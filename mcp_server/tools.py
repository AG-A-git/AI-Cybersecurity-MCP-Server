"""
MCP Cybersecurity Tools

Provides:
- scan_project
- analyze_vulnerability
- get_scan_results
- get_risk_score
- generate_report
"""

from pathlib import Path
from uuid import uuid4
from datetime import datetime

from ai.input import VulnerabilityInput
from ai.llm import analyze_vulnerability as run_ai_analysis
from ai.risk_score import calculate_risk, classify_risk


# ======================================================
# In-memory scan result store
# ======================================================

SCAN_RESULTS = {}


# ======================================================
# scan_project
# ======================================================

def scan_project(project_path: str) -> dict:
    """
    Scan a project and return standardized vulnerability
    findings.

    This is the initial scanner integration.
    """

    path = Path(project_path)

    if not path.exists():
        return {
            "status": "error",
            "message": "Project could not be scanned"
        }

    if not path.is_dir():
        return {
            "status": "error",
            "message": "Project could not be scanned"
        }

    try:
        # --------------------------------------------------
        # Initial scanner implementation
        # --------------------------------------------------
        #
        # Replace this section later with your actual
        # scanner module.
        #
        # For now, we return an empty finding list so
        # the MCP scan workflow is functional.
        # --------------------------------------------------

        findings = []

        scan_id = f"scan-{uuid4().hex[:8]}"

        result = {
            "status": "success",
            "scan_id": scan_id,
            "project_path": str(path),
            "findings": findings,
            "created_at": datetime.now().isoformat()
        }

        SCAN_RESULTS[scan_id] = result

        return result

    except Exception:
        return {
            "status": "error",
            "message": "Project could not be scanned"
        }


# ======================================================
# get_scan_results
# ======================================================

def get_scan_results(scan_id: str) -> dict:
    """
    Retrieve findings from a previous scan.
    """

    result = SCAN_RESULTS.get(scan_id)

    if result is None:
        return {
            "status": "error",
            "message": "Scan results not found"
        }

    return {
        "status": "success",
        "scan_id": scan_id,
        "findings": result["findings"]
    }


# ======================================================
# analyze_vulnerability
# ======================================================

def analyze_vulnerability(
    file: str,
    line: int,
    vulnerability: str,
    severity: str,
    confidence: float,
    code: str
) -> dict:
    """
    Analyze one vulnerability using the existing
    AI analysis pipeline.
    """

    try:

        finding = VulnerabilityInput(
            file=file,
            line=line,
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence,
            code=code
        )

    except Exception:

        return {
            "status": "error",
            "message": "Invalid vulnerability input"
        }

    try:

        result = run_ai_analysis(
            finding
        )

        return result

    except RuntimeError:

        return {
            "status": "error",
            "message": "AI analysis service unavailable"
        }

    except Exception:

        return {
            "status": "error",
            "message": "AI analysis service unavailable"
        }


# ======================================================
# get_risk_score
# ======================================================

def get_risk_score(
    file: str,
    line: int,
    vulnerability: str,
    severity: str,
    confidence: float
) -> dict:
    """
    Calculate risk using the existing deterministic
    risk-analysis module.
    """

    try:

        risk_score = calculate_risk(
            severity=severity,
            confidence=confidence,
            vulnerability_type=vulnerability
        )

        risk_level = classify_risk(
            risk_score
        )

        return {
            "status": "success",
            "risk_score": risk_score,
            "risk_level": risk_level
        }

    except ValueError as exc:

        return {
            "status": "error",
            "message": str(exc)
        }

    except Exception:

        return {
            "status": "error",
            "message": "Risk calculation failed"
        }


# ======================================================
# generate_report
# ======================================================

def generate_report(
    scan_id: str,
    report_format: str = "json"
) -> dict:
    """
    Generate a security report from scan results.

    Supported formats:
    - json
    - pdf
    - html

    JSON is implemented initially.
    """

    if report_format not in {
        "json",
        "pdf",
        "html"
    }:
        return {
            "status": "error",
            "message": "Report generation failed"
        }

    scan = SCAN_RESULTS.get(scan_id)

    if scan is None:
        return {
            "status": "error",
            "message": "Scan results not found"
        }

    try:

        report_findings = []

        for finding in scan["findings"]:

            report_findings.append({
                "file": finding.get("file"),
                "line": finding.get("line"),
                "vulnerability": finding.get(
                    "vulnerability"
                ),
                "severity": finding.get(
                    "severity"
                ),
                "confidence": finding.get(
                    "confidence"
                ),
                "risk_score": finding.get(
                    "risk_score"
                ),
                "owasp": finding.get(
                    "owasp"
                ),
                "cwe": finding.get(
                    "cwe"
                ),
                "recommendation": finding.get(
                    "recommendation"
                )
            })

        report = {
            "scan_id": scan_id,
            "total_findings": len(
                report_findings
            ),
            "findings": report_findings
        }

        return {
            "status": "success",
            "report": report
        }

    except Exception:

        return {
            "status": "error",
            "message": "Report generation failed"
        }