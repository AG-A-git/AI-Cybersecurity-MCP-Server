from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ai.analysis import analyze_finding


app = FastAPI(
    title="AI Cybersecurity MCP Server",
    description="AI vulnerability analysis API",
    version="1.0.0",
)


class VulnerabilityRequest(BaseModel):
    file: str
    line: int = Field(gt=0)
    vulnerability: str = Field(min_length=1)
    severity: str
    confidence: float = Field(ge=0, le=100)
    code: str = Field(max_length=10000)


@app.get("/")
def root():
    return {"message": "AI Cybersecurity MCP Server is running"}


@app.post("/analyze")
def analyze(request: VulnerabilityRequest):
    scanner_result = {
        "file": request.file,
        "line": request.line,
        "vulnerability": request.vulnerability,
        "severity": request.severity,
        "confidence": request.confidence,
        "code": request.code,
    }

    try:
        analysis = analyze_finding(scanner_result)
        if not isinstance(analysis, dict):
            raise TypeError("Analysis returned an invalid result")

        result = {**scanner_result, **analysis}
        result.setdefault(
            "ai_status",
            "completed" if result.get("explanation") else "failed",
        )
        result.setdefault("impact", None)
        result.setdefault("explanation", None)

        if result["ai_status"] != "completed":
            result["explanation"] = None
            result["impact"] = None
            result.setdefault(
                "recommendation",
                "AI analysis service unavailable.",
            )

        return result

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Vulnerability analysis failed.",
        ) from None


# Compatibility exports for the root MCP implementation.
# Keep the FastAPI app above available for existing API users.

import importlib.util as _importlib_util
from pathlib import Path as _Path

_mcp_impl_path = _Path(__file__).resolve().parent.parent / "mcp_server.py"
_mcp_spec = _importlib_util.spec_from_file_location(
    "_ai_cybersecurity_mcp_impl",
    _mcp_impl_path,
)

if _mcp_spec is None or _mcp_spec.loader is None:
    raise ImportError(f"Cannot load MCP implementation from {_mcp_impl_path}")

_mcp_impl = _importlib_util.module_from_spec(_mcp_spec)
_mcp_spec.loader.exec_module(_mcp_impl)

mcp = _mcp_impl.mcp
EnvironmentTokenVerifier = _mcp_impl.EnvironmentTokenVerifier
scan_code = _mcp_impl.scan_code
scan_project = _mcp_impl.scan_project
analyze_vulnerability = _mcp_impl.analyze_vulnerability
get_scan_results = _mcp_impl.get_scan_results
get_risk_score = _mcp_impl.get_risk_score
from scanner.scan_persistence import get_scan
def generate_report(
    db_path: str,
    scan_id: int,
    format: str = "markdown",
) -> dict:
    """Generate a report using the package-level, mockable get_scan."""
    if format not in {"markdown", "json"}:
        raise ValueError("format must be 'markdown' or 'json'")
    scan = get_scan(db_path=db_path, scan_id=scan_id)
    if scan is None:
        return {"found": False, "scan_id": scan_id}
    findings = [
        _mcp_impl._normalize_finding(finding)
        for finding in scan.get("findings", [])
    ]

    if format == "json":
        import json

        return {
            "found": True,
            "scan_id": scan_id,
            "content": json.dumps(
                {
                    "id": scan_id,
                    "project_path": scan.get("project_path"),
                    "findings": findings,
                },
                indent=2,
            ),
        }

    lines = [
        "# Cybersecurity Scan Report",
        "",
        f"**Project:** {scan.get('project_path', 'Unknown')}",
        f"**Scan ID:** {scan_id}",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No findings.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding.get('vulnerability_type', 'Unknown vulnerability')}",
                f"- Severity: {finding.get('severity', 'Unknown')}",
                f"- File: {finding.get('file_name', 'Unknown')}",
                f"- Line: {finding.get('line_number', 'Unknown')}",
                f"- Confidence: {finding.get('confidence', 'Unknown')}",
                f"- Code: `{finding.get('code', '')}`",
                "",
            ])
    return {
        "found": True,
        "scan_id": scan_id,
        "content": "\n".join(lines),
    }
