"""
AI Cybersecurity MCP Server

Provides:
- FastAPI REST API
- MCP server
- Vulnerability analysis
- OWASP/CWE mapping
- Deterministic risk scoring
- LLM explanation and remediation
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from mcp.server.fastmcp import FastMCP

from ai.input import VulnerabilityInput
from ai.llm import analyze_vulnerability

from .resources import register_resources


# ======================================================
# FastAPI Application
# ======================================================

app = FastAPI(
    title="AI Cybersecurity MCP Server",
    description="AI vulnerability analysis API",
    version="1.0.0"
)


# ======================================================
# MCP Application
# ======================================================

mcp = FastMCP(
    "AI Cybersecurity MCP Server"
)


# ======================================================
# Register MCP Resources
# ======================================================

register_resources(mcp)


# ======================================================
# Request Model
# ======================================================

class VulnerabilityRequest(BaseModel):
    file: str
    line: int

    vulnerability: str

    severity: str

    confidence: float = Field(
        ge=0,
        le=100
    )

    code: str


# ======================================================
# AI Analysis Response
# ======================================================

class AIAnalysisResponse(BaseModel):
    severity: str
    explanation: str
    recommendation: str


# ======================================================
# Final Vulnerability Response
# ======================================================

class VulnerabilityResponse(BaseModel):

    file: str

    line: int

    code: str

    vulnerability: str

    severity: str

    confidence: float

    risk_score: float

    risk_level: str

    owasp: str | None = None

    cwe: str | None = None

    ai_status: str

    ai_analysis: AIAnalysisResponse | None = None

    recommendation: str


# ======================================================
# Root Endpoint
# ======================================================

@app.get("/")
def root():

    return {
        "message":
        "AI Cybersecurity MCP Server is running"
    }


# ======================================================
# Health Endpoint
# ======================================================

@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# ======================================================
# Analyze Vulnerability
# ======================================================

@app.post(
    "/analyze",
    response_model=VulnerabilityResponse
)
def analyze(
    request: VulnerabilityRequest
):

    # --------------------------------------------------
    # Convert API request to project input model
    # --------------------------------------------------

    try:

        finding = VulnerabilityInput(
            file=request.file,
            line=request.line,
            vulnerability=request.vulnerability,
            severity=request.severity,
            confidence=request.confidence,
            code=request.code
        )

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc


    # --------------------------------------------------
    # Run complete vulnerability analysis
    # --------------------------------------------------

    try:

        analysis = analyze_vulnerability(
            finding
        )

    except RuntimeError as exc:

        raise HTTPException(
            status_code=503,
            detail="AI analysis unavailable"
        ) from exc

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail="Security analysis failed"
        ) from exc


    # --------------------------------------------------
    # Return analysis
    # --------------------------------------------------

    return analysis


# ======================================================
# MCP Tool
# ======================================================

@mcp.tool()
def analyze_vulnerability_tool(
    file: str,
    line: int,
    vulnerability: str,
    severity: str,
    confidence: float,
    code: str
) -> dict:
    """
    Analyze a single security vulnerability.

    Returns:
    - vulnerability type
    - severity
    - confidence
    - risk score
    - risk level
    - OWASP category
    - CWE identifier
    - AI explanation
    - remediation recommendation
    """

    finding = VulnerabilityInput(
        file=file,
        line=line,
        vulnerability=vulnerability,
        severity=severity,
        confidence=confidence,
        code=code
    )

    return analyze_vulnerability(
        finding
    )


# ======================================================
# MCP Tool - Multiple Findings
# ======================================================

@mcp.tool()
def analyze_vulnerabilities_tool(
    findings: list[dict]
) -> list[dict]:
    """
    Analyze multiple security vulnerabilities.

    Each finding must contain:

    file
    line
    vulnerability
    severity
    confidence
    code
    """

    results = []

    for finding in findings:

        vulnerability_input = (
            VulnerabilityInput(
                file=finding["file"],
                line=finding["line"],
                vulnerability=finding[
                    "vulnerability"
                ],
                severity=finding["severity"],
                confidence=finding[
                    "confidence"
                ],
                code=finding["code"]
            )
        )

        result = analyze_vulnerability(
            vulnerability_input
        )

        results.append(result)

    return results


# ======================================================
# MCP Server Entry Point
# ======================================================

if __name__ == "__main__":

    mcp.run()