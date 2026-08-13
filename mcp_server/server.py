from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ai.analysis import analyze_vulnerability
from ai.utils import format_ai_response


app = FastAPI(
    title="AI Cybersecurity MCP Server",
    description="AI vulnerability analysis API",
    version="1.0.0"
)


class VulnerabilityRequest(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float
    code: str


class VulnerabilityResponse(BaseModel):
    severity: str
    risk_score: int | float
    owasp: str
    cwe: str
    explanation: str
    recommendation: str


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity MCP Server is running"
    }


@app.post("/analyze", response_model=VulnerabilityResponse)
def analyze(request: VulnerabilityRequest):

    scanner_result = {
        "file": request.file,
        "line": request.line,
        "vulnerability": request.vulnerability,
        "severity": request.severity,
        "confidence": request.confidence,
        "code": request.code
    }

    try:
        analysis = analyze_vulnerability(scanner_result)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(
            status_code=503,
            detail="AI analysis unavailable"
        ) from e
    formatted_response = format_ai_response(
        severity=analysis["severity"],
        risk_score=analysis["risk_score"],
        owasp=analysis["owasp"],
        cwe=analysis["cwe"],
        explanation=analysis["explanation"],
        recommendation=analysis["recommendation"]
    )

    return formatted_response