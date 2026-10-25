from fastapi import FastAPI
from pydantic import BaseModel, Field

from ai.analysis import analyze_finding
from ai.utils import format_ai_response


app = FastAPI(
    title="AI Cybersecurity MCP Server",
    description="AI vulnerability analysis API",
    version="1.0.0"
)


class VulnerabilityRequest(BaseModel):
    file: str = Field(..., min_length=1, max_length=500)
    line: int = Field(..., ge=1)
    vulnerability: str = Field(..., min_length=1, max_length=200)
    severity: str = Field(..., min_length=1, max_length=50)
    confidence: float = Field(..., ge=0, le=100)
    code: str = Field(..., max_length=10000)


class VulnerabilityResponse(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float
    risk_score: int | float
    risk_level: str
    owasp: str
    cwe: str
    ai_status: str
    explanation: str | None
    recommendation: str | None


@app.post("/analyze", response_model=VulnerabilityResponse)
def analyze(request: VulnerabilityRequest):
    finding = request.model_dump()

    analysis = analyze_finding(finding)

    return format_ai_response(analysis)