from pydantic import BaseModel, Field


# ======================================================
# Vulnerability Input
# ======================================================

class VulnerabilityInput(BaseModel):
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
# Final Security Analysis Response
# ======================================================

class SecurityAnalysisResponse(BaseModel):
    file: str
    line: int
    code: str
    vulnerability: str
    severity: str

    confidence: float = Field(
        ge=0,
        le=100
    )

    risk_score: float = Field(
        ge=0,
        le=100
    )

    risk_level: str

    owasp: str | None = None
    cwe: str | None = None

    ai_status: str

    ai_analysis: AIAnalysisResponse | None = None

    recommendation: str