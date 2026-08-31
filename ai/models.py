from pydantic import BaseModel, Field


class VulnerabilityInput(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float = Field(ge=0, le=100)
    code: str


class AIAnalysisResponse(BaseModel):
    severity: str
    risk_score: int = Field(ge=0, le=100)
    owasp: str
    cwe: str
    explanation: str
    recommendation: str