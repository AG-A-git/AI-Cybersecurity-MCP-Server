from pydantic import BaseModel, Field


class VulnerabilityInput(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float = Field(ge=0, le=100)
    code: str


class AIAnalysisResponse(BaseModel):
    """
    Structured response used by the existing AI pipeline.
    """

    explanation: str
    impact: str = ""
    recommendation: str
    owasp: str | None = None
    cwe: str | None = None


class AIAnalysis(BaseModel):
    """
    Validated AI-generated security analysis.
    """

    explanation: str
    impact: str
    recommendation: str
    secure_practice: str


class SecurityAnalysisResponse(BaseModel):
    """
    Complete normalized security analysis result.
    """

    file: str
    line: int
    code: str
    vulnerability: str
    severity: str
    confidence: float = Field(ge=0, le=100)

    risk_score: float = Field(ge=0, le=100)
    risk_level: str

    owasp: str | None = None
    cwe: str | None = None

    ai_status: str
    ai_analysis: AIAnalysisResponse | None = None

    recommendation: str