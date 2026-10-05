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
    Structured intelligence returned by the AI.

    The AI is responsible only for explanatory security
    intelligence. Scanner severity and risk values remain
    authoritative outside this model.
    """

    explanation: str
    recommendation: str
    owasp: str | None = None
    cwe: str | None = None


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

    risk_score: float = Field(
        ge=0,
        le=100,
    )

    risk_level: str

    owasp: str | None = None
    cwe: str | None = None

    ai_status: str

    ai_analysis: AIAnalysisResponse | None = None

    recommendation: str