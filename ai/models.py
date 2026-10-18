
from pydantic import BaseModel, Field, field_validator


class VulnerabilityInput(BaseModel):
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    vulnerability: str
    severity: str = Field(min_length=1, max_length=50)
    confidence: float = Field(ge=0, le=100)
    code: str

    @field_validator("file", "severity")
    @classmethod
    def require_non_whitespace_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(
                "Field must not be empty or whitespace-only."
            )
        return value

    @field_validator("severity")
    @classmethod
    def require_supported_severity(cls, value: str) -> str:
        from .risk_score import normalize_severity

        normalize_severity(value)
        return value


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

    @field_validator(
        "explanation",
        "impact",
        "recommendation",
        "secure_practice",
    )
    @classmethod
    def require_non_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(
                "Field must not be empty or whitespace-only."
            )
        return value


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