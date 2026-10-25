from pydantic import BaseModel, Field


class VulnerabilityInput(BaseModel):
    file: str
    line: int
    vulnerability: str
    severity: str
    confidence: float = Field(ge=0, le=100)
    code: str


def validate_vulnerability(data):
    return VulnerabilityInput(**data)