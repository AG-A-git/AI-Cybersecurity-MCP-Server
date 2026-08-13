from typing import Optional

from pydantic import BaseModel


class VulnerabilityInput(BaseModel):
    file: str
    line: Optional[int] = None
    vulnerability: str
    severity: str
    confidence: Optional[int] = None
    code: Optional[str] = None