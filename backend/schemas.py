from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
from datetime import datetime
class UserRegister(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=100
    )

    username: str = Field(
        min_length=3,
        max_length=50
    )
class UserLogin(BaseModel):

    email: EmailStr

    password: str
class UserResponse(BaseModel):

    id: int
    username: str
    email: EmailStr

    class Config:
        from_attributes = True
class Token(BaseModel):

    access_token: str
    token_type: str
class TokenData(BaseModel):

    email: Optional[str] = None
    
class ProjectCreate(BaseModel):
    project_name: str
    description: str | None = None
    
class ProjectResponse(BaseModel):
    id: int
    project_name: str
    description: str | None = None
    created_at: datetime
    owner_id: int

    model_config = ConfigDict(from_attributes=True)

class UploadResponse(BaseModel):
    message: str
    id: int
    filename: str
    filepath: str
    language: str
    project_id: int
    
class ProjectList(BaseModel):
    projects: list[ProjectResponse]
    
class ScanCreate(BaseModel):
    project_id: int
    
class VulnerabilityResponse(BaseModel):
    id: int
    file_name: str
    line_number: int | None = None
    vulnerability_type: str
    severity: str
    confidence: int | None = None
    code: str | None = None
    model_config = ConfigDict(from_attributes=True)
    
class ScanResponse(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)
    
class ScanResultResponse(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    vulnerabilities: list[VulnerabilityResponse] = []
    model_config = ConfigDict(from_attributes=True)