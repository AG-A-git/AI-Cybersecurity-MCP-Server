
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


# -------------------------
# Authentication schemas
# -------------------------

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)
    username: str = Field(min_length=3, max_length=50)


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


# -------------------------
# Project schemas
# -------------------------

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    owner_id: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# -------------------------
# Uploaded file schemas
# -------------------------

class UploadedFileResponse(BaseModel):
    id: int
    filename: str
    file_path: str
    project_id: int
    uploaded_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# -------------------------
# Scan schemas
# -------------------------

class ScanCreate(BaseModel):
    project_id: int


class ScanResponse(BaseModel):
    id: int
    project_id: int
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# -------------------------
# Vulnerability schemas
# -------------------------

class VulnerabilityResponse(BaseModel):
    id: int
    file_name: Optional[str] = None
    line_number: Optional[int] = None
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[str] = None
    code: Optional[str] = None

    class Config:
        from_attributes = True


# -------------------------
# Scan result schema
# -------------------------

class ScanResultResponse(BaseModel):
    id: int
    project_id: int
    status: str
    created_at: Optional[datetime] = None
    vulnerability_count: int = 0
    vulnerabilities: list[VulnerabilityResponse] = Field(
        default_factory=list
    )

    class Config:
        from_attributes = True
