from pydantic import BaseModel, EmailStr, Field
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
class UploadedFileResponse(BaseModel):

    id: int
    filename: str
    file_path: str
    project_id: int
    uploaded_at: Optional[datetime] = None

    class Config:
        from_attributes = True