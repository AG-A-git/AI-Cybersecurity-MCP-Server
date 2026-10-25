
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from database import engine, get_db
from models import Base, User
from config import (
    PROJECT_NAME,
    PROJECT_VERSION,
    PROJECT_DESCRIPTION,
)
from schemas import UserRegister, UserResponse, UserLogin, Token
from utils import hash_password, verify_password
from auth import create_access_token, get_current_user
from routers import projects, upload, scan


# Create database tables
Base.metadata.create_all(bind=engine)


# Create FastAPI application
app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=PROJECT_DESCRIPTION,
)


# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register existing API routers
app.include_router(projects.router)
app.include_router(upload.router)
app.include_router(scan.router)


# OAuth2 token configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Home endpoint
@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cybersecurity MCP Server!"
    }


# Register endpoint
@app.post("/register", response_model=UserResponse)
def register(
    user: UserRegister,
    db: Session = Depends(get_db),
):
    # Check for an existing email
    existing_email = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    # Check for an existing username
    existing_username = (
        db.query(User)
        .filter(User.username == user.username)
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already taken",
        )

    # Create the user
    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
    )

    db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists",
        )
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to register user",
        )

    return new_user


# Login endpoint
@app.post("/login", response_model=Token)
def login(
    user: UserLogin,
    db: Session = Depends(get_db),
):
    db_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if (
        not db_user
        or not verify_password(
            user.password,
            db_user.password_hash,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    access_token = create_access_token(
        data={"sub": db_user.email}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# Profile endpoint
@app.get("/profile", response_model=UserResponse)
def profile(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return user
