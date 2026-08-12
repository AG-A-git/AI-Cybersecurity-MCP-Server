import re

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

from sqlalchemy.orm import Session

from database import engine, get_db
from models import Base, User

from config import (
    PROJECT_NAME,
    PROJECT_VERSION,
    PROJECT_DESCRIPTION,
)

from schemas import (
    UserRegister,
    UserResponse,
    UserLogin,
    Token,
)

from utils import hash_password, verify_password
from auth import create_access_token, get_current_user


# =========================================================
# DATABASE
# =========================================================

Base.metadata.create_all(bind=engine)


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=PROJECT_DESCRIPTION,
)


# =========================================================
# CORS
# =========================================================

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


# =========================================================
# OAUTH2
# =========================================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login"
)


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cybersecurity MCP Server!"
    }


# =========================================================
# REGISTER
# =========================================================

@app.post(
    "/register",
    response_model=UserResponse
)
def register(
    user: UserRegister,
    db: Session = Depends(get_db),
):

    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(
            user.password
        ),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


# =========================================================
# LOGIN
# =========================================================

@app.post(
    "/login",
    response_model=Token
)
def login(
    user: UserLogin,
    db: Session = Depends(get_db),
):

    db_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not verify_password(
        user.password,
        db_user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    access_token = create_access_token(
        data={
            "sub": db_user.email
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# =========================================================
# PROFILE
# =========================================================

@app.get(
    "/profile",
    response_model=UserResponse
)
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


# =========================================================
# SCANNER
# =========================================================

def scan_source_code(content: str):

    vulnerabilities = []

    # -----------------------------------------------------
    # SQL INJECTION
    # -----------------------------------------------------

    sql_patterns = [
        r'execute\s*\(\s*["\'].*SELECT.*\+',
        r'execute\s*\(\s*["\'].*INSERT.*\+',
        r'execute\s*\(\s*["\'].*UPDATE.*\+',
        r'execute\s*\(\s*["\'].*DELETE.*\+',
        r'query\s*\(\s*["\'].*SELECT.*\+',
        r'SELECT.*["\']\s*\+',
        r'INSERT.*["\']\s*\+',
        r'UPDATE.*["\']\s*\+',
        r'DELETE.*["\']\s*\+',
    ]

    for pattern in sql_patterns:

        if re.search(
            pattern,
            content,
            re.IGNORECASE,
        ):

            vulnerabilities.append({
                "severity": "Critical",
                "vulnerability": "SQL Injection",
                "description":
                    "User input may be directly concatenated into a database query.",
                "status": "Open",
            })

            break

    # -----------------------------------------------------
    # XSS
    # -----------------------------------------------------

    xss_patterns = [
        r'innerHTML\s*=',
        r'dangerouslySetInnerHTML',
        r'document\.write\s*\(',
    ]

    for pattern in xss_patterns:

        if re.search(
            pattern,
            content,
            re.IGNORECASE,
        ):

            vulnerabilities.append({
                "severity": "High",
                "vulnerability":
                    "Cross-Site Scripting (XSS)",
                "description":
                    "Untrusted input may be rendered without proper sanitization.",
                "status": "Open",
            })

            break

    # -----------------------------------------------------
    # HARDCODED PASSWORD
    # -----------------------------------------------------

    password_pattern = (
        r'(password|passwd|pwd)'
        r'\s*=\s*["\'][^"\']+["\']'
    )

    if re.search(
        password_pattern,
        content,
        re.IGNORECASE,
    ):

        vulnerabilities.append({
            "severity": "High",
            "vulnerability":
                "Hardcoded Password",
            "description":
                "A password appears to be stored directly in source code.",
            "status": "Open",
        })

    # -----------------------------------------------------
    # HARDCODED SECRET
    # -----------------------------------------------------

    secret_pattern = (
        r'(api[_-]?key|secret[_-]?key|access[_-]?token)'
        r'\s*=\s*["\'][^"\']+["\']'
    )

    if re.search(
        secret_pattern,
        content,
        re.IGNORECASE,
    ):

        vulnerabilities.append({
            "severity": "High",
            "vulnerability":
                "Hardcoded Secret",
            "description":
                "A possible API key or secret is present in source code.",
            "status": "Open",
        })

    # -----------------------------------------------------
    # DEBUG MODE
    # -----------------------------------------------------

    if re.search(
        r'debug\s*=\s*True',
        content,
        re.IGNORECASE,
    ):

        vulnerabilities.append({
            "severity": "Medium",
            "vulnerability":
                "Debug Mode Enabled",
            "description":
                "Debug mode appears to be enabled.",
            "status": "Open",
        })

    # -----------------------------------------------------
    # INFORMATION DISCLOSURE
    # -----------------------------------------------------

    information_pattern = (
        r'(server|powered[-_ ]by|'
        r'x[-_]?powered[-_]?by)'
    )

    if re.search(
        information_pattern,
        content,
        re.IGNORECASE,
    ):

        vulnerabilities.append({
            "severity": "Low",
            "vulnerability":
                "Information Disclosure",
            "description":
                "Server or technology information may be exposed.",
            "status": "Open",
        })

    return vulnerabilities


# =========================================================
# UPLOAD + SECURITY SCAN
# =========================================================

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):

    # -----------------------------------------------------
    # AUTHENTICATION
    # -----------------------------------------------------

    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    # -----------------------------------------------------
    # USER
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # FILE NAME
    # -----------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected",
        )

    # -----------------------------------------------------
    # FILE SIZE LIMIT
    # 5 MB
    # -----------------------------------------------------

    MAX_FILE_SIZE = 5 * 1024 * 1024

    contents = await file.read()

    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum size is 5 MB.",
        )

    if not contents:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty",
        )

    # -----------------------------------------------------
    # DECODE
    # -----------------------------------------------------

    text = contents.decode(
        "utf-8",
        errors="ignore",
    )

    # -----------------------------------------------------
    # SCAN
    # -----------------------------------------------------

    vulnerabilities = scan_source_code(
        text
    )

    # -----------------------------------------------------
    # COUNTS
    # -----------------------------------------------------

    critical = sum(
        1
        for item in vulnerabilities
        if item["severity"] == "Critical"
    )

    high = sum(
        1
        for item in vulnerabilities
        if item["severity"] == "High"
    )

    medium = sum(
        1
        for item in vulnerabilities
        if item["severity"] == "Medium"
    )

    low = sum(
        1
        for item in vulnerabilities
        if item["severity"] == "Low"
    )

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {
        "message": "Security scan completed",
        "filename": file.filename,
        "uploaded_by": user.email,
        "file_size": len(contents),
        "total_vulnerabilities": len(
            vulnerabilities
        ),
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "vulnerabilities": vulnerabilities,
    }
    # =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard")
def dashboard(
    token: str = Depends(oauth2_scheme),
):
    # -----------------------------------------------------
    # Check authentication
    # -----------------------------------------------------

    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    # -----------------------------------------------------
    # Temporary dashboard data
    # -----------------------------------------------------

    return {
        "total_projects": 26,

        "total_scans": 120,

        "critical_vulnerabilities": 18,

        "high_vulnerabilities": 35,

        "medium_vulnerabilities": 45,

        "low_vulnerabilities": 22,

        "recent_scans": [
            {
                "project": "E-Commerce App",
                "date": "06 Aug 2026",
                "issues_found": 12,
                "status": "Completed",
            },
            {
                "project": "Banking System",
                "date": "05 Aug 2026",
                "issues_found": 25,
                "status": "Completed",
            },
            {
                "project": "Student Portal",
                "date": "04 Aug 2026",
                "issues_found": 8,
                "status": "Completed",
            },
        ],

        "vulnerability_trend": [
            {
                "date": "01 Aug 2026",
                "critical": 3,
                "high": 7,
                "medium": 10,
                "low": 5,
            },
            {
                "date": "02 Aug 2026",
                "critical": 4,
                "high": 8,
                "medium": 12,
                "low": 6,
            },
            {
                "date": "03 Aug 2026",
                "critical": 2,
                "high": 6,
                "medium": 9,
                "low": 4,
            },
            {
                "date": "04 Aug 2026",
                "critical": 5,
                "high": 10,
                "medium": 14,
                "low": 7,
            },
            {
                "date": "05 Aug 2026",
                "critical": 3,
                "high": 9,
                "medium": 11,
                "low": 5,
            },
            {
                "date": "06 Aug 2026",
                "critical": 4,
                "high": 8,
                "medium": 13,
                "low": 6,
            },
        ],
    }