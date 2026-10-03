from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from database import engine
from models import Base
from config import PROJECT_NAME
from config import PROJECT_VERSION
from config import PROJECT_DESCRIPTION
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User, Project, UploadedFile
from schemas import (
    UserRegister,
    UserResponse,
    ProjectCreate,
    ProjectResponse,
    UploadedFileResponse,
)
from utils import hash_password
from schemas import UserLogin, Token
from utils import verify_password
from auth import create_access_token
from fastapi.security import OAuth2PasswordBearer
from auth import get_current_user
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=PROJECT_DESCRIPTION
)
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cybersecurity MCP Server!"
    }
@app.post("/register", response_model=UserResponse)
def register(
    user: UserRegister,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
@app.post("/login", response_model=Token)
def login(
    user: UserLogin,
    db: Session = Depends(get_db)
):
    db_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(
        user.password,
        db_user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    access_token = create_access_token(
        data={
            "sub": db_user.email
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
@app.get("/profile", response_model=UserResponse)
def profile(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user
@app.post("/projects", response_model=ProjectResponse)
def create_project(
    project: ProjectCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    new_project = Project(
        name=project.name,
        description=project.description,
        owner_id=user.id
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    return new_project
@app.get("/projects", response_model=list[ProjectResponse])
def get_projects(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    projects = db.query(Project).filter(
        Project.owner_id == user.id
    ).all()

    return projects
@app.get(
    "/projects/{project_id}/files",
    response_model=list[UploadedFileResponse]
)
def get_project_files(
    project_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    files = db.query(UploadedFile).filter(
        UploadedFile.project_id == project_id
    ).all()

    return files
@app.post("/upload")
async def upload_file(
    project_id: int = Form(...),
    file: UploadFile = File(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(User).filter(
        User.email == email
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id
    ).first()

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    file_path = f"uploads/{file.filename}"

    contents = await file.read()

    with open(file_path, "wb") as buffer:
        buffer.write(contents)

    uploaded_file = UploadedFile(
        filename=file.filename,
        file_path=file_path,
        project_id=project_id
    )

    db.add(uploaded_file)
    db.commit()
    db.refresh(uploaded_file)

    return {
        "message": "File uploaded successfully",
        "file": uploaded_file
    }