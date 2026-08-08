from fastapi import FastAPI
from database import engine
from models import Base
from config import PROJECT_NAME
from config import PROJECT_VERSION
from config import PROJECT_DESCRIPTION
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import UserRegister, UserResponse
from utils import hash_password
from schemas import UserLogin, Token
from utils import verify_password
from auth import create_access_token
from fastapi.security import OAuth2PasswordBearer
from auth import get_current_user
from routers import projects
from routers import upload
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=PROJECT_DESCRIPTION
)
app.include_router(projects.router)
app.include_router(upload.router)
print("UPLOAD ROUTES:", [(route.path, route.methods) for route in upload.router.routes])
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