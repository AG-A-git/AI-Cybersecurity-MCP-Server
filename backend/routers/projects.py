
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db
from models import Project, UploadedFile, User
from auth import get_current_user as get_current_user_email

router = APIRouter(prefix="/projects", tags=["Projects"])

# Use the existing login endpoint to obtain a JWT token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_authenticated_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate the JWT and return the corresponding database user."""

    try:
        email = get_current_user_email(token)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not email:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.email == email).first()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_owned_project(
    project_id: int,
    user_id: int,
    db: Session,
) -> Project:
    """Return a project only if it belongs to the specified user."""

    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.owner_id == user_id,
        )
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return project


@router.post("/")
def create_project(
    project_name: str,
    description: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Create a project for the authenticated user."""

    name = project_name.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Project name is required",
        )

    project = Project(
        name=name,
        description=description.strip() or None,
        owner_id=current_user.id,
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


@router.get("/")
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """List only projects belonging to the authenticated user."""

    return (
        db.query(Project)
        .filter(Project.owner_id == current_user.id)
        .order_by(Project.id.desc())
        .all()
    )


@router.get("/{project_id}/files")
def get_project_files(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """List files belonging to an owned project."""

    get_owned_project(project_id, current_user.id, db)

    files = (
        db.query(UploadedFile)
        .filter(UploadedFile.project_id == project_id)
        .order_by(UploadedFile.id.desc())
        .all()
    )

    return [
        {
            "id": item.id,
            "filename": item.filename,
            "file_path": item.file_path,
            "project_id": item.project_id,
            "uploaded_at": item.uploaded_at,
        }
        for item in files
    ]


@router.get("/{project_id}")
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Retrieve one project belonging to the authenticated user."""

    return get_owned_project(project_id, current_user.id, db)


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Delete a project only if it belongs to the authenticated user."""

    project = get_owned_project(project_id, current_user.id, db)

    db.delete(project)
    db.commit()

    return {
        "message": "Project deleted successfully",
        "project_id": project_id,
    }
