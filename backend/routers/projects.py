from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import Project, User
from auth import get_current_user
from response_utils import success_response
from logging_config import get_logger


logger = get_logger(__name__)


router = APIRouter(
    prefix="/projects",
    tags=["Projects"]
)

security = HTTPBearer()


def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials,
    db: Session
):
    """
    Validate JWT and return the current database user.
    """

    token = credentials.credentials

    email = get_current_user(token)

    if email is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    current_user = db.query(User).filter(
        User.email == email
    ).first()

    if current_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return current_user


@router.post("/")
def create_project(
    project_name: str,
    description: str = None,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    # ---------------------------------------------------------
    # 1. Verify authentication
    # ---------------------------------------------------------
    current_user = get_authenticated_user(
        credentials,
        db
    )

    # ---------------------------------------------------------
    # 2. Create project for current user
    # ---------------------------------------------------------
    project = Project(
        project_name=project_name,
        description=description,
        owner_id=current_user.id
    )

    try:
        db.add(project)
        db.commit()
        db.refresh(project)

        logger.info(
            "Project created | project_id=%s | user_id=%s | project_name=%s",
            project.id,
            current_user.id,
            project.project_name
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to create project"
        )

    return success_response(
        "Project created successfully",
        {
            "id": project.id,
            "project_name": project.project_name,
            "description": project.description,
            "owner_id": project.owner_id
        }
    )


@router.get("/")
def get_projects(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    # ---------------------------------------------------------
    # 1. Verify authentication
    # ---------------------------------------------------------
    current_user = get_authenticated_user(
        credentials,
        db
    )

    # ---------------------------------------------------------
    # 2. Get only current user's projects
    # ---------------------------------------------------------
    projects = db.query(Project).filter(
        Project.owner_id == current_user.id
    ).all()

    return success_response(
        "Projects retrieved successfully",
        [
            {
                "id": project.id,
                "project_name": project.project_name,
                "description": project.description,
                "owner_id": project.owner_id
            }
            for project in projects
        ]
    )


@router.get("/{project_id}")
def get_project(
    project_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    # ---------------------------------------------------------
    # 1. Verify authentication
    # ---------------------------------------------------------
    current_user = get_authenticated_user(
        credentials,
        db
    )

    # ---------------------------------------------------------
    # 2. Find project
    # ---------------------------------------------------------
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # ---------------------------------------------------------
    # 3. Verify ownership
    # ---------------------------------------------------------
    if project.owner_id != current_user.id:
        logger.warning(
            "Unauthorized project access | project_id=%s | user_id=%s | owner_id=%s",
            project_id,
            current_user.id,
            project.owner_id
        )

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view this project"
        )

    return success_response(
        "Project retrieved successfully",
        {
            "id": project.id,
            "project_name": project.project_name,
            "description": project.description,
            "owner_id": project.owner_id
        }
    )


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    # ---------------------------------------------------------
    # 1. Verify authentication
    # ---------------------------------------------------------
    current_user = get_authenticated_user(
        credentials,
        db
    )

    # ---------------------------------------------------------
    # 2. Find project
    # ---------------------------------------------------------
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # ---------------------------------------------------------
    # 3. Verify ownership
    # ---------------------------------------------------------
    if project.owner_id != current_user.id:
        logger.warning(
            "Unauthorized project deletion | project_id=%s | user_id=%s | owner_id=%s",
            project_id,
            current_user.id,
            project.owner_id
        )

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete this project"
        )

    # ---------------------------------------------------------
    # 4. Delete project
    # ---------------------------------------------------------
    try:
        db.delete(project)
        db.commit()

        logger.info(
            "Project deleted | project_id=%s | user_id=%s",
            project_id,
            current_user.id
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to delete project"
        )

    return success_response(
        "Project deleted successfully",
        {
            "project_id": project_id
        }
    )
