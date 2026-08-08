from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Project


router = APIRouter(
    prefix="/projects",
    tags=["Projects"]
)


@router.post("/")
def create_project(
    project_name: str,
    description: str = None,
    db: Session = Depends(get_db)
):
    project = Project(
        project_name=project_name,
        description=description,
        owner_id=1
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


@router.get("/")
def get_projects(
    db: Session = Depends(get_db)
):
    projects = db.query(Project).all()

    return projects


@router.get("/{project_id}")
def get_project(
    project_id: int,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    return project


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    db.delete(project)
    db.commit()

    return {
        "message": "Project deleted successfully"
    }