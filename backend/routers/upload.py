
from pathlib import Path

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import UploadedFile, Project, User
from routers.projects import get_authenticated_user
from services.upload_service import (
    save_file,
    validate_extension,
    extract_zip,
    get_language,
)

router = APIRouter(prefix="/upload", tags=["Upload"])


@router.post("/")
async def upload_file(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    # Confirm that the authenticated user owns the requested project.
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
        .first()
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    filename = file.filename

    # Validate the file type before saving.
    if not filename or not validate_extension(filename):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Allowed: .py, .java, .js, .html, .zip",
        )

    language = get_language(filename)
    file_path = None

    try:
        # Save the file in a directory specific to this project.
        file_path = await save_file(file, filename, project_id)

        # Extract ZIP archives into a project-specific directory.
        if Path(filename).suffix.lower() == ".zip":
            extract_zip(file_path, project_id)

        uploaded_file = UploadedFile(
            filename=Path(filename).name,
            file_path=str(file_path),
            project_id=project_id,
        )

        db.add(uploaded_file)
        db.commit()
        db.refresh(uploaded_file)

        return {
            "message": "File uploaded successfully",
            "id": uploaded_file.id,
            "filename": uploaded_file.filename,
            "file_path": uploaded_file.file_path,
            "language": language,
            "project_id": uploaded_file.project_id,
        }

    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="File upload failed",
        ) from exc

    finally:
        await file.close()
