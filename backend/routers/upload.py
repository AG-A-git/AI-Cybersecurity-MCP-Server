from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from pathlib import Path

from database import get_db
from models import UploadedFile, Project

from services.upload_service import (
    save_file,
    validate_extension,
    extract_zip,
    get_language
)

router = APIRouter(
    prefix="/upload",
    tags=["Upload"]
)


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR = Path("uploads/extracted")
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)


ALLOWED_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".html",
    ".zip"
}


@router.post("/")
async def upload_file(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # Check project
    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # Validate extension
    if not validate_extension(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    # Determine language
    language = get_language(file.filename)

    # Save file
    file_path = await save_file(
        file,
        file.filename
    )

    # Extract ZIP
    if Path(file.filename).suffix.lower() == ".zip":
        extract_zip(file_path)

    # Save metadata
    uploaded_file = UploadedFile(
        filename=file.filename,
        filepath=str(file_path),
        language=language,
        project_id=project_id,
        user_id=1
    )

    db.add(uploaded_file)
    db.commit()
    db.refresh(uploaded_file)

    return {
        "message": "File uploaded successfully",
        "id": uploaded_file.id,
        "filename": uploaded_file.filename,
        "filepath": uploaded_file.filepath,
        "language": uploaded_file.language,
        "project_id": uploaded_file.project_id
    }