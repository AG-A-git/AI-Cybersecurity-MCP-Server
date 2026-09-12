from response_utils import success_response
import zipfile

from fastapi import (
    APIRouter,
    Depends,
    UploadFile,
    File,
    HTTPException
)

from sqlalchemy.orm import Session

from pathlib import Path

from database import get_db
from models import UploadedFile, Project, User

from auth import get_current_user

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

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

security = HTTPBearer()


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True
)

EXTRACT_DIR = Path("uploads/extracted")
EXTRACT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


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
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    # --------------------------------------------------
    # 1. Get current user from JWT
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 2. Check project exists
    # --------------------------------------------------

    project = db.query(Project).filter(
        Project.id == project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # --------------------------------------------------
    # 3. Check project ownership
    # --------------------------------------------------

    if project.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to upload to this project"
        )

    # --------------------------------------------------
    # 4. Validate file extension
    # --------------------------------------------------

    if not validate_extension(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    # --------------------------------------------------
    # 5. Determine programming language
    # --------------------------------------------------

    language = get_language(file.filename)

    # --------------------------------------------------
    # 6. Save file with size validation
    # --------------------------------------------------

    try:
        file_path = await save_file(
            file,
            file.filename
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    # --------------------------------------------------
    # 7. Safely extract ZIP
    # --------------------------------------------------

    if Path(file.filename).suffix.lower() == ".zip":

        try:
            extract_zip(file_path)

        except ValueError as e:

            if file_path.exists():
                file_path.unlink()

            raise HTTPException(
                status_code=400,
                detail=str(e)
            )

        except zipfile.BadZipFile:

            if file_path.exists():
                file_path.unlink()

            raise HTTPException(
                status_code=400,
                detail="Invalid or corrupted ZIP file"
            )

    # --------------------------------------------------
    # 8. Save uploaded file metadata
    # --------------------------------------------------

    uploaded_file = UploadedFile(
        filename=file.filename,
        filepath=str(file_path),
        language=language,
        project_id=project_id,
        user_id=current_user.id
    )

    try:

        db.add(uploaded_file)

        db.commit()

        db.refresh(uploaded_file)

    except Exception:

        db.rollback()

        # Remove physical file if database operation fails
        if file_path.exists():
            file_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="Failed to save uploaded file information"
        )

    # --------------------------------------------------
    # 9. Return successful response
    # --------------------------------------------------

    return success_response(
    "File uploaded successfully",
    {
        "id": uploaded_file.id,
        "filename": uploaded_file.filename,
        "filepath": uploaded_file.filepath,
        "language": uploaded_file.language,
        "project_id": uploaded_file.project_id
    }
)
