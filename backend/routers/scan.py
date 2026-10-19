from pathlib import Path

from fastapi.responses import FileResponse

from services.report_service import (
    REPORT_DIR,
    REPORT_FORMATS,
    generate_json_report,
    generate_html_report,
    generate_pdf_report,
    render_report_file,
)
from response_utils import success_response
from datetime import datetime

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session, sessionmaker
from services.scan_worker import execute_scan_in_background
from database import get_db
from models import Project, Scan, UploadedFile, Vulnerability, User
from schemas import (
    ScanCreate,
    ScanResponse,
    VulnerabilityResponse,
    ScanResultResponse
)

# Authentication
from auth import get_current_user

# AI analysis pipeline
from services.scan_service import (
    create_scan,
    retry_failed_scan,
)
from services.scan_result_service import (
    get_scan_result,
    get_scan_history
)
router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
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


@router.post("/", status_code=202)
def create_scan_endpoint(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    current_user = get_authenticated_user(credentials, db)

    scan = create_scan(
        db=db,
        project_id=scan_data.project_id,
        user_id=current_user.id,
    )

    # Use the request's database engine, but create a separate
    # session for background execution.
    worker_session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db.get_bind(),
    )

    background_tasks.add_task(
        execute_scan_in_background,
        scan.id,
        worker_session_factory,
    )

    return success_response(
        "Scan accepted for processing",
        {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
        },
    )

@router.get("/")
def get_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    current_user = get_authenticated_user(
        credentials,
        db
    )

    results = get_scan_history(
        db=db,
        user_id=current_user.id,
        skip=skip,
        limit=limit
    )

    return success_response(
        "Scan history retrieved successfully",
        results
    )
@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    current_user = get_authenticated_user(
        credentials,
        db
    )

    result = get_scan_result(
        db=db,
        scan_id=scan_id,
        user_id=current_user.id
    )

    return success_response(
        "Scan details retrieved successfully",
        result
    )

@router.post("/{scan_id}/retry", status_code=202)
def retry_scan_endpoint(
    scan_id: int,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    current_user = get_authenticated_user(credentials, db)

    scan = retry_failed_scan(
        db=db,
        scan_id=scan_id,
        user_id=current_user.id,
    )

    worker_session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db.get_bind(),
    )

    background_tasks.add_task(
        execute_scan_in_background,
        scan.id,
        worker_session_factory,
    )

    return success_response(
        "Scan retry accepted for processing",
        {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
        },
    )

@router.get("/{scan_id}/report")
def download_scan_report(
    scan_id: int,
    report_format: str = Query("pdf", alias="format"),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Generate and download a report for a scan owned by the current user."""
    current_user = get_authenticated_user(credentials, db)

    if scan_id < 1:
        raise HTTPException(
            status_code=400,
            detail="scan_id must be a positive integer.",
        )

    if not isinstance(report_format, str):
        raise HTTPException(
            status_code=400,
            detail="Report format must be json, html, or pdf.",
        )

    normalized_format = report_format.strip().lower()

    report_generators = {
        "json": generate_json_report,
        "html": generate_html_report,
        "pdf": generate_pdf_report,
    }

    if normalized_format not in report_generators:
        raise HTTPException(
            status_code=400,
            detail="Unsupported report format. Choose json, html, or pdf.",
        )

    # The report service checks scan ownership before returning its data.
    report_data = report_generators[normalized_format](
        db=db,
        scan_id=scan_id,
        user_id=current_user.id,
    )

    try:
        metadata = render_report_file(
            report=report_data,
            scan_id=scan_id,
            report_format=normalized_format,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to generate the report file.",
        ) from exc

    # Resolve only the known filename generated from the validated scan ID.
    report_path = (REPORT_DIR / metadata["file_name"]).resolve()
    report_directory = REPORT_DIR.resolve()

    if report_path.parent != report_directory:
        raise HTTPException(
            status_code=500,
            detail="Invalid report file path.",
        )

    if not report_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Generated report file not found.",
        )

    return FileResponse(
        path=report_path,
        media_type=metadata["content_type"],
        filename=metadata["file_name"],
    )
