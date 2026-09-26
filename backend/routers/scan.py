from response_utils import success_response
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

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
from services.scan_service import create_scan
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

@router.post("/")
def create_scan_endpoint(
    scan_data: ScanCreate,
    credentials=Depends(security),
    db=Depends(get_db)
):
    current_user = get_authenticated_user(credentials, db)

    scan, results = create_scan(
        db=db,
        project_id=scan_data.project_id,
        user_id=current_user.id
    )

    return success_response(
        "Scan completed successfully",
        {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
            "results": results
        }
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