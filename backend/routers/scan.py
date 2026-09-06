from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
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
from scanner_client import run_scanner

# Authentication
from auth import get_current_user

# AI analysis pipeline
from services.ai_client import analyze_vulnerabilities


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


def calculate_scan_risk_score(scan):
    """
    Calculate the overall risk score for a scan
    using the highest vulnerability risk score.
    """

    risk_scores = [
        vulnerability.risk_score
        for vulnerability in scan.vulnerabilities
        if vulnerability.risk_score is not None
    ]

    if not risk_scores:
        return 0

    return max(risk_scores)


@router.post("/")
def create_scan(
    scan_data: ScanCreate,
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
    # 2. Verify project exists
    # ---------------------------------------------------------
    project = db.query(Project).filter(
        Project.id == scan_data.project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # ---------------------------------------------------------
    # 3. Verify project ownership
    # ---------------------------------------------------------
    if project.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to scan this project"
        )

    # ---------------------------------------------------------
    # 4. Get uploaded files
    # ---------------------------------------------------------
    uploaded_files = db.query(UploadedFile).filter(
        UploadedFile.project_id == scan_data.project_id
    ).all()

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project"
        )

    # ---------------------------------------------------------
    # 5. Create scan with PENDING status
    # ---------------------------------------------------------
    scan = Scan(
        project_id=scan_data.project_id,
        status="pending"
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # ---------------------------------------------------------
    # 6. Change status to RUNNING
    # ---------------------------------------------------------
    scan.status = "running"
    scan.started_at = datetime.utcnow()

    db.commit()
    db.refresh(scan)

    results = []

    try:
        # -----------------------------------------------------
        # 7. Run scanner on all uploaded files
        # -----------------------------------------------------
        for uploaded_file in uploaded_files:

            file_results = run_scanner(
                uploaded_file.filepath
            )

            if file_results:
                results.extend(file_results)

        # -----------------------------------------------------
        # 8. Send scanner findings to AI analysis
        # -----------------------------------------------------
        if results:
            results = analyze_vulnerabilities(results)

        # -----------------------------------------------------
        # 9. Store vulnerability results in database
        # -----------------------------------------------------
        for result in results:

            vulnerability = Vulnerability(
                scan_id=scan.id,
                file_name=result.get("file"),
                line_number=result.get("line"),
                vulnerability_type=result.get("vulnerability"),
                severity=result.get("severity"),
                confidence=result.get("confidence"),
                code=result.get("code"),
                risk_score=result.get("risk_score"),
                owasp_category=result.get("owasp"),
                cwe_id=result.get("cwe"),
                explanation=result.get("explanation"),
                impact=result.get("impact"),
                recommendation=result.get("recommendation")
            )

            db.add(vulnerability)

        db.commit()

        # -----------------------------------------------------
        # 10. Mark scan as COMPLETED
        # -----------------------------------------------------
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.error_message = None

        db.commit()
        db.refresh(scan)

    except Exception as e:

        # -----------------------------------------------------
        # 11. Roll back uncommitted database changes
        # -----------------------------------------------------
        db.rollback()

        # -----------------------------------------------------
        # 12. Mark scan as FAILED
        # -----------------------------------------------------
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()
        scan.error_message = str(e)

        db.commit()

        raise HTTPException(
            status_code=500,
            detail="Scanner failed. Please check the scan details for more information."
        )

    # ---------------------------------------------------------
    # 13. Return scan result
    # ---------------------------------------------------------
    return {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "results": results
    }


@router.get("/")
def get_scans(
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
    # 2. Get only scans belonging to user's projects
    # ---------------------------------------------------------
    scans = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(Project.owner_id == current_user.id)
        .all()
    )

    result = []

    for scan in scans:

        risk_score = calculate_scan_risk_score(scan)

        result.append({
            "id": scan.id,
            "project_id": scan.project_id,
            "project_name": scan.project.project_name,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
            "error_message": scan.error_message,
            "vulnerability_count": len(
                scan.vulnerabilities
            ),
            "risk_score": risk_score
        })

    return result


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
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
    # 2. Find scan
    # ---------------------------------------------------------
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # ---------------------------------------------------------
    # 3. Verify project ownership
    # ---------------------------------------------------------
    project = db.query(Project).filter(
        Project.id == scan.project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    if project.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view this scan"
        )

    # ---------------------------------------------------------
    # 4. Calculate overall risk score
    # ---------------------------------------------------------
    risk_score = calculate_scan_risk_score(scan)

    # ---------------------------------------------------------
    # 5. Return scan details
    # ---------------------------------------------------------
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": project.project_name,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "error_message": scan.error_message,
        "vulnerability_count": len(
            scan.vulnerabilities
        ),
        "risk_score": risk_score,
        "vulnerabilities": [
            {
                "id": vulnerability.id,
                "file_name": vulnerability.file_name,
                "line_number": vulnerability.line_number,
                "vulnerability_type": vulnerability.vulnerability_type,
                "severity": vulnerability.severity,
                "confidence": vulnerability.confidence,
                "code": vulnerability.code,
                "risk_score": vulnerability.risk_score,
                "owasp_category": vulnerability.owasp_category,
                "cwe_id": vulnerability.cwe_id,
                "explanation": vulnerability.explanation,
                "impact": vulnerability.impact,
                "recommendation": vulnerability.recommendation
            }
            for vulnerability in scan.vulnerabilities
        ]
    }