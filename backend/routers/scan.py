
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Project, Scan, UploadedFile, Vulnerability, User
from schemas import ScanCreate
from routers.projects import get_authenticated_user
from services.scanner_service import run_scanner
from services.ai_service import analyze_finding, calculate_risk

router = APIRouter(prefix="/scans", tags=["Scans"])


def get_owned_scan(
    scan_id: int,
    user_id: int,
    db: Session,
) -> Scan:
    """Return a scan only if its project belongs to the current user."""
    scan = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(
            Scan.id == scan_id,
            Project.owner_id == user_id,
        )
        .first()
    )

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


def build_finding_response(item):
    """Convert a stored finding into an enriched API response."""
    finding = {
        "id": item.id,
        "file": item.file_name,
        "file_name": item.file_name,
        "line": item.line_number,
        "line_number": item.line_number,
        "vulnerability": item.vulnerability_type,
        "vulnerability_type": item.vulnerability_type,
        "severity": item.severity,
        "confidence": item.confidence,
        "code": item.code,
        "status": "Open",
    }

    enriched = analyze_finding(finding)

    severity_scores = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 0,
        "informational": 0,
    }

    enriched["risk_score"] = severity_scores.get(
        str(enriched.get("severity", "medium")).lower(),
        50,
    )
    enriched["ai_analysis"] = enriched.get("explanation")

    return enriched


@router.post("/")
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    # A user may scan only their own project.
    project = (
        db.query(Project)
        .filter(
            Project.id == scan_data.project_id,
            Project.owner_id == current_user.id,
        )
        .first()
    )

    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    uploaded_files = (
        db.query(UploadedFile)
        .filter(UploadedFile.project_id == project.id)
        .all()
    )

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project",
        )

    scan = Scan(project_id=project.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Avoid scanning the same physical path more than once.
        scanned_paths = set()

        for uploaded_file in uploaded_files:
            file_path = Path(uploaded_file.file_path)
            normalized_path = str(file_path.resolve()).casefold()

            if normalized_path in scanned_paths:
                continue

            scanned_paths.add(normalized_path)

            findings = run_scanner(str(file_path))

            for finding in findings:
                vulnerability = Vulnerability(
                    scan_id=scan.id,
                    file_name=finding.get("file", uploaded_file.filename),
                    line_number=finding.get("line"),
                    vulnerability_type=finding.get("vulnerability"),
                    severity=finding.get("severity"),
                    confidence=finding.get("confidence"),
                    code=finding.get("code"),
                )
                db.add(vulnerability)

        scan.status = "completed"
        db.commit()
        db.refresh(scan)

    except Exception as exc:
        db.rollback()

        failed_scan = db.query(Scan).filter(Scan.id == scan.id).first()
        if failed_scan is not None:
            failed_scan.status = "failed"
            db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Scanner failed: {str(exc)}",
        ) from exc

    stored_findings = [
        build_finding_response(item)
        for item in scan.vulnerabilities
    ]
    risk_summary = calculate_risk(stored_findings)

    return {
        "id": scan.id,
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "created_at": scan.created_at,
        "vulnerability_count": len(stored_findings),
        "risk_score": risk_summary["risk_score"],
        "risk_level": risk_summary["risk_level"],
        "critical_count": risk_summary["critical_count"],
        "high_count": risk_summary["high_count"],
        "medium_count": risk_summary["medium_count"],
        "low_count": risk_summary["low_count"],
        "results": stored_findings,
        "vulnerabilities": stored_findings,
    }


@router.get("/")
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    scans = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(Project.owner_id == current_user.id)
        .order_by(Scan.id.desc())
        .all()
    )

    return [
        {
            "id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
            "created_at": scan.created_at,
            "vulnerability_count": len(scan.vulnerabilities),
        }
        for scan in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    scan = get_owned_scan(scan_id, current_user.id, db)

    findings = [
        build_finding_response(item)
        for item in scan.vulnerabilities
    ]
    risk_summary = calculate_risk(findings)

    return {
        "id": scan.id,
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "created_at": scan.created_at,
        "vulnerability_count": len(findings),
        "risk_score": risk_summary["risk_score"],
        "risk_level": risk_summary["risk_level"],
        "critical_count": risk_summary["critical_count"],
        "high_count": risk_summary["high_count"],
        "medium_count": risk_summary["medium_count"],
        "low_count": risk_summary["low_count"],
        "vulnerabilities": findings,
        "results": findings,
    }
