from services.ai_client import analyze_vulnerabilities
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Project, Scan, UploadedFile, Vulnerability
from schemas import (
    ScanCreate,
    ScanResponse,
    VulnerabilityResponse,
    ScanResultResponse
)
from scanner_client import run_scanner


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


# ==========================================
# POST /scans/
# Create and run a scan
# ==========================================

@router.post("/")
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db)
):
    # ------------------------------------------
    # 1. Check if project exists
    # ------------------------------------------

    project = db.query(Project).filter(
        Project.id == scan_data.project_id
    ).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # ------------------------------------------
    # 2. Get uploaded files for this project
    # ------------------------------------------

    uploaded_files = db.query(UploadedFile).filter(
        UploadedFile.project_id == scan_data.project_id
    ).all()

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project"
        )

    # ------------------------------------------
    # 3. Create scan
    # ------------------------------------------

    scan = Scan(
        project_id=scan_data.project_id,
        status="running",
        started_at=datetime.utcnow()
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # ------------------------------------------
    # 4. Run scanner
    # ------------------------------------------

    results = []

    try:

        for uploaded_file in uploaded_files:

            file_results = run_scanner(
                uploaded_file.filepath
            )

            results.extend(file_results)
            
            # ------------------------------------------
            # Run AI analysis on scanner results
            # ------------------------------------------

            if results:
                results = analyze_vulnerabilities(results)

        # ------------------------------------------
        # 5. Store scanner results in database
        # ------------------------------------------

        for result in results:
            vulnerability = Vulnerability(
                scan_id=scan.id,
                file_name=result.get("file"),
                line_number=result.get("line"),
                vulnerability_type=result.get("vulnerability"),
                severity=result.get("severity"),
                confidence=result.get("confidence"),
                code=result.get("code"),

                # AI analysis
                risk_score=result.get("risk_score"),
                owasp_category=result.get("owasp"),
                cwe_id=result.get("cwe"),
                explanation=result.get("explanation"),
                impact=result.get("impact"),
                recommendation=result.get("recommendation")
            )

            db.add(vulnerability)

        db.commit()

        # ------------------------------------------
        # 6. Mark scan as completed
        # ------------------------------------------

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(scan)

    except Exception as e:

        # ------------------------------------------
        # 7. Handle scanner failure
        # ------------------------------------------

        scan.status = "failed"
        scan.completed_at = datetime.utcnow()

        db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Scanner failed: {str(e)}"
        )

    # ------------------------------------------
    # 8. Return scan results
    # ------------------------------------------

    return {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "results": results
    }


# ==========================================
# GET /scans/
# Get scan history
# ==========================================

@router.get("/")
def get_scans(
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).all()

    result = []

    for scan in scans:

        result.append({
            "id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
            "vulnerability_count": len(scan.vulnerabilities)
        })

    return result


# ==========================================
# GET /scans/{scan_id}
# Get individual scan + complete vulnerabilities
# ==========================================

@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "vulnerability_count": len(scan.vulnerabilities),

        "vulnerabilities": [
            {
                "id": vulnerability.id,
                "file_name": vulnerability.file_name,
                "line_number": vulnerability.line_number,
                "vulnerability_type": vulnerability.vulnerability_type,
                "severity": vulnerability.severity,
                "confidence": vulnerability.confidence,
                "code": vulnerability.code,

                # AI analysis fields
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