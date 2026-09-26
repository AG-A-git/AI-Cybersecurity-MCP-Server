from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import Project, Scan, UploadedFile, Vulnerability
from scanner_client import run_scanner
from services.ai_client import analyze_vulnerabilities

from logging_config import get_logger

logger = get_logger(__name__)


def normalize_scanner_finding(finding: dict) -> dict:
    """
    Normalize a scanner finding into the backend contract.
    The scanner remains responsible for detection.
    The backend only guarantees a stable structure
    for downstream AI, risk, persistence, and APIs.
    """
    return {
        "file": finding.get("file"),
        "line": finding.get("line"),
        "vulnerability": finding.get("vulnerability"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "code": finding.get("code")
    }


def create_scan(db: Session, project_id: int, user_id: int):
    """
    Create and execute a complete scan for an owned project.

    Responsibilities:
    - Validate project ownership
    - Validate uploaded files
    - Create scan record
    - Execute scanner
    - Execute AI analysis
    - Persist vulnerabilities
    - Complete or fail the scan safely
    """

    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    if project.owner_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to scan this project"
        )

    logger.info(
        "Scan requested | project_id=%s | user_id=%s",
        project_id,
        user_id
    )

    uploaded_files = (
        db.query(UploadedFile)
        .filter(UploadedFile.project_id == project_id)
        .all()
    )

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project"
        )

    scan = Scan(
        project_id=project_id,
        status="pending"
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.error_message = None

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan started | scan_id=%s | project_id=%s | user_id=%s",
            scan.id,
            project_id,
            user_id
        )

        logger.info(
            "Scanner execution started | scan_id=%s | files=%s",
            scan.id,
            len(uploaded_files)
        )

        results = []

        for uploaded_file in uploaded_files:
            file_results = run_scanner(uploaded_file.filepath)

            if file_results:
                normalized_results = [
                    normalize_scanner_finding(finding)
                    for finding in file_results
                ]

                results.extend(normalized_results)

        logger.info(
            "Scanner execution completed | scan_id=%s | findings=%s",
            scan.id,
            len(results)
        )

        if results:
            logger.info(
                "AI analysis started | scan_id=%s | findings=%s",
                scan.id,
                len(results)
            )

            try:
                results = analyze_vulnerabilities(results)

            except Exception:
                logger.exception(
                    "AI analysis failed | scan_id=%s | findings=%s",
                    scan.id,
                    len(results)
                )
                raise

            logger.info(
                "AI analysis completed | scan_id=%s | findings=%s",
                scan.id,
                len(results)
            )

        # AI contract:
        # file, line, vulnerability, severity, confidence,
        # risk_score, owasp, cwe, explanation,
        # impact, recommendation, secure_practice

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

        try:
            db.commit()

        except Exception:
            logger.exception(
                "Database persistence failed | scan_id=%s | project_id=%s",
                scan.id,
                project_id
            )
            raise

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.error_message = None

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan completed | scan_id=%s | project_id=%s | findings=%s",
            scan.id,
            project_id,
            len(results)
        )

        return scan, results

    except Exception:
        logger.exception(
            "Scan failed | scan_id=%s | project_id=%s | user_id=%s",
            scan.id,
            project_id,
            user_id
        )

        db.rollback()

        failed_scan = (
            db.query(Scan)
            .filter(Scan.id == scan.id)
            .first()
        )

        if failed_scan:
            failed_scan.status = "failed"
            failed_scan.completed_at = datetime.utcnow()
            failed_scan.error_message = "Scan execution failed"

            db.commit()

        raise HTTPException(
            status_code=500,
            detail="Scan failed. Please check the scan details for more information."
        )