from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import Project, Scan, UploadedFile, Vulnerability
from scanner_client import run_scanner
from services.ai_client import analyze_vulnerabilities
from logging_config import get_logger

from services.scan_states import ScanStatus
from services.scan_lifecycle_service import (
    mark_scan_running,
    mark_scan_completed,
    mark_scan_failed
)


logger = get_logger(__name__)


def execute_scanner(filepath: str, scan_id: int):
    """
    Execute the scanner with backend-level failure logging.

    Scanner implementation remains responsible for detection.
    This boundary is responsible for execution observability.
    """

    try:
        return run_scanner(filepath)

    except Exception:
        logger.exception(
            "Scanner execution failed | scan_id=%s | filepath=%s",
            scan_id,
            filepath
        )
        raise


def normalize_scanner_finding(finding: dict) -> dict:
    """
    Normalize a scanner finding into the backend contract.

    The scanner remains responsible for detection.
    The backend guarantees a stable structure for downstream
    AI, risk, persistence, and API layers.
    """

    return {
        "file": finding.get("file"),
        "line": finding.get("line"),
        "vulnerability": finding.get("vulnerability"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "code": finding.get("code")
    }

def validate_finding(finding: dict) -> None:
    """
    Validate the minimum backend contract for a vulnerability finding.

    Detection remains the scanner's responsibility.
    This validation only ensures that malformed findings do not
    reach the persistence layer.
    """

    required_fields = {
        "file": "Finding file is required",
        "vulnerability": "Finding vulnerability type is required",
        "severity": "Finding severity is required"
    }

    for field, message in required_fields.items():
        value = finding.get(field)

        if value is None or (
            isinstance(value, str) and not value.strip()
        ):
            raise ValueError(message)

    if finding.get("line") is not None:
        if not isinstance(finding["line"], int) or finding["line"] < 1:
            raise ValueError("Finding line must be a positive integer")

    if finding.get("confidence") is not None:
        if not isinstance(finding["confidence"], int):
            raise ValueError("Finding confidence must be an integer")

        if not 0 <= finding["confidence"] <= 100:
            raise ValueError("Finding confidence must be between 0 and 100")

def create_scan(db: Session, project_id: int, user_id: int):
    """
    Create and execute a complete scan for an owned project.

    Responsibilities:
    - Validate project ownership
    - Validate uploaded files
    - Prevent duplicate active scans
    - Create scan record
    - Execute scanner
    - Execute AI analysis
    - Persist vulnerabilities
    - Complete or fail the scan safely
    """

    # ---------------------------------------------------------
    # 1. Validate project
    # ---------------------------------------------------------

    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    # ---------------------------------------------------------
    # 2. Validate project ownership
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # 3. Get uploaded files
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # 4. Prevent duplicate active scans
    # ---------------------------------------------------------

    active_scan = (
        db.query(Scan)
        .filter(
            Scan.project_id == project_id,
            Scan.status.in_([
                ScanStatus.PENDING.value,
                ScanStatus.RUNNING.value
            ])
        )
        .first()
    )

    if active_scan:
        logger.warning(
            "Active scan already exists | scan_id=%s | project_id=%s",
            active_scan.id,
            project_id
        )

        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress for this project"
        )

    # ---------------------------------------------------------
    # 5. Create pending scan
    # ---------------------------------------------------------

    scan = Scan(
        project_id=project_id,
        status=ScanStatus.PENDING.value
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:

        # -----------------------------------------------------
        # 6. Mark scan as running
        # -----------------------------------------------------

        mark_scan_running(scan)

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan started | scan_id=%s | project_id=%s | user_id=%s",
            scan.id,
            project_id,
            user_id
        )

        # -----------------------------------------------------
        # 7. Execute scanner
        # -----------------------------------------------------

        logger.info(
            "Scanner execution started | scan_id=%s | files=%s",
            scan.id,
            len(uploaded_files)
        )

        results = []

        for uploaded_file in uploaded_files:

            file_results = execute_scanner(
                uploaded_file.filepath,
                scan.id
            )

            if file_results:

                normalized_results = []

                for finding in file_results:
                  normalized_finding = normalize_scanner_finding(finding)
                  validate_finding(normalized_finding)
                  normalized_results.append(normalized_finding)
                results.extend(normalized_results)

        logger.info(
            "Scanner execution completed | scan_id=%s | findings=%s",
            scan.id,
            len(results)
        )

        # -----------------------------------------------------
        # 8. AI analysis
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # 9. Persist vulnerabilities
        # -----------------------------------------------------

        # AI contract:
        #
        # file
        # line
        # vulnerability
        # severity
        # confidence
        # risk_score
        # owasp
        # cwe
        # explanation
        # impact
        # recommendation
        # secure_practice

                # -----------------------------------------------------
        # 9. Persist vulnerabilities transaction-safely
        # -----------------------------------------------------

        try:

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

            db.flush()

        except Exception:

            logger.exception(
                "Finding persistence failed | scan_id=%s | project_id=%s",
                scan.id,
                project_id
            )

            db.rollback()
            raise

        # -----------------------------------------------------
        # 11. Mark scan completed
        # -----------------------------------------------------

        mark_scan_completed(scan)

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan completed | scan_id=%s | project_id=%s | findings=%s",
            scan.id,
            project_id,
            len(results)
        )

        return scan, results

    # ---------------------------------------------------------
    # 12. Failure handling
    # ---------------------------------------------------------

    except Exception as exc:

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

            mark_scan_failed(
                failed_scan,
                f"Scan execution failed: {type(exc).__name__}"
            )

            db.commit()

        raise HTTPException(
            status_code=500,
            detail="Scan failed. Please check the scan details for more information."
        )
