from sqlalchemy.exc import IntegrityError
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
    mark_scan_failed,
)

logger = get_logger(__name__)


def execute_scanner(filepath: str, scan_id: int):
    """
    Execute the scanner and enforce the scanner/backend contract.
    """

    try:
        results = run_scanner(filepath)

        if results is None:
            return []

        if not isinstance(results, list):
            raise ValueError(
                "Scanner returned an invalid result format"
            )

        return results

    except Exception:
        logger.exception(
            "Scanner execution failed | scan_id=%s",
            scan_id,
        )
        raise


def normalize_scanner_finding(finding: dict) -> dict:
    """
    Normalize a raw scanner finding into the backend finding contract.
    """

    if not isinstance(finding, dict):
        raise ValueError(
            "Scanner finding must be a dictionary"
        )

    file_path = finding.get("file")
    line_number = finding.get("line")
    vulnerability = finding.get("vulnerability")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    code = finding.get("code")

    return {
        "file": (
            str(file_path).strip()
            if file_path is not None
            else None
        ),
        "line": line_number,
        "vulnerability": (
            str(vulnerability).strip()
            if vulnerability is not None
            else None
        ),
        "severity": (
            str(severity).strip().title()
            if severity is not None
            else None
        ),
        "confidence": confidence,
        "code": (
            str(code).strip()
            if code is not None
            else None
        ),
    }


def validate_finding(finding: dict) -> None:
    """
    Validate the normalized/enriched finding contract.
    """

    required_fields = {
        "file": "Finding file is required",
        "vulnerability": "Finding vulnerability type is required",
        "severity": "Finding severity is required",
    }

    for field, message in required_fields.items():
        value = finding.get(field)

        if value is None:
            raise ValueError(message)

        if isinstance(value, str) and not value.strip():
            raise ValueError(message)

    if finding.get("line") is not None:
        if (
            isinstance(finding["line"], bool)
            or not isinstance(finding["line"], int)
            or finding["line"] < 1
        ):
            raise ValueError(
                "Finding line must be a positive integer"
            )

    if finding.get("confidence") is not None:
        if (
            isinstance(finding["confidence"], bool)
            or not isinstance(finding["confidence"], int)
        ):
            raise ValueError(
                "Finding confidence must be an integer"
            )

        if not 0 <= finding["confidence"] <= 100:
            raise ValueError(
                "Finding confidence must be between 0 and 100"
            )

    if finding.get("risk_score") is not None:
        if (
            isinstance(finding["risk_score"], bool)
            or not isinstance(
                finding["risk_score"],
                (int, float)
            )
        ):
            raise ValueError(
                "Finding risk score must be numeric"
            )

        if not 0 <= finding["risk_score"] <= 100:
            raise ValueError(
                "Finding risk score must be between 0 and 100"
            )

    if finding.get("severity") not in {
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    }:
        raise ValueError(
            f"Unsupported finding severity: "
            f"{finding.get('severity')}"
        )


def finding_identity(finding: dict) -> tuple:
    """
    Return the identity used to detect duplicate findings.

    A finding is considered the same when it has the same:
    - file
    - line
    - vulnerability type
    """

    return (
        finding.get("file"),
        finding.get("line"),
        finding.get("vulnerability"),
    )


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Remove duplicate findings while preserving their original order.

    The first occurrence of a finding is retained.
    """

    seen = set()
    unique_findings = []

    for finding in findings:
        identity = finding_identity(finding)

        if identity in seen:
            continue

        seen.add(identity)
        unique_findings.append(finding)

    return unique_findings


def persist_findings(
    db: Session,
    scan_id: int,
    findings: list[dict],
) -> int:
    """
    Persist validated vulnerability findings
    within the caller's existing transaction.
    """

    if (
        isinstance(scan_id, bool)
        or not isinstance(scan_id, int)
        or scan_id <= 0
    ):
        raise ValueError("Invalid scan ID")

    if not isinstance(findings, list):
        raise ValueError(
            "Findings must be provided as a list"
        )

    scan_exists = (
        db.query(Scan.id)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan_exists:
        raise ValueError(
            "Cannot persist findings for a missing scan"
        )

    persisted_count = 0

    for finding in findings:
        validate_finding(finding)

        vulnerability = Vulnerability(
            scan_id=scan_id,
            file_name=finding["file"],
            line_number=finding.get("line"),
            vulnerability_type=finding["vulnerability"],
            severity=finding["severity"],
            confidence=finding.get("confidence"),
            code=finding.get("code"),
            risk_score=finding.get("risk_score"),
            owasp_category=finding.get("owasp"),
            cwe_id=finding.get("cwe"),
            explanation=finding.get("explanation"),
            impact=finding.get("impact"),
            recommendation=finding.get("recommendation"),
        )

        db.add(vulnerability)
        persisted_count += 1

    db.flush()

    return persisted_count


def fail_scan_safely(
    db: Session,
    scan_id: int,
    error_message: str,
) -> None:
    """
    Safely transition a scan into FAILED state after
    rolling back the failed transaction.
    """

    try:
        db.rollback()

        failed_scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if not failed_scan:
            logger.error(
                "Unable to mark scan failed because scan "
                "was not found | scan_id=%s",
                scan_id,
            )
            return

        if failed_scan.status in {
            ScanStatus.PENDING.value,
            ScanStatus.RUNNING.value,
        }:
            mark_scan_failed(
                failed_scan,
                error_message,
            )

            db.commit()

            logger.info(
                "Scan marked failed | scan_id=%s | error=%s",
                scan_id,
                error_message,
            )

    except Exception:
        db.rollback()

        logger.exception(
            "CRITICAL: Failed to persist scan failure state "
            "| scan_id=%s",
            scan_id,
        )


def run_scan_pipeline(
    db: Session,
    scan: Scan,
    uploaded_files: list[UploadedFile],
) -> list[dict]:
    """
    Execute the complete scanner → normalization → validation
    → deduplication → AI → persistence pipeline.
    """

    results = []

    logger.info(
        "Scan pipeline started | scan_id=%s | files=%s",
        scan.id,
        len(uploaded_files),
    )

    # ---------------------------------------------------------
    # Scanner stage
    # ---------------------------------------------------------

    for uploaded_file in uploaded_files:
        file_results = execute_scanner(
            uploaded_file.filepath,
            scan.id,
        )

        if not file_results:
            continue

        for finding in file_results:
            normalized_finding = normalize_scanner_finding(
                finding
            )

            validate_finding(
                normalized_finding
            )

            results.append(
                normalized_finding
            )

    raw_finding_count = len(results)

    logger.info(
        "Scanner stage completed | scan_id=%s | findings=%s",
        scan.id,
        raw_finding_count,
    )

    # ---------------------------------------------------------
    # Deduplication stage
    # ---------------------------------------------------------

    results = deduplicate_findings(results)

    unique_finding_count = len(results)

    logger.info(
        "Finding deduplication completed | "
        "scan_id=%s | raw=%s | unique=%s",
        scan.id,
        raw_finding_count,
        unique_finding_count,
    )

    # ---------------------------------------------------------
    # AI stage
    # ---------------------------------------------------------

    if results:
        results = analyze_vulnerabilities(results)

        logger.info(
            "AI stage completed | scan_id=%s | findings=%s",
            scan.id,
            len(results),
        )

    # ---------------------------------------------------------
    # Validate AI results
    # ---------------------------------------------------------

    for finding in results:
        validate_finding(finding)

    # ---------------------------------------------------------
    # Persistence stage
    # ---------------------------------------------------------

    # Findings are added to the current database transaction.
    # The scan is committed only after the complete pipeline
    # succeeds.

    persisted_count = persist_findings(
        db,
        scan.id,
        results,
    )

    logger.info(
        "Persistence stage completed | scan_id=%s | findings=%s",
        scan.id,
        persisted_count,
    )

    return results



def create_scan(
    db: Session,
    project_id: int,
    user_id: int,
):
    """Validate and create a pending scan without executing it."""

    project = (
        db.query(Project)
        .filter(Project.id == project_id)
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    if project.owner_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to scan this project",
        )

    uploaded_files = (
        db.query(UploadedFile)
        .filter(UploadedFile.project_id == project_id)
        .all()
    )

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project",
        )

    active_scan = (
        db.query(Scan)
        .filter(
            Scan.project_id == project_id,
            Scan.status.in_([
                ScanStatus.PENDING.value,
                ScanStatus.RUNNING.value,
            ]),
        )
        .first()
    )

    if active_scan:
        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress for this project",
        )

    scan = Scan(
        project_id=project_id,
        status=ScanStatus.PENDING.value,
    )

    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)

    except IntegrityError as exc:
        db.rollback()
        logger.warning(
            "Concurrent scan creation rejected | project_id=%s | user_id=%s",
            project_id,
            user_id,
        )
        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress for this project",
        ) from exc

    logger.info(
        "Scan queued | scan_id=%s | project_id=%s | user_id=%s",
        scan.id,
        project_id,
        user_id,
    )

    return scan

def retry_failed_scan(
    db: Session,
    scan_id: int,
    user_id: int,
):
    """
    Retry a previously failed scan.
    """

    scan = (
        db.query(Scan)
        .join(
            Project,
            Scan.project_id == Project.id,
        )
        .filter(
            Scan.id == scan_id,
            Project.owner_id == user_id,
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    if scan.status != ScanStatus.FAILED.value:
        raise HTTPException(
            status_code=409,
            detail="Only failed scans can be retried",
        )

    project = (
        db.query(Project)
        .filter(Project.id == scan.project_id)
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    uploaded_files = (
        db.query(UploadedFile)
        .filter(
            UploadedFile.project_id == scan.project_id
        )
        .all()
    )

    if not uploaded_files:
        raise HTTPException(
            status_code=400,
            detail="No uploaded files found for this project",
        )

    try:
        scan.status = ScanStatus.PENDING.value
        scan.started_at = None
        scan.completed_at = None
        scan.error_message = None

        db.commit()
        db.refresh(scan)

        logger.info(
            "Failed scan reset for retry | "
            "scan_id=%s | user_id=%s",
            scan.id,
            user_id,
        )

    except Exception:
        db.rollback()

        logger.exception(
            "Failed to reset scan for retry | scan_id=%s",
            scan.id,
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retry scan",
        )

    try:
        mark_scan_running(scan)

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan retry started | "
            "scan_id=%s | project_id=%s | user_id=%s",
            scan.id,
            scan.project_id,
            user_id,
        )

        results = run_scan_pipeline(
            db=db,
            scan=scan,
            uploaded_files=uploaded_files,
        )

        mark_scan_completed(scan)

        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan retry completed | "
            "scan_id=%s | project_id=%s",
            scan.id,
            scan.project_id,
        )

        return scan, results

    except Exception:
        logger.exception(
            "Scan retry failed | "
            "scan_id=%s | project_id=%s",
            scan.id,
            scan.project_id,
        )

        fail_scan_safely(
            db,
            scan.id,
            "Scan retry failed",
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Scan retry failed. Please check the scan details "
                "for more information."
            ),
        )