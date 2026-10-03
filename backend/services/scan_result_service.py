from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import Project, Scan


def get_owned_project(
    db: Session,
    project_id: int,
    user_id: int
) -> Project:
    """
    Retrieve a project only when it belongs to the authenticated user.
    """

    project = (
        db.query(Project)
        .filter(
            Project.id == project_id
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    if project.owner_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this project"
        )

    return project


def get_owned_scan(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Retrieve a scan and enforce project ownership.

    A missing scan returns 404.
    An existing scan belonging to another user returns 403.
    """

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    project = (
        db.query(Project)
        .filter(
            Project.id == scan.project_id
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    if project.owner_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this scan"
        )

    return scan, project


def calculate_scan_risk_score(
    scan: Scan
) -> int:
    """
    Calculate the overall risk score for a scan.

    The highest vulnerability risk score is used as the
    scan-level risk score.

    Returns:
        Integer between 0 and 100.
    """

    risk_scores = [
        vulnerability.risk_score
        for vulnerability in scan.vulnerabilities
        if vulnerability.risk_score is not None
    ]

    if not risk_scores:
        return 0

    return max(
        risk_scores
    )


def calculate_severity_counts(
    vulnerabilities: list
) -> dict:
    """
    Calculate the number of findings for each supported
    vulnerability severity.

    Expects Vulnerability ORM objects.
    """

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for vulnerability in vulnerabilities:

        if not vulnerability.severity:
            continue

        severity = (
            vulnerability.severity
            .strip()
            .lower()
        )

        if severity in severity_counts:
            severity_counts[severity] += 1

    return severity_counts


def validate_scan_summary(
    total_findings: int,
    severity_counts: dict
) -> None:
    """
    Ensure severity counts always match the total
    number of persisted vulnerability findings.
    """

    severity_total = sum(
        severity_counts.values()
    )

    if severity_total != total_findings:
        raise ValueError(
            "Scan summary severity counts do not "
            "match total findings"
        )


def serialize_vulnerability(
    vulnerability
) -> dict:
    """
    Convert a Vulnerability ORM object into the
    public API response contract.
    """

    return {
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


def serialize_scan(
    scan: Scan,
    project: Project
) -> dict:
    """
    Convert a Scan ORM object into the standardized
    scan-result response contract.
    """

    # IMPORTANT:
    # Calculate severity counts while vulnerabilities
    # are still ORM objects.
    severity_counts = calculate_severity_counts(
        scan.vulnerabilities
    )

    total_findings = len(
        scan.vulnerabilities
    )

    validate_scan_summary(
        total_findings=total_findings,
        severity_counts=severity_counts
    )

    # Serialize only after all ORM-level calculations
    # have been completed.
    vulnerabilities = [
        serialize_vulnerability(
            vulnerability
        )
        for vulnerability in scan.vulnerabilities
    ]

    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": project.project_name,
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,

        "total_findings": total_findings,

        # Keep the existing field for backward compatibility.
        "vulnerability_count": total_findings,

        "severity_counts": severity_counts,

        "risk_score": calculate_scan_risk_score(
            scan
        ),

        "vulnerabilities": vulnerabilities
    }


def get_scan_result(
    db: Session,
    scan_id: int,
    user_id: int
) -> dict:
    """
    Return the complete result of a scan owned by the user.
    """

    scan, project = get_owned_scan(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )

    return serialize_scan(
        scan,
        project
    )


def get_scan_history(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 10
) -> list[dict]:
    """
    Return paginated scan history belonging only to the
    authenticated user.
    """

    if skip < 0:
        raise ValueError(
            "skip must be greater than or equal to 0"
        )

    if limit < 1:
        raise ValueError(
            "limit must be greater than 0"
        )

    limit = min(
        limit,
        100
    )

    scans = (
        db.query(Scan)
        .join(
            Project,
            Scan.project_id == Project.id
        )
        .filter(
            Project.owner_id == user_id
        )
        .order_by(
            Scan.created_at.desc(),
            Scan.id.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )

    results = []

    for scan in scans:

        vulnerabilities = scan.vulnerabilities

        total_findings = len(
            vulnerabilities
        )

        severity_counts = calculate_severity_counts(
            vulnerabilities
        )

        validate_scan_summary(
            total_findings=total_findings,
            severity_counts=severity_counts
        )

        results.append({
            "id": scan.id,
            "project_id": scan.project_id,
            "project_name": scan.project.project_name,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "created_at": scan.created_at,
            "error_message": scan.error_message,

            "total_findings": total_findings,

            # Keep the old field for existing frontend code.
            "vulnerability_count": total_findings,

            "severity_counts": severity_counts,

            "risk_score": calculate_scan_risk_score(
                scan
            )
        })

    return results