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
        "vulnerability_count": len(vulnerabilities),
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

        results.append({
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
            "risk_score": calculate_scan_risk_score(
                scan
            )
        })

    return results