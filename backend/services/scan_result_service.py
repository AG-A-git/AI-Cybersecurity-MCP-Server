from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import Project, Scan


def get_owned_scan(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Retrieve a scan only if it belongs to a project
    owned by the authenticated user.
    """

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    project = (
        db.query(Project)
        .filter(Project.id == scan.project_id)
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


def calculate_scan_risk_score(scan: Scan) -> int:
    """
    Return the highest vulnerability risk score
    for the scan.
    """

    risk_scores = [
        vulnerability.risk_score
        for vulnerability in scan.vulnerabilities
        if vulnerability.risk_score is not None
    ]

    if not risk_scores:
        return 0

    return max(risk_scores)


def serialize_vulnerability(vulnerability):
    """
    Convert a Vulnerability model into the standard
    API representation.
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


def serialize_scan(scan, project):
    """
    Convert a Scan model into the standard API response.
    """

    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "project_name": project.project_name,
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "vulnerability_count": len(scan.vulnerabilities),
        "risk_score": calculate_scan_risk_score(scan),
        "vulnerabilities": [
            serialize_vulnerability(vulnerability)
            for vulnerability in scan.vulnerabilities
        ]
    }

def get_scan_result(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Get complete details for one owned scan.
    """

    scan, project = get_owned_scan(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )

    return serialize_scan(scan, project)


def get_scan_history(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 10
):
    """
    Get scan history belonging only to the authenticated user.
    """

    scans = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(Project.owner_id == user_id)
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
            "vulnerability_count": len(scan.vulnerabilities),
            "risk_score": calculate_scan_risk_score(scan)
        })

    return results