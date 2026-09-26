from sqlalchemy.orm import Session

from models import Scan, Project

from logging_config import get_logger


logger = get_logger(__name__)


def get_report_data(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Prepare normalized data for report generation.

    Report generation remains separate from
    scan execution and database ownership logic.
    """

    logger.info(
        "Report data requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    scan = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(
            Scan.id == scan_id,
            Project.owner_id == user_id
        )
        .first()
    )

    if not scan:
        logger.warning(
            "Report data not found or unauthorized | scan_id=%s | user_id=%s",
            scan_id,
            user_id
        )
        return None

    return {
        "scan": scan,
        "project": scan.project,
        "vulnerabilities": scan.vulnerabilities
    }


def generate_json_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Generate report data intended for JSON export.
    """

    logger.info(
        "JSON report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    report_data = get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )

    if report_data is None:
        return None

    return report_data


def generate_html_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Placeholder interface for HTML report generation.
    """

    logger.info(
        "HTML report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    report_data = get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )

    if report_data is None:
        return None

    return report_data


def generate_pdf_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Placeholder interface for PDF report generation.

    Actual PDF rendering will be implemented later.
    """

    logger.info(
        "PDF report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    report_data = get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )

    if report_data is None:
        return None

    return report_data