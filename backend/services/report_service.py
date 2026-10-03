from sqlalchemy.orm import Session

from models import Scan, Project

from logging_config import get_logger
from services.scan_result_service import get_scan_result


logger = get_logger(__name__)


def get_report_data(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Prepare normalized, report-ready data for a scan.

    Ownership and scan serialization are delegated to the
    standardized scan-result service.
    """

    logger.info(
        "Report data requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    return get_scan_result(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )


def generate_json_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Generate normalized data intended for JSON export.
    """

    logger.info(
        "JSON report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    return get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )


def generate_html_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Prepare normalized data for HTML report generation.

    Actual HTML rendering remains separate.
    """

    logger.info(
        "HTML report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    return get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )


def generate_pdf_report(
    db: Session,
    scan_id: int,
    user_id: int
):
    """
    Prepare normalized data for PDF report generation.

    Actual PDF rendering remains separate.
    """

    logger.info(
        "PDF report requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id
    )

    return get_report_data(
        db=db,
        scan_id=scan_id,
        user_id=user_id
    )