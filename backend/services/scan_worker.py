
import logging

from sqlalchemy.orm import Session, sessionmaker

from models import Scan, UploadedFile
from services.scan_lifecycle_service import (
    mark_scan_completed,
    mark_scan_running,
)
from services.scan_service import (
    fail_scan_safely,
    run_scan_pipeline,
)

logger = logging.getLogger(__name__)


def execute_scan_in_background(
    scan_id: int,
    session_factory: sessionmaker,
) -> None:
    """Execute a pending scan in an independently managed DB session."""
    db: Session = session_factory()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if scan is None:
            logger.error("Background scan not found: scan_id=%s", scan_id)
            return

        # Only pending scans may be claimed for execution.
        if scan.status != "pending":
            logger.warning(
                "Skipping scan: scan_id=%s status=%s",
                scan_id,
                scan.status,
            )
            return

        uploaded_files = (
            db.query(UploadedFile)
            .filter(UploadedFile.project_id == scan.project_id)
            .all()
        )

        if not uploaded_files:
            fail_scan_safely(
                db,
                scan_id,
                "No uploaded files are available for scanning.",
            )
            return

        mark_scan_running(scan)
        db.commit()

        logger.info("Background scan started: scan_id=%s", scan_id)

        try:
            run_scan_pipeline(db, scan, uploaded_files)
            mark_scan_completed(scan)
            db.commit()

            logger.info("Background scan completed: scan_id=%s", scan_id)

        except Exception:
            logger.exception(
                "Background scan execution failed: scan_id=%s",
                scan_id,
            )
            fail_scan_safely(
                db,
                scan_id,
                "Scan execution failed. Check server logs for details.",
            )

    except Exception:
        logger.exception(
            "Background scan initialization failed: scan_id=%s",
            scan_id,
        )
        try:
            fail_scan_safely(
                db,
                scan_id,
                "Scan initialization failed. Check server logs for details.",
            )
        except Exception:
            logger.exception(
                "Unable to persist scan failure: scan_id=%s",
                scan_id,
            )

    finally:
        db.close()