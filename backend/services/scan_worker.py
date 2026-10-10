import logging

from sqlalchemy import update
from sqlalchemy.orm import Session, sessionmaker

from models import Scan, UploadedFile
from services.scan_lifecycle_service import (
    mark_scan_completed,
    mark_scan_failed,
    mark_scan_running,
)
from services.scan_service import (
    fail_scan_safely,
    run_scan_pipeline,
)
from services.time_service import utc_now

logger = logging.getLogger(__name__)


def execute_scan_in_background(
    scan_id: int,
    session_factory: sessionmaker,
) -> None:
    """Atomically claim and execute a pending scan."""
    db: Session = session_factory()

    try:
        # Claim the scan atomically. Only one worker can change
        # the same pending scan to running.
        claim_result = db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "pending",
            )
            .values(
                status="running",
                started_at=utc_now(),
                completed_at=None,
                error_message=None,
            )
        )

        if claim_result.rowcount != 1:
            db.rollback()

            existing_scan = (
                db.query(Scan)
                .filter(Scan.id == scan_id)
                .first()
            )

            if existing_scan is None:
                logger.error(
                    "Background scan not found: scan_id=%s",
                    scan_id,
                )
            else:
                logger.warning(
                    "Skipping scan: scan_id=%s status=%s",
                    scan_id,
                    existing_scan.status,
                )

            return



        db.commit()

        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if scan is None:
            logger.error(
                "Claimed scan could not be loaded: scan_id=%s",
                scan_id,
            )
            return

        logger.info("Background scan started: scan_id=%s", scan_id)

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

        try:
            run_scan_pipeline(db, scan, uploaded_files)

            mark_scan_completed(scan)
            db.commit()

            logger.info(
                "Background scan completed: scan_id=%s",
                scan_id,
            )

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
