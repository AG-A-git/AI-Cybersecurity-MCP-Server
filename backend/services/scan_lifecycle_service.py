from models import Scan
from services.time_service import utc_now
from services.scan_states import ScanStatus, can_transition


def transition_scan_status(
    scan: Scan,
    target_status: ScanStatus
) -> None:
    """
    Apply a validated scan status transition.
    """

    current_status = scan.status

    if not can_transition(
        current_status,
        target_status.value
    ):
        raise ValueError(
            f"Invalid scan status transition: "
            f"{current_status} -> {target_status.value}"
        )

    scan.status = target_status.value


def mark_scan_running(scan: Scan) -> None:
    """
    Move a pending scan into the running state.
    """

    transition_scan_status(
        scan,
        ScanStatus.RUNNING
    )

    scan.started_at = utc_now()
    scan.completed_at = None
    scan.error_message = None


def mark_scan_completed(scan: Scan) -> None:
    """
    Mark a running scan as successfully completed.
    """

    transition_scan_status(
        scan,
        ScanStatus.COMPLETED
    )

    scan.completed_at = utc_now()
    scan.error_message = None


def mark_scan_failed(
    scan: Scan,
    error_message: str
) -> None:
    """
    Mark a running or pending scan as failed.
    """

    transition_scan_status(
        scan,
        ScanStatus.FAILED
    )

    scan.completed_at = utc_now()
    scan.error_message = error_message