import pytest

from models import Scan
from services.scan_states import ScanStatus
from services.scan_lifecycle_service import (
    transition_scan_status,
    mark_scan_running,
    mark_scan_completed,
    mark_scan_failed,
)


def test_pending_to_running():
    scan = Scan(status=ScanStatus.PENDING.value)

    mark_scan_running(scan)

    assert scan.status == ScanStatus.RUNNING.value
    assert scan.started_at is not None
    assert scan.completed_at is None
    assert scan.error_message is None


def test_running_to_completed():
    scan = Scan(status=ScanStatus.RUNNING.value)

    mark_scan_completed(scan)

    assert scan.status == ScanStatus.COMPLETED.value
    assert scan.completed_at is not None
    assert scan.error_message is None


def test_running_to_failed():
    scan = Scan(status=ScanStatus.RUNNING.value)

    mark_scan_failed(
        scan,
        "Scanner execution failed"
    )

    assert scan.status == ScanStatus.FAILED.value
    assert scan.completed_at is not None
    assert scan.error_message == "Scanner execution failed"


@pytest.mark.parametrize(
    "current_status,target_status",
    [
        (ScanStatus.COMPLETED.value, ScanStatus.RUNNING),
        (ScanStatus.COMPLETED.value, ScanStatus.FAILED),
        (ScanStatus.FAILED.value, ScanStatus.RUNNING),
        (ScanStatus.FAILED.value, ScanStatus.COMPLETED),
        (ScanStatus.RUNNING.value, ScanStatus.PENDING),
    ],
)
def test_invalid_scan_transitions_are_rejected(
    current_status,
    target_status,
):
    scan = Scan(status=current_status)

    with pytest.raises(ValueError, match="Invalid scan status transition"):
        transition_scan_status(
            scan,
            target_status
        )