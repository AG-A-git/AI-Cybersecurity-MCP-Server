from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


ALLOWED_TRANSITIONS = {
    ScanStatus.PENDING: {
        ScanStatus.RUNNING,
        ScanStatus.FAILED,
    },
    ScanStatus.RUNNING: {
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
}


def can_transition(current: str, target: str) -> bool:
    """
    Check whether a scan is allowed to move from current state to target state.
    """

    try:
        current_status = ScanStatus(current)
        target_status = ScanStatus(target)
    except ValueError:
        return False

    return target_status in ALLOWED_TRANSITIONS[current_status]