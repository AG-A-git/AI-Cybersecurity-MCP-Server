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
    ScanStatus.FAILED: {
        ScanStatus.PENDING,
    },
}


def can_transition(current: str, target: str) -> bool:
    """
    Check whether a scan is allowed to move
    from the current state to the target state.
    """

    try:
        current_status = ScanStatus(current)
        target_status = ScanStatus(target)
    except (ValueError, TypeError):
        return False

    return target_status in ALLOWED_TRANSITIONS[current_status]