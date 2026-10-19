"""Track terminal outcomes for scanner operations."""

from dataclasses import dataclass
from enum import Enum


class ScanStatus(str, Enum):
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class ScanOutcome:
    status: ScanStatus
    files_scanned: int = 0
    error_count: int = 0
    message: str = ""


def make_outcome(status, files_scanned=0, error_count=0, message=""):
    """Build a consistent, immutable terminal scan outcome."""
    return ScanOutcome(
        status=status,
        files_scanned=files_scanned,
        error_count=error_count,
        message=message,
    )
