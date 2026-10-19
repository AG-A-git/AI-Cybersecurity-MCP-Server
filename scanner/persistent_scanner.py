"""Optional persistence wrapper around the existing scanner."""
from datetime import datetime, timezone

from scanner.engine import scan_project, get_last_scan_outcome
from scanner.scan_persistence import save_scan


def scan_project_and_persist(project_path, db_path, timeout_seconds=None,
                             hard_timeout=False):
    """Scan and persist findings plus terminal status; return findings."""
    started_at = datetime.now(timezone.utc).isoformat()
    findings = []
    try:
        findings = scan_project(
            project_path,
            timeout_seconds=timeout_seconds,
            hard_timeout=hard_timeout,
        )
        return findings
    finally:
        outcome = get_last_scan_outcome()
        if outcome is not None:
            finished_at = datetime.now(timezone.utc).isoformat()
            save_scan(
                db_path=db_path,
                project_path=project_path,
                findings=findings,
                outcome=outcome,
                started_at=started_at,
                finished_at=finished_at,
            )
