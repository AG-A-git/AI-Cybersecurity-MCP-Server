
from pathlib import Path
import logging
import os
import time

from scanner.utils import run_all_rules, remove_duplicates
from scanner.scan import scan_zip
from scanner.zip_scan_result import scan_zip_with_status, ZipScanStatus
from scanner.scan_worker import run_file_with_hard_timeout
from scanner.finding import validate_finding
from scanner.path_security import ensure_allowed_path
from scanner.scan_state import ScanStatus, make_outcome


SUPPORTED_EXTENSIONS = {".py", ".js"}

logger = logging.getLogger(__name__)
_last_scan_outcome = None

IGNORED_DIRECTORIES = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
}


def get_last_scan_outcome():
    """Return the terminal outcome of the most recent scan in this process."""
    return _last_scan_outcome


def _record_outcome(status, files_scanned=0, error_count=0, message=""):
    """Record and return an immutable terminal scan outcome."""
    global _last_scan_outcome
    _last_scan_outcome = make_outcome(
        status,
        files_scanned=files_scanned,
        error_count=error_count,
        message=message,
    )
    return _last_scan_outcome


def find_source_files(path):
    """Find supported source files while skipping ignored directories."""
    path = Path(path)

    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_EXTENSIONS else []

    if path.is_dir():
        source_files = []

        for file in path.rglob("*"):
            if not file.is_file():
                continue

            relative_path = file.relative_to(path)

            if any(
                directory in IGNORED_DIRECTORIES
                for directory in relative_path.parts[:-1]
            ):
                continue

            if file.suffix.lower() in SUPPORTED_EXTENSIONS:
                source_files.append(file)

        return source_files

    raise FileNotFoundError(f"Path does not exist: {path}")


def scan_project(project_path, timeout_seconds=None, hard_timeout=False):
    """Scan a source file, directory, or ZIP and return a list of findings.

    By default, timeout checks are cooperative between files. Set
    hard_timeout=True to run each source file in a child process that can
    be terminated when its remaining deadline expires.

    ZIP scans retain the existing ZIP scanner's behavior and API.
    """
    started = time.monotonic()
    files_scanned = 0
    error_count = 0

    if timeout_seconds is None:
        try:
            timeout_seconds = float(
                os.environ.get("SCAN_TIMEOUT_SECONDS", "60")
            )
        except (TypeError, ValueError):
            timeout_seconds = 60.0

    if not isinstance(project_path, (str, os.PathLike)):
        _record_outcome(
            ScanStatus.FAILED,
            message="Invalid path type.",
        )
        return []

    try:
        timeout_seconds = float(timeout_seconds)
    except (TypeError, ValueError):
        _record_outcome(
            ScanStatus.FAILED,
            message="Invalid timeout value.",
        )
        return []

    if timeout_seconds <= 0:
        _record_outcome(
            ScanStatus.TIMED_OUT,
            message="Timeout must be greater than zero.",
        )
        return []

    try:
        if str(project_path).lower().endswith(".zip"):
            zip_result = scan_zip_with_status(project_path, scan_zip)

            if zip_result.status in (
                ZipScanStatus.REJECTED,
                ZipScanStatus.FAILED,
            ):
                _record_outcome(
                    ScanStatus.FAILED,
                    error_count=1,
                    message=zip_result.message,
                )
                return []

            _record_outcome(
                ScanStatus.COMPLETED,
                message=zip_result.message or "ZIP scan finished.",
            )
            return list(zip_result.findings)

        project_path = ensure_allowed_path(project_path)
        source_files = find_source_files(project_path)
        results = []

        for file_path in source_files:
            elapsed = time.monotonic() - started
            remaining = timeout_seconds - elapsed

            if remaining <= 0:
                _record_outcome(
                    ScanStatus.TIMED_OUT,
                    files_scanned=files_scanned,
                    error_count=error_count,
                    message=(
                        "Scan deadline reached; findings may be incomplete."
                    ),
                )
                logger.warning("Scan timed out: %s", project_path)
                return remove_duplicates(results)

            try:
                if hard_timeout:
                    worker_status, worker_result = run_file_with_hard_timeout(
                        str(file_path),
                        remaining,
                    )

                    if worker_status == "timeout":
                        _record_outcome(
                            ScanStatus.TIMED_OUT,
                            files_scanned=files_scanned,
                            error_count=error_count,
                            message=(
                                "Hard timeout reached while scanning "
                                f"{file_path}; findings may be incomplete."
                            ),
                        )
                        logger.warning(
                            "Hard timeout scanning %s",
                            file_path,
                        )
                        return remove_duplicates(results)

                    if worker_status == "error":
                        error_name, error_message = worker_result
                        error_count += 1
                        logger.error(
                            "Worker failed scanning %s: %s: %s",
                            file_path,
                            error_name,
                            error_message,
                        )
                        continue

                    file_results = worker_result[0]
                else:
                    file_results = run_all_rules(str(file_path))

                files_scanned += 1

            except (
                SyntaxError,
                ValueError,
                OSError,
                UnicodeError,
            ) as error:
                error_count += 1
                logger.exception(
                    "Recoverable error scanning %s: %s",
                    file_path,
                    error,
                )
                continue

            for finding in file_results:
                try:
                    validate_finding(finding)
                except (ValueError, TypeError):
                    error_count += 1
                    continue

                results.append(finding)

        status = (
            ScanStatus.COMPLETED_WITH_ERRORS
            if error_count
            else ScanStatus.COMPLETED
        )

        _record_outcome(
            status,
            files_scanned=files_scanned,
            error_count=error_count,
            message=(
                "Scan finished."
                if not error_count
                else "Scan finished with errors."
            ),
        )

        return remove_duplicates(results)

    except (FileNotFoundError, PermissionError):
        _record_outcome(
            ScanStatus.FAILED,
            files_scanned=files_scanned,
            error_count=error_count + 1,
            message="Path missing or access denied.",
        )
        raise

    except Exception:
        _record_outcome(
            ScanStatus.FAILED,
            files_scanned=files_scanned,
            error_count=error_count + 1,
            message="Unexpected scan failure.",
        )
        logger.exception("Scan failed for %r", project_path)
        raise
