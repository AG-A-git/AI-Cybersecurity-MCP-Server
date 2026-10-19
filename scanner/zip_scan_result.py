
"""Internal result types for ZIP scan status reporting."""

from dataclasses import dataclass
from enum import Enum
import os
import stat
import zipfile

from scanner.path_security import ensure_allowed_path


class ZipScanStatus(str, Enum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True)
class ZipScanResult:
    status: ZipScanStatus
    findings: tuple = ()
    message: str = ""


def scan_zip_with_status(zip_path, scan_function):
    """Validate ZIP safety limits before invoking the existing scanner."""
    if not isinstance(zip_path, (str, os.PathLike)):
        return ZipScanResult(
            ZipScanStatus.REJECTED,
            message="Invalid ZIP path type.",
        )

    try:
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"ZIP path does not exist: {zip_path}")

        allowed_path = ensure_allowed_path(zip_path)

        if os.path.islink(allowed_path) or not os.path.isfile(allowed_path):
            return ZipScanResult(
                ZipScanStatus.REJECTED,
                message="ZIP path rejected.",
            )

        if not zipfile.is_zipfile(allowed_path):
            return ZipScanResult(
                ZipScanStatus.REJECTED,
                message="Invalid ZIP archive.",
            )

        # Match the existing scanner's archive limits and safety checks.
        with zipfile.ZipFile(allowed_path, "r") as archive:
            members = archive.infolist()

            if len(members) > 1000:
                return ZipScanResult(
                    ZipScanStatus.REJECTED,
                    message="ZIP entry limit exceeded.",
                )

            if sum(member.file_size for member in members) > 100 * 1024 * 1024:
                return ZipScanResult(
                    ZipScanStatus.REJECTED,
                    message="ZIP uncompressed-size limit exceeded.",
                )

            for member in members:
                name = member.filename
                normalized = name.replace("\\", "/")
                parts = normalized.split("/")

                if (
                    normalized.startswith("/")
                    or (len(normalized) >= 2 and normalized[1] == ":")
                    or ".." in parts
                ):
                    return ZipScanResult(
                        ZipScanStatus.REJECTED,
                        message="Unsafe ZIP member path.",
                    )

                unix_mode = member.external_attr >> 16
                if (
                    member.create_system == 3
                    and stat.S_ISLNK(unix_mode)
                ):
                    return ZipScanResult(
                        ZipScanStatus.REJECTED,
                        message="ZIP symbolic-link entry rejected.",
                    )

        findings = scan_function(allowed_path)

        return ZipScanResult(
            ZipScanStatus.COMPLETED,
            tuple(findings),
            "ZIP scan finished.",
        )

    except (FileNotFoundError, PermissionError):
        raise
    except (OSError, ValueError, TypeError, zipfile.BadZipFile,
            RuntimeError, NotImplementedError) as error:
        return ZipScanResult(
            ZipScanStatus.FAILED,
            message=f"ZIP scan failed: {error}",
        )
