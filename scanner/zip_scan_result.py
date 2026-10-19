
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

        # Validate archive contents before invoking the scanner.
        with zipfile.ZipFile(allowed_path, "r") as archive:
            members = archive.infolist()

            # Reject duplicate names to prevent ambiguous archive contents.
            member_names = [member.filename for member in members]
            if len(member_names) != len(set(member_names)):
                return ZipScanResult(
                    ZipScanStatus.REJECTED,
                    message="Duplicate ZIP member names rejected.",
                )

            # Limit the number of archive entries.
            if len(members) > 1000:
                return ZipScanResult(
                    ZipScanStatus.REJECTED,
                    message="ZIP entry limit exceeded.",
                )

            # Limit total declared uncompressed size.
            total_size = sum(member.file_size for member in members)
            if total_size > 100 * 1024 * 1024:
                return ZipScanResult(
                    ZipScanStatus.REJECTED,
                    message="ZIP uncompressed-size limit exceeded.",
                )

            for member in members:
                name = member.filename
                normalized = name.replace("\\", "/")
                parts = normalized.split("/")

                # Reject absolute paths, drive paths, and traversal.
                if (
                    "\x00" in name
                    or normalized.startswith("/")
                    or (len(normalized) >= 2 and normalized[1] == ":")
                    or ".." in parts
                ):
                    return ZipScanResult(
                        ZipScanStatus.REJECTED,
                        message="Unsafe ZIP member path.",
                    )

                # Reject Unix symbolic-link entries.
                unix_mode = member.external_attr >> 16
                if (
                    member.create_system == 3
                    and stat.S_ISLNK(unix_mode)
                ):
                    return ZipScanResult(
                        ZipScanStatus.REJECTED,
                        message="ZIP symbolic-link entry rejected.",
                    )

        # Invoke the existing scanner only after validation succeeds.
        findings = scan_function(allowed_path)

        return ZipScanResult(
            status=ZipScanStatus.COMPLETED,
            findings=tuple(findings),
            message="ZIP scan finished.",
        )

    except (FileNotFoundError, PermissionError):
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
    ) as error:
        return ZipScanResult(
            ZipScanStatus.FAILED,
            message=f"ZIP scan failed: {error}",
        )
