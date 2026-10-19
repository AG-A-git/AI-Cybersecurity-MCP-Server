
import json
import ntpath
import os
import stat
import sys
import tempfile
import zipfile


sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


from scanner.parser import read_file, supported_language
from scanner.utils import (
    run_all_rules,
    deduplicate_findings,
)
from scanner.finding import validate_finding
from scanner.path_security import ensure_allowed_path


# ============================================================
# Directories that should not be scanned
# ============================================================

IGNORED_DIRECTORIES = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
}


# ============================================================
# Finding Sorting
# ============================================================

def sort_findings(findings):
    """Sort findings deterministically."""
    return sorted(
        findings,
        key=lambda finding: (
            finding["file_name"],
            finding["line_number"],
            finding["vulnerability_type"],
        ),
    )


# ============================================================
# Single File Scanner
# ============================================================

def scan_file(file_path):
    """
    Scan one supported source file.

    Invalid, unsupported, oversized, or unreadable files
    return an empty list.
    """
    if not isinstance(file_path, (str, os.PathLike)):
        return []

    try:
        if os.path.islink(file_path):
            return []

        if not os.path.isfile(file_path):
            return []

        if not supported_language(file_path):
            return []

        # Validate readability and parser size limits.
        read_file(file_path)

    except (
        FileNotFoundError,
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
    ):
        return []

    findings = run_all_rules(file_path)
    validated_findings = []

    for finding in findings:
        try:
            validate_finding(finding)
            validated_findings.append(finding)
        except (ValueError, TypeError):
            continue

    validated_findings = deduplicate_findings(
        validated_findings
    )

    return sort_findings(validated_findings)


# ============================================================
# Directory Scanner
# ============================================================

def scan_directory(directory_path):
    """Scan supported source files without following symlinks."""
    if not isinstance(directory_path, (str, os.PathLike)):
        return []

    try:
        if os.path.islink(directory_path):
            return []

        if not os.path.isdir(directory_path):
            return []
    except (OSError, ValueError, TypeError):
        return []

    all_results = []

    for root, dirs, files in os.walk(
        directory_path,
        followlinks=False,
    ):
        # Do not traverse ignored or symlinked directories.
        dirs[:] = [
            directory
            for directory in dirs
            if (
                directory not in IGNORED_DIRECTORIES
                and not os.path.islink(
                    os.path.join(root, directory)
                )
            )
        ]

        for filename in files:
            file_path = os.path.join(root, filename)

            # Never scan symlinked files.
            if os.path.islink(file_path):
                continue

            try:
                if not os.path.isfile(file_path):
                    continue

                if not supported_language(file_path):
                    continue

                all_results.extend(scan_file(file_path))

            except (OSError, ValueError, TypeError):
                continue

    all_results = deduplicate_findings(all_results)

    return sort_findings(all_results)


# ============================================================
# ZIP Path Validation
# ============================================================

def _is_safe_zip_member(member_name):
    """
    Reject absolute paths, Windows drive/UNC paths,
    parent-directory components, and NUL characters.
    """
    if not isinstance(member_name, str) or not member_name:
        return False

    if "\x00" in member_name:
        return False

    normalized_name = member_name.replace("\\", "/")
    drive, _ = ntpath.splitdrive(member_name)

    if normalized_name.startswith("/"):
        return False

    if drive:
        return False

    if ".." in normalized_name.split("/"):
        return False

    return True


# ============================================================
# ZIP Scanner
# ============================================================

def scan_zip(zip_path):
    """
    Safely extract and scan a ZIP project in a temporary directory.

    Rejects:
      - Invalid ZIP files
      - Symbolic-link entries
      - Absolute or traversal paths
      - Archives with excessive entry counts
      - Archives with excessive declared uncompressed size
    """
    if not isinstance(zip_path, (str, os.PathLike)):
        return []

    try:
        if not os.path.exists(zip_path):
            raise FileNotFoundError(
                f"ZIP path does not exist: {zip_path}"
            )

        # Authorize the archive before opening or inspecting it.
        zip_path = ensure_allowed_path(zip_path)

        if os.path.islink(zip_path) or not os.path.isfile(zip_path):
            return []

        if not zipfile.is_zipfile(zip_path):
            return []

    except (FileNotFoundError, PermissionError):
        raise
    except (OSError, ValueError, TypeError):
        return []

    max_files = 1000
    max_uncompressed_size = 100 * 1024 * 1024

    with tempfile.TemporaryDirectory() as temp_directory:
        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                members = archive.infolist()

                # Limit the number of archive entries.
                if len(members) > max_files:
                    return []

                # Reject unsafe paths and Unix symbolic links
                # before extracting anything.
                for member in members:
                    if not _is_safe_zip_member(member.filename):
                        return []

                    unix_mode = member.external_attr >> 16

                    if (
                        member.create_system == 3
                        and stat.S_ISLNK(unix_mode)
                    ):
                        return []

                # Reject invalid negative declared file sizes.
                if any(member.file_size < 0 for member in members):
                    return []

                # Limit total declared uncompressed size.
                total_size = sum(
                    member.file_size for member in members
                )

                if total_size > max_uncompressed_size:
                    return []

                # Defense in depth: resolve every destination and
                # ensure it remains inside the extraction directory.
                temp_root = os.path.realpath(temp_directory)

                for member in members:
                    member_path = os.path.realpath(
                        os.path.join(
                            temp_root,
                            member.filename.replace(
                                "\\", os.sep
                            ),
                        )
                    )

                    try:
                        if os.path.commonpath(
                            [temp_root, member_path]
                        ) != temp_root:
                            return []
                    except ValueError:
                        return []

                # Extract only after all members pass validation.
                archive.extractall(temp_directory)

        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError,
            ValueError,
            NotImplementedError,
        ):
            return []

        results = scan_directory(temp_directory)

        # Convert temporary absolute file paths into relative paths.
        temp_root = os.path.realpath(temp_directory)

        for finding in results:
            file_name = finding.get("file_name")

            if not isinstance(file_name, str):
                continue

            if os.path.isabs(file_name):
                try:
                    resolved_name = os.path.realpath(file_name)

                    if os.path.commonpath(
                        [temp_root, resolved_name]
                    ) == temp_root:
                        finding["file_name"] = os.path.relpath(
                            resolved_name,
                            temp_root,
                        )
                except (OSError, ValueError):
                    continue

        return sort_findings(results)


# ============================================================
# Main Scanner Entry Point
# ============================================================

def scan_project(path):
    """
    Scan a source file, project directory, or ZIP project.

    Invalid path types return an empty list.
    Missing paths raise FileNotFoundError.
    """
    if not isinstance(path, (str, os.PathLike)):
        return []

    try:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Path does not exist: {path}"
            )

        # Resolve and authorize before opening or scanning anything.
        authorized_path = ensure_allowed_path(path)

        # Preserve the existing rejection of symlink entry points.
        if os.path.islink(path):
            return []

        path = authorized_path

        if os.path.isfile(path):
            if os.fspath(path).lower().endswith(".zip"):
                return scan_zip(path)

            return scan_file(path)

        if os.path.isdir(path):
            return scan_directory(path)

    except (FileNotFoundError, PermissionError):
        raise
    except (OSError, ValueError, TypeError):
        return []

    return []


# ============================================================
# JSON Report
# ============================================================

def generate_json_report(path):
    """Generate scanner results as JSON."""
    results = scan_project(path)

    return json.dumps(
        results,
        indent=2,
    )


# ============================================================
# Command-Line Entry Point
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python scanner\\scan.py "
            "<file_or_directory_or_zip>"
        )
        sys.exit(1)

    target = sys.argv[1]
    print(generate_json_report(target))
