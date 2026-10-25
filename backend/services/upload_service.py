
from pathlib import Path
import zipfile

UPLOAD_DIR = Path("uploads").resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

EXTRACT_DIR = UPLOAD_DIR / "extracted"
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".py", ".java", ".js", ".html", ".zip"}

LANGUAGE_MAP = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".html": "html",
    ".zip": "zip",
}


def validate_extension(filename: str) -> bool:
    """Check whether a file has a supported extension."""
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def get_language(filename: str) -> str:
    """Return the language associated with a supported file extension."""
    return LANGUAGE_MAP.get(Path(filename).suffix.lower(), "unknown")


def get_project_upload_dir(project_id: int) -> Path:
    """Create and return the upload directory for a project."""
    if project_id < 1:
        raise ValueError("Invalid project ID")

    project_dir = (UPLOAD_DIR / f"project_{project_id}").resolve()

    if UPLOAD_DIR not in project_dir.parents:
        raise ValueError("Invalid project upload directory")

    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


async def save_file(file, filename: str, project_id: int) -> Path:
    """Save a file in its project's directory without overwriting existing files."""
    safe_filename = Path(filename).name

    if not safe_filename or safe_filename in {".", ".."}:
        raise ValueError("Invalid filename")

    project_dir = get_project_upload_dir(project_id)
    destination = project_dir / safe_filename

    # Preserve existing files when a filename is uploaded more than once.
    counter = 1

    while destination.exists():
        original = Path(safe_filename)
        destination = project_dir / (
            f"{original.stem}_{counter}{original.suffix}"
        )
        counter += 1

    contents = await file.read()

    # Exclusive creation prevents overwriting an existing destination.
    with destination.open("xb") as buffer:
        buffer.write(contents)

    return destination


def extract_zip(file_path: Path, project_id: int) -> Path:
    """Safely extract a ZIP file into a project-specific directory."""
    project_dir = get_project_upload_dir(project_id)
    resolved_file = file_path.resolve()

    # Only extract ZIP files located inside the relevant project's directory.
    if project_dir not in resolved_file.parents:
        raise ValueError("ZIP file does not belong to this project")

    if not resolved_file.is_file() or resolved_file.suffix.lower() != ".zip":
        raise ValueError("Invalid ZIP file")

    project_extract_dir = (
        EXTRACT_DIR / f"project_{project_id}" / resolved_file.stem
    ).resolve()

    project_extract_dir.mkdir(parents=True, exist_ok=True)
    root = project_extract_dir.resolve()

    with zipfile.ZipFile(resolved_file, "r") as zip_ref:
        for member in zip_ref.infolist():
            # Reject entries that attempt to escape the extraction directory.
            target = (root / member.filename).resolve()

            if target != root and root not in target.parents:
                raise ValueError(
                    f"Unsafe ZIP archive path: {member.filename}"
                )

            # Reject symbolic links in ZIP archives.
            unix_mode = member.external_attr >> 16

            if (unix_mode & 0o170000) == 0o120000:
                raise ValueError(
                    f"ZIP symbolic links are not allowed: {member.filename}"
                )

        zip_ref.extractall(root)

    return root
