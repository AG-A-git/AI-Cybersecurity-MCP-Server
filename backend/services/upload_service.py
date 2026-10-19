import stat
from pathlib import Path
import uuid
import zipfile
import shutil

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_ZIP_EXTRACTED_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_ZIP_FILES = 500


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

EXTRACT_DIR = UPLOAD_DIR / "extracted"
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)


ALLOWED_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".html",
    ".zip"
}


LANGUAGE_MAP = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".html": "html",
    ".zip": "zip"
}


def validate_extension(filename: str) -> bool:
    """Check whether the uploaded file has a supported extension."""
    if not filename or not filename.strip():
        return False
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def get_language(filename: str) -> str:
    """Determine the programming language from the file extension."""
    extension = Path(filename).suffix.lower()
    return LANGUAGE_MAP.get(extension, "unknown")


async def save_file(file, filename: str) -> Path:
    """Save an upload under a unique server-generated name with a size limit."""
    if not filename or not filename.strip() or not Path(filename).name:
        raise ValueError("Invalid filename")

    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type")

    file_path = UPLOAD_DIR / f"{uuid.uuid4().hex}{extension}"
    total_size = 0

    try:
        with open(file_path, "xb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise ValueError("File size exceeds the 10 MB limit")

                buffer.write(chunk)
    except Exception:
        if file_path.exists():
            file_path.unlink()
        raise

    return file_path


from pathlib import Path
import shutil
import zipfile


def extract_zip(file_path: Path) -> Path:
    """
    Safely extract a ZIP project with path, size, and entry-count checks.
    Remove the extraction directory if validation or extraction fails.
    """
    project_name = file_path.stem
    project_extract_dir = EXTRACT_DIR / project_name

    # Refuse to overwrite an existing extraction directory.
    if project_extract_dir.exists():
        raise ValueError("A project with this extracted filename already exists")

    project_extract_dir.mkdir(parents=True, exist_ok=False)

    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            members = zip_ref.infolist()

            if len(members) > MAX_ZIP_FILES:
                raise ValueError("ZIP file contains too many files")

            total_uncompressed_size = sum(
                member.file_size for member in members
            )
            if total_uncompressed_size > MAX_ZIP_EXTRACTED_SIZE:
                raise ValueError(
                    "ZIP contents exceed the 50 MB extraction limit"
                )

            root = project_extract_dir.resolve()

            for member in members:
                # Reject symbolic links before extracting any archive entries.
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise ValueError(
                        "Unsafe ZIP file: symlink entries are not allowed"
                    )

                target_path = (project_extract_dir / member.filename).resolve()
                try:
                    target_path.relative_to(root)
                except ValueError:
                    raise ValueError(
                        "Unsafe ZIP file: path traversal detected"
                    )
            zip_ref.extractall(project_extract_dir)
        return project_extract_dir

    except Exception:
        if project_extract_dir.exists():
            shutil.rmtree(project_extract_dir, ignore_errors=True)
        raise
