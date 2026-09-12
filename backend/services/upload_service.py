from pathlib import Path
import zipfile


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
    """
    Check whether the uploaded file has a supported extension.
    """

    extension = Path(filename).suffix.lower()

    return extension in ALLOWED_EXTENSIONS


def get_language(filename: str) -> str:
    """
    Determine the programming language from the file extension.
    """

    extension = Path(filename).suffix.lower()

    return LANGUAGE_MAP.get(extension, "unknown")


async def save_file(file, filename: str) -> Path:
    """
    Save an uploaded file to the uploads directory
    while enforcing a maximum file size.
    """

    safe_filename = Path(filename).name
    if not safe_filename:
        raise ValueError("Invalid filename")
    file_path = UPLOAD_DIR / safe_filename

    total_size = 0

    with open(file_path, "wb") as buffer:
        while True:
            chunk = await file.read(1024 * 1024)

            if not chunk:
                break

            total_size += len(chunk)

            if total_size > MAX_FILE_SIZE:
                buffer.close()

                if file_path.exists():
                    file_path.unlink()

                raise ValueError(
                    "File size exceeds the 10 MB limit"
                )

            buffer.write(chunk)

    return file_path


def extract_zip(file_path: Path) -> Path:
    """
    Safely extract a ZIP project into the extracted directory.
    Prevent path traversal and excessive ZIP contents.
    """

    project_name = file_path.stem

    project_extract_dir = EXTRACT_DIR / project_name

    project_extract_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(file_path, "r") as zip_ref:

        members = zip_ref.infolist()

        if len(members) > MAX_ZIP_FILES:
            raise ValueError(
                "ZIP file contains too many files"
            )

        total_uncompressed_size = sum(
            member.file_size
            for member in members
        )

        if total_uncompressed_size > MAX_ZIP_EXTRACTED_SIZE:
            raise ValueError(
                "ZIP contents exceed the 50 MB extraction limit"
            )

        for member in members:

            target_path = project_extract_dir / member.filename

            try:
                target_path.resolve().relative_to(
                    project_extract_dir.resolve()
                )
            except ValueError:
                raise ValueError(
                    "Unsafe ZIP file: path traversal detected"
                )

        zip_ref.extractall(project_extract_dir)

    return project_extract_dir