from pathlib import Path
import zipfile


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
    Save an uploaded file to the uploads directory.
    """

    file_path = UPLOAD_DIR / filename

    contents = await file.read()

    with open(file_path, "wb") as buffer:
        buffer.write(contents)

    return file_path


def extract_zip(file_path: Path) -> Path:
    """
    Extract a ZIP project into the extracted directory.
    """

    project_name = file_path.stem

    project_extract_dir = EXTRACT_DIR / project_name

    project_extract_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(project_extract_dir)

    return project_extract_dir