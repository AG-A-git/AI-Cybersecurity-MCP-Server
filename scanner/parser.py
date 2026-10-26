
import os


# Maximum source file size: 5 MB
MAX_FILE_SIZE = 5 * 1024 * 1024

SUPPORTED_EXTENSIONS = {".py", ".js"}


def read_file(file_path):
    """
    Read a supported source-code file with input validation.

    Raises:
        ValueError: Invalid path, unsupported file type,
                    or file exceeds the size limit.
        OSError: File cannot be accessed.
        UnicodeError: File is not valid UTF-8.
    """

    if not isinstance(file_path, (str, os.PathLike)):
        raise ValueError("Invalid file path type")

    path = os.fspath(file_path)

    if not isinstance(path, str) or not path:
        raise ValueError("Invalid file path")

    if not supported_language(path):
        raise ValueError("Unsupported file type")

    if not os.path.isfile(path):
        raise ValueError("File does not exist or is not a regular file")

    if os.path.getsize(path) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 5 MB size limit")

    with open(path, "r", encoding="utf-8") as file:
        content = file.read(MAX_FILE_SIZE + 1)

    if len(content.encode("utf-8")) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 5 MB size limit")

    return content


def supported_language(file_path):
    """
    Check whether a path has a supported source-code extension.

    Supported:
    - Python (.py)
    - JavaScript (.js)
    """

    if not isinstance(file_path, (str, os.PathLike)):
        return False

    try:
        path = os.fspath(file_path)
        if not isinstance(path, str):
            return False

        _, extension = os.path.splitext(path)
        return extension.lower() in SUPPORTED_EXTENSIONS

    except (TypeError, ValueError):
        return False
