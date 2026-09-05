import os


def read_file(file_path):
    """
    Read the contents of a source code file.

    Args:
        file_path: Path to the source code file.

    Returns:
        The complete source code as a string.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


def supported_language(file_path):
    """
    Check whether the file is a supported source-code file.

    Currently supported:
    - Python (.py)
    - JavaScript (.js)
    """

    _, extension = os.path.splitext(file_path)

    supported_extensions = [".py", ".js"]

    return extension.lower() in supported_extensions