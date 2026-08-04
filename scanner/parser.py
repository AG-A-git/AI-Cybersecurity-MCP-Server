import os

# Supported file extensions
SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".c": "C",
    ".cpp": "C++",
    ".php": "PHP",
}


def parse_file(file_path):
    """
    Reads a source code file and returns its language and code.
    """

    # Check if file exists
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Detect extension
    _, extension = os.path.splitext(file_path)

    if extension.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type: {extension}"
        )

    language = SUPPORTED_EXTENSIONS[extension.lower()]

    # Read file
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        code = file.read()

    return {
        "file": file_path,
        "language": language,
        "code": code
    }


# Test parser directly
if __name__ == "__main__":
    path = input("Enter file path: ")

    try:
        result = parse_file(path)

        print("\n=== Parser Output ===")
        print(f"File      : {result['file']}")
        print(f"Language  : {result['language']}")
        print("\nCode:\n")
        print(result["code"])

    except Exception as e:
        print(f"Error: {e}")