import re


def scan_xss(file_path):
    """
    Detect common Cross-Site Scripting (XSS) patterns.
    """

    results = []

    patterns = [
        re.compile(
            r'\.innerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
            re.IGNORECASE
        ),
        re.compile(
            r'document\.write\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)',
            re.IGNORECASE
        ),
        re.compile(
            r'\.outerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
            re.IGNORECASE
        ),
    ]

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

    except FileNotFoundError:
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern in patterns:

            if pattern.search(line):

                results.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "Cross Site Scripting",
                    "severity": "High",
                    "confidence": 92,
                    "code": line.strip()
                })

                break

    return results

if __name__ == "__main__":
    results = scan_xss("scanner/test_files/xss_test.js")

    for result in results:
        print(result)