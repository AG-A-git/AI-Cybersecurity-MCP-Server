SEVERITY_MAP = {
    "SQL Injection": "Critical",
    "Command Injection": "Critical",
    "Cross-Site Scripting": "High",
    "Hardcoded Credentials": "High",
    "Path Traversal": "High",
    "Weak Cryptography": "Medium",
    "Insecure Deserialization": "Medium",
    "Information Disclosure": "Low",
    "Debug Code": "Low",
    "Code Style": "Info",
    "Unused Variable": "Info",
}


def get_severity(vulnerability):
    """Return the mapped severity for a known vulnerability category.

    Info is reserved for explicitly mapped informational categories.
    Unknown categories raise ValueError rather than silently receiving Info.
    """
    if not isinstance(vulnerability, str) or vulnerability not in SEVERITY_MAP:
        raise ValueError(f"Unknown vulnerability type: {vulnerability}")

    return SEVERITY_MAP[vulnerability]
