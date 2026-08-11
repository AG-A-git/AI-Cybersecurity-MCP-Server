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
    "Unused Variable": "Info"
}
def get_severity(vulnerability):
    """
    Return the severity level for a vulnerability.
    """

    return SEVERITY_MAP.get(vulnerability, "Info")
