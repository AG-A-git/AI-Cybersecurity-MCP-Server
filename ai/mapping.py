
from .vulnerability_mapping import (
    VULNERABILITY_MAPPING,
    get_vulnerability_mapping,
)


def get_mapping(vulnerability):
    """
    Return the canonical OWASP/CWE mapping for a vulnerability.

    Returns "Unknown" values when no mapping exists.
    """

    if not isinstance(vulnerability, str) or not vulnerability.strip():
        return {
            "owasp": "Unknown",
            "cwe": "Unknown",
        }

    mapping = get_vulnerability_mapping(vulnerability.strip())

    if mapping is None:
        return {
            "owasp": "Unknown",
            "cwe": "Unknown",
        }

    return mapping


if __name__ == "__main__":
    for vulnerability in VULNERABILITY_MAPPING:
        print(vulnerability, "->", get_mapping(vulnerability))
