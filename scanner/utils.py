from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto
from scanner.rules.input_validation import scan_input_validation


def load_rules():
    """
    Load all vulnerability detection rules.
    """

    return [
        scan_sql,
        scan_xss,
        scan_credentials,
        scan_crypto,
        scan_input_validation
    ]


def run_all_rules(file_path):
    """
    Run all vulnerability rules against a file.
    """

    results = []

    rules = load_rules()

    for rule in rules:
        rule_results = rule(file_path)
        results.extend(rule_results)

    return results

def remove_duplicates(results):
    """
    Remove duplicate vulnerability findings.

    Findings are considered duplicates when they have
    the same file, line, and vulnerability.
    """

    unique_results = []
    seen = set()

    for result in results:
        key = (
            result.get("file"),
            result.get("line"),
            result.get("vulnerability")
        )

        if key not in seen:
            seen.add(key)
            unique_results.append(result)

    return remove_duplicates(results)

def remove_duplicates(results):
    """
    Remove duplicate vulnerability findings.

    Findings are considered duplicates when they have
    the same file, line, and vulnerability.
    """

    unique_results = []
    seen = set()

    for result in results:
        key = (
            result.get("file"),
            result.get("line"),
            result.get("vulnerability")
        )

        if key not in seen:
            seen.add(key)
            unique_results.append(result)

    return unique_results