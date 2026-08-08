from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto


def load_rules():
    """
    Load all vulnerability detection rules.
    """

    return [
        scan_sql,
        scan_xss,
        scan_credentials,
        scan_crypto
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