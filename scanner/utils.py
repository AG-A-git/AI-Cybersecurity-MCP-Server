import logging

from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto
from scanner.rules.input_validation import scan_input_validation
from scanner.rules.command import scan_command
from scanner.rules.ldap import scan_ldap


logger = logging.getLogger(__name__)


# ============================================================
# Rule Loading
# ============================================================

def load_rules():
    """
    Load all vulnerability detection rules.
    """

    return [
        scan_sql,
        scan_xss,
        scan_credentials,
        scan_crypto,
        scan_input_validation,
        scan_command,
        scan_ldap
    ]


# ============================================================
# Run Rules
# ============================================================

def run_all_rules(file_path):
    """
    Run all vulnerability rules against a file.

    If one rule fails, log the error and continue
    with the remaining rules.
    """

    results = []

    rules = load_rules()

    for rule in rules:

        try:
            rule_results = rule(file_path)

            if rule_results:
                results.extend(rule_results)

        except Exception as error:
            logger.exception(
                "Rule %s failed while scanning %s: %s",
                rule.__name__,
                file_path,
                error
            )

    return results


# ============================================================
# Deduplication
# ============================================================

def deduplicate_findings(findings):
    """
    Remove duplicate vulnerability findings.

    Two findings are considered duplicates when they have
    the same:

        file_name
        line_number
        vulnerability_type

    If duplicate findings have different confidence values,
    keep the finding with the highest confidence.
    """

    unique = {}

    for finding in findings:

        key = (
            finding["file_name"],
            finding["line_number"],
            finding["vulnerability_type"]
        )

        if key not in unique:
            unique[key] = finding

        elif finding["confidence"] > unique[key]["confidence"]:
            unique[key] = finding

    return list(unique.values())


def remove_duplicates(results):
    """
    Backward-compatible wrapper.

    Existing code that calls remove_duplicates()
    will now use the Task 8 deduplication logic.
    """

    return deduplicate_findings(results)