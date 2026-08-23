import logging

from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto
from scanner.rules.input_validation import scan_input_validation
from scanner.rules.command import scan_command
from scanner.rules.ldap import scan_ldap


logger = logging.getLogger(__name__)


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


def remove_duplicates(results):
    """
    Remove duplicate vulnerability findings.

    Supports both the old scanner output format and
    the new standardized output format.
    """

    unique_results = []
    seen = set()

    for result in results:

        key = (
            result.get("file_name", result.get("file")),
            result.get("line_number", result.get("line")),
            result.get(
                "vulnerability_type",
                result.get("vulnerability")
            ),
            result.get("code")
        )

        if key not in seen:
            seen.add(key)
            unique_results.append(result)

    return unique_results