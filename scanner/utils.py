import logging

from scanner.context import build_rule_context

from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto
from scanner.rules.input_validation import scan_input_validation
from scanner.rules.command import scan_command
from scanner.rules.ldap import scan_ldap
from scanner.rules.insecure_deserialization import scan_insecure_deserialization
from scanner.rules.security_misconfiguration import scan_security_misconfiguration
from scanner.rules.authentication_access_control import scan_authentication_access_control
from scanner.rules.ssrf import detect_ssrf
from scanner.rules.sensitive import scan_sensitive_data_exposure

logger = logging.getLogger(__name__)


# ============================================================
# Rule Loading
# ============================================================

def load_rules():
    """
    Load all implemented vulnerability detection rules.
    """
    return [
        scan_sql,
        scan_xss,
        scan_credentials,
        scan_crypto,
        scan_input_validation,
        scan_command,
        scan_ldap,
        scan_insecure_deserialization,
        scan_security_misconfiguration,
        scan_authentication_access_control,
        detect_ssrf,
        scan_sensitive_data_exposure,
    ]


# ============================================================
# Run Rules
# ============================================================

def run_all_rules(file_path):
    """
    Run all vulnerability rules against a file.

    A shared rule context is built once per file so future
    context-aware rules can reuse parsed source information.

    Existing rules continue to receive file_path for backward
    compatibility.

    If context creation fails, the scanner returns no findings
    for that file rather than crashing the complete scan.

    If one rule fails, the error is logged and the remaining
    rules continue to run.
    """
    results = []
    rules = load_rules()

    # Build shared context once for this file.
    try:
        context = build_rule_context(file_path)

        logger.debug(
            "Built rule context for %s: language=%s, lines=%d, "
            "imports=%d, functions=%d, variables=%d",
            file_path,
            context["language"],
            len(context["lines"]),
            len(context["imports"]),
            len(context["functions"]),
            len(context["variables"]),
        )

    except (SyntaxError, ValueError, OSError, UnicodeError) as error:
        logger.exception(
            "Failed to build rule context for %s: %s",
            file_path,
            error
        )
        return results

    # Existing rules continue to use the original file_path API.
    for rule in rules:
        try:
            rule_results = rule(file_path)

            if rule_results:
                results.extend(rule_results)

        except (SyntaxError, ValueError, OSError) as error:
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

    Two findings are considered duplicates when they have the same:
        vulnerability_type
        file_name
        line_number
        code

    If duplicate findings have different confidence values,
    keep the finding with the highest confidence.
    """
    unique = {}

    for finding in findings:
        key = (
            finding["vulnerability_type"],
            finding["file_name"],
            finding["line_number"],
            finding["code"],
        )

        if key not in unique:
            unique[key] = finding

        elif finding["confidence"] > unique[key]["confidence"]:
            unique[key] = finding

    return list(unique.values())


def remove_duplicates(results):
    """
    Backward-compatible wrapper.
    """
    return deduplicate_findings(results)