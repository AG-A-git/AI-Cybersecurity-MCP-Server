
import logging

from scanner.context import build_rule_context

from scanner.rules.sql import scan_sql
from scanner.rules.xss import scan_xss
from scanner.rules.credentials import scan_credentials
from scanner.rules.crypto import scan_crypto
from scanner.rules.input_validation import scan_input_validation
from scanner.rules.command import scan_command
from scanner.rules.ldap import scan_ldap
from scanner.rules.insecure_deserialization import (
    scan_insecure_deserialization,
)
from scanner.rules.security_misconfiguration import (
    scan_security_misconfiguration,
)
from scanner.rules.authentication_access_control import (
    scan_authentication_access_control,
)
from scanner.rules.ssrf import detect_ssrf
from scanner.rules.sensitive import scan_sensitive_data_exposure

logger = logging.getLogger(__name__)


# ============================================================
# Rule Loading
# ============================================================

def load_rules():
    """Load all implemented vulnerability detection rules."""
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

    Build shared context once for diagnostics, then execute each
    rule independently. A failure in one rule does not prevent
    the remaining rules from running.
    """
    results = []
    rules = load_rules()

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
            error,
        )
        return results

    rule_failures = False

    for rule in rules:
        try:
            rule_results = rule(file_path)

            if rule_results:
                results.extend(rule_results)

        except (SyntaxError, ValueError, OSError) as error:
            rule_failures = True

            logger.exception(
                "Rule %s failed while scanning %s: %s",
                rule.__name__,
                file_path,
                error,
            )

    if rule_failures:
        logger.warning(
            "Scan for %s completed with rule failures; "
            "findings may be incomplete",
            file_path,
        )

    return results


# ============================================================
# Deduplication
# ============================================================

def deduplicate_findings(findings):
    """
    Remove identical findings while preferring higher confidence
    and then higher severity.

    Findings on different lines remain separate because they may
    represent different detection points or vulnerabilities.
    """
    severity_rank = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1,
    }

    unique = {}

    for finding in findings:
        key = (
            finding.get("vulnerability_type"),
            finding.get("file_name"),
            finding.get("line_number"),
            finding.get("code"),
        )

        current = unique.get(key)

        if current is None:
            unique[key] = finding
            continue

        new_priority = (
            finding.get("confidence", 0),
            severity_rank.get(finding.get("severity"), 0),
        )

        current_priority = (
            current.get("confidence", 0),
            severity_rank.get(current.get("severity"), 0),
        )

        if new_priority > current_priority:
            unique[key] = finding

    return list(unique.values())


def remove_duplicates(results):
    """Backward-compatible wrapper for finding deduplication."""
    return deduplicate_findings(results)
