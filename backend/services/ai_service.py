
"""
Rule-based vulnerability analysis.

Provides explanations, recommendations, CWE/OWASP mappings,
and a simple project risk score without an external AI API.
"""

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
    "informational": 0,
}

VULNERABILITY_GUIDANCE = {
    "possible hard-coded credential": {
        "severity": "Medium",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "explanation": (
            "A credential-like variable appears to contain a literal string. "
            "Hard-coded secrets can be exposed through source code, version "
            "control, logs, or shared files. Verify whether the value is an "
            "actual password, API key, or other secret."
        ),
        "recommendation": (
            "If this is a real secret, revoke or rotate it. Load secrets from "
            "environment variables or a managed secrets store, and avoid "
            "committing credentials to source control."
        ),
    },
    "use of eval()": {
        "severity": "High",
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "explanation": (
            "eval() evaluates a string as Python code. If an attacker can "
            "influence that string, arbitrary code may execute."
        ),
        "recommendation": (
            "Avoid eval() for untrusted input. Use safer parsing methods or "
            "explicitly validate input against an expected format."
        ),
    },
    "subprocess call with shell=true": {
        "severity": "High",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "explanation": (
            "A subprocess call enables shell interpretation. If untrusted "
            "input reaches the command, shell metacharacters may alter what "
            "gets executed."
        ),
        "recommendation": (
            "Prefer subprocess calls with an argument list and shell=False. "
            "Validate arguments and avoid concatenating untrusted input "
            "into commands."
        ),
    },
    "python syntax error": {
        "severity": "Info",
        "cwe": None,
        "owasp": None,
        "explanation": (
            "The scanner could not parse this Python file because it contains "
            "a syntax error. Security checks may be incomplete for this file."
        ),
        "recommendation": (
            "Fix the syntax error and run the scan again."
        ),
    },
}


def analyze_finding(finding: dict) -> dict:
    """
    Add guidance to a finding returned by scanner_service.run_scanner().
    Existing scanner fields are retained.
    """
    result = dict(finding)

    vulnerability_type = str(
        result.get("vulnerability", result.get("vulnerability_type", ""))
    ).strip().lower()

    guidance = VULNERABILITY_GUIDANCE.get(vulnerability_type)

    if guidance is None:
        guidance = {
            "severity": str(result.get("severity", "Medium")),
            "cwe": None,
            "owasp": None,
            "explanation": (
                "The scanner detected a potentially risky code pattern. "
                "Review the reported line and surrounding code to determine "
                "whether it is exploitable."
            ),
            "recommendation": (
                "Review the code, validate inputs, and follow secure coding "
                "practices appropriate to this finding."
            ),
        }

    result["severity"] = result.get("severity") or guidance["severity"]
    result["cwe"] = guidance["cwe"]
    result["owasp"] = guidance["owasp"]
    result["explanation"] = guidance["explanation"]
    result["recommendation"] = guidance["recommendation"]
    result["confidence"] = result.get("confidence") or "Medium"

    return result


def calculate_risk(findings: list[dict]) -> dict:
    """
    Calculate a capped project-level risk score from unique findings.
    This is a simple heuristic, not a CVSS score.
    """
    severity_scores = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 0,
        "informational": 0,
    }

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    # Deduplicate using file, line, vulnerability type, and code.
    unique_findings = {}

    for finding in findings:
        key = (
            str(finding.get("file_name", finding.get("file", ""))).lower(),
            finding.get("line_number", finding.get("line")),
            str(
                finding.get(
                    "vulnerability_type",
                    finding.get("vulnerability", finding.get("type", "")),
                )
            ).strip().lower(),
            str(
                finding.get(
                    "code",
                    finding.get("vulnerable_code", ""),
                )
            ).strip(),
        )
        unique_findings[key] = finding

    raw_score = 0

    for finding in unique_findings.values():
        severity = str(
            finding.get("severity", "medium")
        ).strip().lower()

        if severity not in severity_scores:
            severity = "medium"

        raw_score += severity_scores[severity]

        if severity in counts:
            counts[severity] += 1
        elif severity == "informational":
            counts["info"] += 1

    score = min(raw_score, 100)

    if counts["critical"] > 0:
        risk_level = "Critical"
    elif counts["high"] > 0:
        risk_level = "High"
    elif counts["medium"] > 0:
        risk_level = "Medium"
    elif counts["low"] > 0:
        risk_level = "Low"
    else:
        risk_level = "Informational"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "informational_count": counts["info"],
    }

def analyze_findings(findings: list[dict]) -> dict:
    """Analyze all findings and calculate the overall risk summary."""
    analyzed = [analyze_finding(item) for item in findings]

    return {
        "findings": analyzed,
        **calculate_risk(analyzed),
    }
