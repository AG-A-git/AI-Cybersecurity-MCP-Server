from __future__ import annotations

import hmac
import json
import os
from collections import Counter
from datetime import datetime, timezone
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from scanner.engine import (
    get_last_scan_outcome,
    scan_project as engine_scan_project,
)
from scanner.path_security import ALLOWED_ROOTS_ENV
from scanner.scan_persistence import (
    get_scan,
    initialize_database,
    save_scan,
)

AUTH_SCOPE = "scanner"
SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Info": 0,
}


class EnvironmentTokenVerifier:
    """Verify bearer tokens against the configured MCP_BEARER_TOKEN."""

    async def verify_token(self, token: str) -> AccessToken | None:
        expected = os.environ.get("MCP_BEARER_TOKEN", "")
        if not expected or not hmac.compare_digest(token, expected):
            return None
        return AccessToken(
            token=token,
            client_id="configured-bearer-client",
            scopes=[AUTH_SCOPE],
        )


def _auth_settings() -> AuthSettings:
    host = os.environ.get("MCP_HTTP_HOST", "127.0.0.1")
    port = int(os.environ.get("MCP_HTTP_PORT", "8000"))
    base = f"http://{host}:{port}"
    return AuthSettings(
        issuer_url=base,
        resource_server_url=base,
        required_scopes=[AUTH_SCOPE],
    )


mcp = FastMCP(
    "AI Cybersecurity Scanner",
    token_verifier=EnvironmentTokenVerifier(),
    auth=_auth_settings(),
    host=os.environ.get("MCP_HTTP_HOST", "127.0.0.1"),
    port=int(os.environ.get("MCP_HTTP_PORT", "8000")),
)


@mcp.tool()
def get_scan_results(db_path: str, scan_id: int) -> dict:
    """Retrieve one persisted scan and its findings by database path and scan ID."""
    if not db_path or not db_path.strip():
        raise ValueError("db_path must not be empty")

    initialize_database(db_path)
    result = get_scan(db_path=db_path, scan_id=scan_id)
    if result is None:
        return {"found": False, "scan_id": scan_id}
    return {"found": True, "scan": result}


@mcp.tool()
def get_risk_score(db_path: str, scan_id: int) -> dict:
    """Calculate a severity-weighted heuristic score for a persisted scan."""
    if not db_path or not db_path.strip():
        raise ValueError("db_path must not be empty")

    result = get_scan(db_path=db_path, scan_id=scan_id)
    if result is None:
        return {"found": False, "scan_id": scan_id}

    findings = result.get("findings", [])
    counts = Counter()
    total_weight = 0

    for finding in findings:
        severity = str(finding.get("severity", "Info")).title()
        counts[severity] += 1
        total_weight += SEVERITY_WEIGHTS.get(severity, 0)

    score = min(100, total_weight)
    if score >= 40:
        level = "Critical"
    elif score >= 20:
        level = "High"
    elif score >= 8:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "Info"

    return {
        "found": True,
        "scan_id": scan_id,
        "risk_score": score,
        "risk_level": level,
        "severity_counts": dict(counts),
        "scoring_method": "severity_weighted_heuristic",
        "weights": SEVERITY_WEIGHTS,
        "ai_provider_used": False,
    }


@mcp.tool()
def generate_report(db_path: str, scan_id: int, format: str = "markdown") -> dict:
    """Generate a Markdown or JSON report from a persisted scan."""
    if not db_path or not db_path.strip():
        raise ValueError("db_path must not be empty")

    output_format = format.strip().lower()
    if output_format not in {"markdown", "json"}:
        raise ValueError("format must be 'markdown' or 'json'")

    result = get_scan(db_path=db_path, scan_id=scan_id)
    if result is None:
        return {"found": False, "scan_id": scan_id}

    if output_format == "json":
        content = json.dumps(result, indent=2, default=str)
    else:
        findings = result.get("findings", [])
        counts = Counter(
            str(item.get("severity", "Info")).title()
            for item in findings
        )
        lines = [
            "# Cybersecurity Scan Report",
            "",
            f"- Scan ID: {scan_id}",
            f"- Project: {result.get('project_path', 'Unknown')}",
            f"- Findings: {len(findings)}",
            "",
            "## Severity Summary",
            "",
        ]
        lines.extend(
            f"- {severity}: {count}"
            for severity, count in sorted(counts.items())
        )
        lines.extend(["", "## Findings", ""])
        if not findings:
            lines.append("No findings were recorded.")
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding.get('type', finding.get('name', 'Finding'))}",
                f"- Severity: {finding.get('severity', 'Info')}",
                f"- File: {finding.get('file', finding.get('file_path', 'Unknown'))}",
                f"- Line: {finding.get('line', 'Unknown')}",
                "",
            ])
        content = "\n".join(lines)

    return {
        "found": True,
        "scan_id": scan_id,
        "format": output_format,
        "content": content,
    }




@mcp.tool()
def scan_code(path: str) -> list:
    """Scan an approved source file or project directory for vulnerabilities."""
    return engine_scan_project(path)


@mcp.tool()
def scan_project(
    path: str,
    db_path: str,
    timeout_seconds: int | None = None,
    hard_timeout: bool = False,
) -> dict:
    """Scan an approved path and persist results to the specified database."""
    if not path or not path.strip():
        raise ValueError("path must not be empty")
    if not db_path or not db_path.strip():
        raise ValueError("db_path must not be empty")

    started_at = datetime.now(timezone.utc).isoformat()
    findings = engine_scan_project(
        path,
        timeout_seconds=timeout_seconds,
        hard_timeout=hard_timeout,
    )
    finished_at = datetime.now(timezone.utc).isoformat()
    outcome = get_last_scan_outcome()
    if outcome is None:
        raise RuntimeError(
            "The scanner did not record a terminal outcome; scan was not persisted."
        )

    scan_id = save_scan(
        db_path=db_path,
        project_path=path,
        findings=findings,
        outcome=outcome,
        started_at=started_at,
        finished_at=finished_at,
    )
    return {
        "scan_id": scan_id,
        "scan": get_scan(db_path=db_path, scan_id=scan_id),
        "findings": findings,
    }


@mcp.tool()
def analyze_vulnerability(finding: dict) -> dict:
    """Provide deterministic remediation guidance for a scanner finding."""
    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary")

    name = str(finding.get("type") or finding.get("name") or "Unknown finding")
    severity = str(finding.get("severity") or "Info").title()
    guidance = {
        "SQL Injection": "Use parameterized queries; never concatenate untrusted input into SQL.",
        "Command Injection": "Avoid constructed shell commands; use safe argument arrays and validate input.",
        "Cross-Site Scripting": "Contextually encode untrusted output and use safe templating APIs.",
        "Hardcoded Credentials": "Move secrets to a secret manager or protected environment configuration, and rotate exposed credentials.",
        "Path Traversal": "Resolve paths against an approved base directory and reject paths that escape it.",
        "Weak Cryptography": "Use modern, vetted cryptographic algorithms and secure library defaults.",
        "Insecure Deserialization": "Avoid deserializing untrusted data or use a safe, constrained data format.",
        "Information Disclosure": "Remove sensitive data from responses and logs.",
        "Debug Code": "Remove debug statements and avoid exposing internal details in production.",
    }
    return {
        "finding": name,
        "severity": severity,
        "recommendation": guidance.get(
            name,
            "Review the finding evidence and apply the relevant secure-coding guidance.",
        ),
        "analysis_method": "deterministic_rule_based",
        "ai_provider_used": False,
    }


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise SystemExit(
            "Unsupported MCP_TRANSPORT; choose stdio, sse, or streamable-http."
        )

    if transport in {"sse", "streamable-http"} and not os.environ.get("MCP_BEARER_TOKEN"):
        raise SystemExit(
            "MCP_BEARER_TOKEN must be configured before starting an HTTP transport."
        )

    if not os.environ.get(ALLOWED_ROOTS_ENV):
        print(
            f"Warning: {ALLOWED_ROOTS_ENV} is not configured; filesystem scans may be denied.",
            file=__import__("sys").stderr,
        )

    mcp.run(transport=transport)
