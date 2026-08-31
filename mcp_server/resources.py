"""
MCP resources for the AI Cybersecurity server.
"""

from mcp.server.fastmcp import FastMCP


# ======================================================
# MCP Resource
# ======================================================

def register_resources(mcp: FastMCP):
    """
    Register MCP resources.
    """

    @mcp.resource("security://info")
    def security_info() -> str:
        """
        Information about the AI cybersecurity
        vulnerability analysis service.
        """

        return """
AI Cybersecurity Vulnerability Analysis Server

Capabilities:
- Vulnerability normalization
- OWASP Top 10 mapping
- CWE mapping
- Deterministic risk scoring
- AI vulnerability explanation
- Security remediation recommendations

Supported vulnerability examples:
- SQL Injection
- XSS
- Command Injection
- LDAP Injection
- Hardcoded Credentials/Secrets
- Weak Cryptography
- Broken Access Control
- Security Misconfiguration
- Insecure Authentication
- Insecure Deserialization
- Sensitive Data Exposure
- SSRF
""".strip()