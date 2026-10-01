"""
MCP server for AI vulnerability analysis.
"""

from mcp.server.fastmcp import FastMCP

from mcp_server.resources import register_resources
from mcp_server.tools import run_ai_analysis


mcp = FastMCP(
    "AI Cybersecurity MCP Server"
)


@mcp.tool()
def analyze_vulnerability_tool(
    file: str,
    line: int,
    vulnerability: str,
    severity: str,
    confidence: float,
    code: str
) -> dict:
    """
    Analyze a single scanner vulnerability finding.

    Returns deterministic risk information together with
    AI-generated explanation and recommendation.
    """

    scanner_result = {
        "file": file,
        "line": line,
        "vulnerability": vulnerability,
        "severity": severity,
        "confidence": confidence,
        "code": code
    }

    return run_ai_analysis(scanner_result)


register_resources(mcp)


if __name__ == "__main__":
    mcp.run(transport="stdio")