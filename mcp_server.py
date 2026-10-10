from mcp.server.fastmcp import FastMCP

from scanner.engine import scan_project


mcp = FastMCP("AI Cybersecurity Scanner")


@mcp.tool()
def scan_code(path: str) -> list:
    """
    Scan a source file or project directory for security vulnerabilities.
    """
    return scan_project(path)


if __name__ == "__main__":
    mcp.run()