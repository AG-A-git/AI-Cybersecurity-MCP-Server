"""
MCP Resources

Resources exposed by the AI Cybersecurity MCP Server.
"""


def register_resources(mcp):
    """
    Register MCP resources.

    This function is intentionally kept separate from the
    MCP tools so that resources can be expanded later.
    """

    @mcp.resource("cybersecurity://status")
    def cybersecurity_status() -> str:
        """
        Return the current cybersecurity MCP server status.
        """

        return "AI Cybersecurity MCP Server is running"