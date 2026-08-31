import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    """
    Connect to the MCP server through STDIO
    and verify tools and resources.
    """

    server_params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_server.server"],
        env=None
    )

    print("Starting MCP server...")

    async with stdio_client(server_params) as (
        read_stream,
        write_stream
    ):

        print("Connected to MCP server.")

        async with ClientSession(
            read_stream,
            write_stream
        ) as session:

            # ------------------------------------------
            # Initialize MCP session
            # ------------------------------------------

            await session.initialize()

            print("MCP session initialized.")

            # ------------------------------------------
            # List tools
            # ------------------------------------------

            tools_result = await session.list_tools()

            print("\n==============================")
            print("MCP TOOLS")
            print("==============================")

            for tool in tools_result.tools:

                print(
                    f"- {tool.name}"
                )

            # ------------------------------------------
            # List resources
            # ------------------------------------------

            resources_result = (
                await session.list_resources()
            )

            print("\n==============================")
            print("MCP RESOURCES")
            print("==============================")

            for resource in resources_result.resources:

                print(
                    f"- {resource.uri}"
                )

            # ------------------------------------------
            # Test vulnerability analysis tool
            # ------------------------------------------

            print("\n==============================")
            print("TESTING MCP TOOL")
            print("==============================")

            result = await session.call_tool(
                "analyze_vulnerability_tool",
                arguments={
                    "file": "app.py",
                    "line": 25,
                    "vulnerability": "SQLi",
                    "severity": "High",
                    "confidence": 90,
                    "code": "query = user_input"
                }
            )

            print("\nTool Result:")

            for content in result.content:

                if hasattr(content, "text"):

                    print(content.text)

                else:

                    print(content)


if __name__ == "__main__":
    asyncio.run(main())