"""
Backend service mapping for MCP operations.

This module does not implement the MCP server.
It defines the backend service boundaries that
Member 3's MCP layer should call.
"""

from services.scan_service import create_scan

from services.scan_result_service import (
    get_scan_result,
    get_scan_history
)

from services.report_service import (
    generate_json_report,
    generate_html_report,
    generate_pdf_report
)

from logging_config import get_logger


logger = get_logger(__name__)

MCP_SERVICE_MAP = {
    "scan_project": {
        "service": "scan_service",
        "function": "create_scan"
    },
    "analyze_vulnerability": {
        "service": "ai_client",
        "function": "analyze_vulnerabilities"
    },
    "get_scan_results": {
        "service": "scan_result_service",
        "function": "get_scan_result"
    },
    "get_risk_score": {
        "service": "scan_result_service",
        "function": "calculate_scan_risk_score"
    },
    "generate_report": {
        "service": "report_service",
        "functions": [
            "generate_json_report",
            "generate_html_report",
            "generate_pdf_report"
        ]
    }
}


def get_mcp_service_mapping():
    """
    Return the backend mapping used by MCP operations.
    """

    return MCP_SERVICE_MAP
def validate_mcp_service_mapping():
    """
    Validate that all required MCP operations
    have a backend service mapping.
    """

    required_operations = {
        "scan_project",
        "analyze_vulnerability",
        "get_scan_results",
        "get_risk_score",
        "generate_report"
    }

    missing_operations = (
        required_operations - MCP_SERVICE_MAP.keys()
    )

    if missing_operations:
        raise ValueError(
            f"Missing MCP service mappings: {sorted(missing_operations)}"
        )

    logger.info(
        "MCP service mapping validated | operations=%s",
        len(MCP_SERVICE_MAP)
    )

    return True