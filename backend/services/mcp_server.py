"""MCP tools for the existing AI cybersecurity backend."""

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from services.scan_worker import execute_scan_in_background

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from database import SessionLocal
from logging_config import get_logger
from models import Scan
from services.ai_client import analyze_vulnerabilities
from services.mcp_auth import (
    MCPJWTAuthMiddleware,
    get_authenticated_mcp_user,
)
from services.report_service import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)
from services.scan_result_service import (
    calculate_scan_risk_score,
    get_scan_result,
)
from services.scan_service import create_scan, fail_scan_safely


logger = get_logger(__name__)
_scan_executor = ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="mcp-scan",
)

MAX_AI_FINDINGS = 50
MAX_AI_INPUT_BYTES = 256 * 1024

REQUIRED_FINDING_FIELDS = {
    "file",
    "line",
    "vulnerability",
    "severity",
    "confidence",
    "code",
}


server = MCPServer(
    name="ai-cybersecurity-mcp-server",
    title="AI Cybersecurity MCP Server",
    description=(
        "Authenticated cybersecurity tools for project scanning, "
        "AI vulnerability analysis, scan results, risk scoring, "
        "and report data."
    ),
    instructions=(
        "Use these tools only for authorized cybersecurity work. "
        "Project and scan access is restricted to the authenticated "
        "user. Scan creation queues a scan; it does not execute it "
        "directly. HTML and PDF report tools return prepared report "
        "data, not rendered files."
    ),
    version="0.1.0",
)


def _service_error(exc: HTTPException) -> ToolError:
    """Convert expected service-layer HTTP errors into anticipated MCP tool errors."""
    return ToolError(
        f"Request rejected ({exc.status_code}): {exc.detail}"
    )


@server.tool(
    name="scan_project",
    description=(
        "Queue a scan for a project owned by the authenticated user. "
        "The project must have uploaded files and no active scan."
    ),
)
def scan_project(project_id: int) -> dict[str, Any]:
    user = get_authenticated_mcp_user()
    db = SessionLocal()

    try:
        scan = create_scan(
            db=db,
            project_id=project_id,
            user_id=user.user_id,
        )
        try:
            _scan_executor.submit(
                execute_scan_in_background,
                scan.id,
                SessionLocal,
            )
        except RuntimeError as exc:
            logger.exception(
                "Unable to schedule MCP scan: scan_id=%s",
                scan.id,
            )
            fail_scan_safely(
                db,
                scan.id,
                "Scan could not be scheduled. Please retry.",
            )
            raise ValueError(
                "Unable to schedule the scan."
            ) from exc
        status = getattr(scan.status, "value", scan.status)

        return {
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "status": str(status),
            "message": "Scan queued successfully.",
        }

    except HTTPException as exc:
        raise _service_error(exc) from exc

    except SQLAlchemyError as exc:
        logger.exception("Database error while queueing MCP scan")
        raise ValueError("Unable to queue the scan.") from exc

    finally:
        db.close()


@server.tool(
    name="analyze_vulnerability",
    description=(
        "Analyze a caller-provided list of normalized vulnerability "
        "findings using the existing AI analysis service. This tool "
        "does not claim that supplied findings came from a verified scan."
    ),
)
def analyze_vulnerability(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate bounded finding input before invoking the AI service."""

    if not isinstance(findings, list):
        raise ValueError("Findings must be a list")

    if len(findings) > MAX_AI_FINDINGS:
        raise ValueError(
            f"Too many findings: maximum allowed is {MAX_AI_FINDINGS}"
        )

    try:
        input_size = len(
            json.dumps(
                findings,
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Findings must contain valid JSON-compatible values"
        ) from exc

    if input_size > MAX_AI_INPUT_BYTES:
        raise ValueError("AI input exceeds the 256 KiB size limit")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError(
                f"Finding at index {index} must be a dictionary"
            )

        missing_fields = REQUIRED_FINDING_FIELDS - finding.keys()

        if missing_fields:
            raise ValueError(
                f"Finding at index {index} is missing required fields: "
                f"{', '.join(sorted(missing_fields))}"
            )

    try:
        results = analyze_vulnerabilities(findings)

        return {
            "count": len(results),
            "findings": results,
        }

    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Invalid vulnerability input: {exc}"
        ) from exc

    except Exception as exc:
        logger.exception("MCP vulnerability analysis failed")
        raise ValueError(
            "Vulnerability analysis failed. Check the AI service logs."
        ) from exc


@server.tool(
    name="get_scan_results",
    description=(
        "Retrieve the results of a scan owned by the authenticated user."
    ),
)
def get_scan_results(scan_id: int) -> dict[str, Any]:
    user = get_authenticated_mcp_user()
    db = SessionLocal()

    try:
        return get_scan_result(
            db=db,
            scan_id=scan_id,
            user_id=user.user_id,
        )

    except HTTPException as exc:
        raise _service_error(exc) from exc

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while retrieving MCP scan results"
        )
        raise ValueError(
            "Unable to retrieve scan results."
        ) from exc

    finally:
        db.close()


@server.tool(
    name="get_risk_score",
    description=(
        "Calculate the risk score for a scan owned by the authenticated "
        "user. The score is based on the existing scan risk-score service."
    ),
)
def get_risk_score(scan_id: int) -> dict[str, Any]:
    user = get_authenticated_mcp_user()
    db = SessionLocal()

    try:
        # Enforce scan ownership before calculating the score.
        get_scan_result(
            db=db,
            scan_id=scan_id,
            user_id=user.user_id,
        )

        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan is None:
            raise ValueError("Scan not found.")

        score = calculate_scan_risk_score(scan)

        return {
            "scan_id": scan_id,
            "risk_score": score,
            "score_basis": (
                "Highest persisted vulnerability risk score"
            ),
        }

    except HTTPException as exc:
        raise _service_error(exc) from exc

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while calculating MCP risk score"
        )
        raise ValueError(
            "Unable to calculate the scan risk score."
        ) from exc

    finally:
        db.close()


@server.tool(
    name="generate_report",
    description=(
        "Prepare report data for a scan owned by the authenticated user. "
        "Supported formats are json, html, and pdf. HTML and PDF currently "
        "return prepared data and do not render downloadable files."
    ),
)
def generate_report(
    scan_id: int,
    report_format: str = "json",
) -> dict[str, Any]:
    user = get_authenticated_mcp_user()
    if not isinstance(report_format, str):
        raise ValueError(
            "Report format must be a string. Choose json, html, or pdf."
        )

    normalized_format = report_format.strip().lower()
    report_generators = {
        "json": generate_json_report,
        "html": generate_html_report,
        "pdf": generate_pdf_report,
    }

    generator = report_generators.get(normalized_format)

    if generator is None:
        raise ValueError(
            "Unsupported report format. Choose json, html, or pdf."
        )

    db = SessionLocal()

    try:
        report_data = generator(
            db=db,
            scan_id=scan_id,
            user_id=user.user_id,
        )

        return {
            "scan_id": scan_id,
            "format": normalized_format,
            "rendered_file": False,
            "report": report_data,
        }

    except HTTPException as exc:
        raise _service_error(exc) from exc

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while preparing MCP report"
        )
        raise ValueError(
            "Unable to prepare the report."
        ) from exc

    finally:
        db.close()


# Mount the MCP HTTP app into the existing FastAPI application.
mcp_app = server.streamable_http_app(
    streamable_http_path="/",
    json_response=True,
    stateless_http=True,
)

mcp_app.add_middleware(MCPJWTAuthMiddleware)
