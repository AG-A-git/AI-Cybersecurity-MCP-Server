from types import SimpleNamespace
from unittest.mock import Mock

import services.mcp_server as mcp_server
from models import Project, Scan, Vulnerability
from services.scan_result_service import serialize_scan


def test_mcp_risk_score_matches_scan_result(monkeypatch):
    scan = Scan(
        id=123,
        project_id=14,
        status="completed",
    )
    scan.vulnerabilities = [
        Vulnerability(
            id=1,
            file_name="src/app.py",
            line_number=42,
            vulnerability_type="SQL Injection",
            severity="High",
            confidence=90,
            code="cursor.execute(query)",
            risk_score=82.5,
        )
    ]

    project = Project(
        id=14,
        project_name="Risk parity test",
        owner_id=9,
    )

    # REST-style scan result uses the shared serializer.
    rest_result = serialize_scan(scan, project)

    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = scan

    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )
    monkeypatch.setattr(
        mcp_server,
        "SessionLocal",
        lambda: db,
    )
    monkeypatch.setattr(
        mcp_server,
        "get_scan_result",
        lambda db, scan_id, user_id: rest_result,
    )

    mcp_result = mcp_server.get_risk_score(scan_id=123)

    assert rest_result["risk_score"] == 82.5
    assert mcp_result["risk_score"] == rest_result["risk_score"]
    assert mcp_result["scan_id"] == rest_result["id"]
    db.close.assert_called_once()
