import asyncio
import json

import pytest
import mcp_server as server


def test_all_six_mcp_tools_are_registered():
    tools = server.mcp._tool_manager.list_tools()
    names = {tool.name for tool in tools}
    assert names == {
        "scan_code", "scan_project", "analyze_vulnerability",
        "get_scan_results", "get_risk_score", "generate_report",
    }


def test_analyze_vulnerability_is_rule_based():
    result = server.analyze_vulnerability({
        "type": "SQL Injection", "severity": "Critical"
    })
    assert result["finding"] == "SQL Injection"
    assert result["severity"] == "Critical"
    assert "parameterized queries" in result["recommendation"]
    assert result["analysis_method"] == "deterministic_rule_based"
    assert result["ai_provider_used"] is False


def test_analyze_vulnerability_rejects_non_dictionary():
    with pytest.raises(TypeError, match="finding must be a dictionary"):
        server.analyze_vulnerability("not a finding")


def test_scan_persistence_risk_and_reports(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "import subprocess\n"
        "user_input = input()\n"
        "subprocess.call(user_input, shell=True)\n",
        encoding="utf-8",
    )
    db_path = tmp_path / "task11_test.sqlite"
    monkeypatch.setenv("SCANNER_ALLOWED_ROOTS", str(project))

    result = server.scan_project(str(project), str(db_path))
    scan_id = result["scan_id"]
    assert scan_id > 0
    assert db_path.exists()

    saved = server.get_scan_results(str(db_path), scan_id)
    assert saved["found"] is True
    assert saved["scan"]["id"] == scan_id
    assert saved["scan"]["findings"] == result["findings"]

    risk = server.get_risk_score(str(db_path), scan_id)
    assert risk["found"] is True
    assert 0 <= risk["risk_score"] <= 100
    assert risk["scoring_method"] == "severity_weighted_heuristic"
    assert risk["ai_provider_used"] is False

    report = server.generate_report(str(db_path), scan_id)
    assert report["found"] is True
    assert "# Cybersecurity Scan Report" in report["content"]

    json_report = server.generate_report(str(db_path), scan_id, "json")
    assert json.loads(json_report["content"])["id"] == scan_id


def test_missing_scan_returns_not_found(tmp_path):
    db_path = str(tmp_path / "missing.sqlite")
    assert server.get_scan_results(db_path, 999)["found"] is False
    assert server.get_risk_score(db_path, 999)["found"] is False
    assert server.generate_report(db_path, 999)["found"] is False


def test_report_rejects_unsupported_format(tmp_path):
    with pytest.raises(ValueError, match="format must be"):
        server.generate_report(str(tmp_path / "unused.sqlite"), 1, "html")


def test_token_verifier_rejects_invalid_tokens(monkeypatch):
    async def check():
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        verifier = server.EnvironmentTokenVerifier()
        assert await verifier.verify_token("dummy") is None

        monkeypatch.setenv("MCP_BEARER_TOKEN", "task11-test-secret")
        assert await verifier.verify_token("wrong") is None
        token = await verifier.verify_token("task11-test-secret")
        assert token is not None
        assert "scanner" in token.scopes

    asyncio.run(check())


def test_analyze_vulnerability_accepts_canonical_vulnerability_type():
    result = server.analyze_vulnerability({
        "vulnerability_type": "SQL Injection",
        "severity": "High",
        "file_name": "app.py",
        "line_number": 12,
        "confidence": 90,
        "code": "SELECT * FROM users",
    })
    assert result["finding"] == "SQL Injection"
    assert result["severity"] == "High"
    assert "parameterized queries" in result["recommendation"]
    assert result["analysis_method"] == "deterministic_rule_based"
    assert result["ai_provider_used"] is False

def test_analyze_vulnerability_legacy_type_fallback():
    result = server.analyze_vulnerability({"type": "SQL Injection"})

    assert result["finding"] == "SQL Injection"
    assert "parameterized queries" in result["recommendation"]


def test_analyze_vulnerability_legacy_name_fallback():
    result = server.analyze_vulnerability({"name": "SQL Injection"})

    assert result["finding"] == "SQL Injection"
    assert "parameterized queries" in result["recommendation"]


def test_analyze_vulnerability_canonical_field_takes_precedence():
    result = server.analyze_vulnerability({
        "vulnerability_type": "SQL Injection",
        "type": "Cross-Site Scripting",
        "name": "Command Injection",
        "severity": "High",
    })

    assert result["finding"] == "SQL Injection"
    assert result["finding"] != "Unknown finding"
    assert "parameterized queries" in result["recommendation"]
