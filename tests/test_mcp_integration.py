import pytest

from mcp_server import scan_code


def test_mcp_scan_code_detects_insecure_deserialization(tmp_path):
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "import pickle\n"
        "data = pickle.loads(request.data)\n",
        encoding="utf-8",
    )

    findings = scan_code(str(source_file))

    assert isinstance(findings, list)
    assert any(
        finding["vulnerability_type"] == "Insecure Deserialization"
        for finding in findings
    )


def test_mcp_scan_code_returns_empty_list_for_safe_file(tmp_path):
    source_file = tmp_path / "safe.py"
    source_file.write_text(
        "message = 'Hello, world!'\n"
        "print(message)\n",
        encoding="utf-8",
    )

    findings = scan_code(str(source_file))

    assert isinstance(findings, list)
    assert findings == []


def test_mcp_scan_code_scans_project_directory(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    source_file = project_dir / "app.py"
    source_file.write_text(
        "import pickle\n"
        "data = pickle.loads(request.data)\n",
        encoding="utf-8",
    )

    findings = scan_code(str(project_dir))

    assert isinstance(findings, list)
    assert any(
        finding["vulnerability_type"] == "Insecure Deserialization"
        for finding in findings
    )


def test_mcp_scan_code_raises_for_missing_path():
    with pytest.raises(FileNotFoundError, match="Path does not exist"):
        scan_code("definitely_missing_scanner_test_project")


def test_mcp_scan_code_filters_invalid_findings(tmp_path, monkeypatch):
    import scanner.engine as engine

    source_file = tmp_path / "app.py"
    source_file.write_text(
        "message = 'hello'\n",
        encoding="utf-8",
    )

    # Missing the required "confidence" field.
    invalid_finding = {
        "file_name": "app.py",
        "line_number": 1,
        "vulnerability_type": "Test Finding",
        "severity": "High",
        "code": "message = 'hello'",
    }

    monkeypatch.setattr(
        engine,
        "run_all_rules",
        lambda file_path: [invalid_finding],
    )

    findings = engine.scan_project(str(source_file))

    assert findings == []


def test_engine_scan_project_returns_empty_list_for_invalid_path_types():
    from scanner.engine import scan_project

    for invalid_path in (None, [], {}, 123):
        assert scan_project(invalid_path) == []


def test_engine_scan_project_raises_for_missing_zip(tmp_path):
    from scanner.engine import scan_project

    missing_zip = tmp_path / "definitely_missing.zip"

    assert not missing_zip.exists()

    with pytest.raises(
        FileNotFoundError,
        match="ZIP path does not exist",
    ):
        scan_project(str(missing_zip))
