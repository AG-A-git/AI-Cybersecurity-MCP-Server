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