from scanner.engine import find_source_files, scan_project
from scanner.scan_state import ScanStatus
from scanner.engine import get_last_scan_outcome


def test_nested_source_file_is_discovered(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)

    source = nested / "handler.py"
    source.write_text(
        'import pickle\n'
        'data = pickle.loads(request.data)\n',
        encoding="utf-8",
    )

    files = find_source_files(project)
    assert source in files

    findings = scan_project(project)
    assert any(
        f["file_name"].endswith("handler.py")
        for f in findings
    )


def test_empty_source_does_not_crash_project_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    (project / "empty.py").write_text("", encoding="utf-8")

    assert scan_project(project) == []
    assert get_last_scan_outcome().status == ScanStatus.COMPLETED


def test_unsupported_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    (project / "notes.txt").write_text(
        "password = 'example'\n", encoding="utf-8"
    )

    assert find_source_files(project) == []
    assert scan_project(project) == []


def test_malformed_python_does_not_abort_other_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    project.mkdir()

    (project / "broken.py").write_text(
        "def broken(:\n", encoding="utf-8"
    )
    (project / "vulnerable.py").write_text(
        "import pickle\n"
        "data = pickle.loads(request.data)\n",
        encoding="utf-8",
    )

    findings = scan_project(project)
    assert any(
        f["file_name"].endswith("vulnerable.py")
        for f in findings
    )


def test_safe_parameterized_sql_has_no_sql_injection_finding(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SCAN_ALLOWED_ROOTS", str(tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    (project / "safe.py").write_text(
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
        encoding="utf-8",
    )

    findings = scan_project(project)
    assert not any(
        f["vulnerability_type"] == "SQL Injection"
        for f in findings
    )
