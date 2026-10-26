
import os

import pytest

from scanner.engine import scan_project


def test_detects_sql_injection_in_f_string(tmp_path):
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        'query = f"SELECT * FROM users WHERE id = {user_id}"\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["vulnerability"] == "SQL Injection"
        and finding["file"] == "vulnerable.py"
        for finding in findings
    )


def test_detects_sql_injection_in_string_concatenation(tmp_path):
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["vulnerability"] == "SQL Injection"
        and finding["file"] == "vulnerable.py"
        for finding in findings
    )


def test_detects_sql_injection_in_multiline_f_string(tmp_path):
    source_file = tmp_path / "vulnerable.py"
    source_file.write_text(
        '''query = f"""SELECT *
        FROM users
        WHERE id = {user_id}"""
''',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["vulnerability"] == "SQL Injection"
        and finding["file"] == "vulnerable.py"
        for finding in findings
    )


def test_multiline_sql_detector_does_not_cross_string_boundaries(tmp_path):
    source_file = tmp_path / "safe.py"
    source_file.write_text(
        '''first = """SELECT * FROM users"""
second = """WHERE id = {user_id}"""
''',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert not any(
        finding["file"] == "safe.py"
        and finding["vulnerability"] == "SQL Injection"
        for finding in findings
    )


def test_scan_project_rejects_nonexistent_path(tmp_path):
    missing_path = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        scan_project(str(missing_path))


def test_findings_use_project_relative_paths(tmp_path):
    nested_dir = tmp_path / "src"
    nested_dir.mkdir()

    source_file = nested_dir / "sample.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert any(
        finding["file"] == os.path.join("src", "sample.py")
        for finding in findings
    )


def test_scanner_skips_symlink_to_file_outside_project(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    outside_file = tmp_path / "outside.py"
    outside_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    linked_file = project_dir / "linked.py"

    try:
        linked_file.symlink_to(outside_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation is unavailable: {exc}")

    findings = scan_project(str(project_dir))

    assert not any(
        finding["file"] == "linked.py"
        for finding in findings
    )

def test_scanner_skips_files_larger_than_configured_limit(tmp_path):
    source_file = tmp_path / "large.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    # This test will use the proposed max_file_size_bytes argument.
    findings = scan_project(
        str(tmp_path),
        max_file_size_bytes=10,
    )

    assert not any(
        finding["file"] == "large.py"
        for finding in findings
    )


def test_scanner_stops_after_configured_file_limit(tmp_path):
    for filename in ("first.py", "second.py", "third.py"):
        (tmp_path / filename).write_text(
            'query = "SELECT * FROM users WHERE name = " + username\n',
            encoding="utf-8",
        )

    # This test will use the proposed max_files argument.
    findings = scan_project(
        str(tmp_path),
        max_files=1,
    )

    assert len({
        finding["file"]
        for finding in findings
    }) <= 1


def test_scanner_accepts_configured_scan_timeout(tmp_path):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    # This test will use the proposed timeout_seconds argument.
    findings = scan_project(
        str(tmp_path),
        timeout_seconds=60,
    )

    assert isinstance(findings, list)
@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_size_bytes": -1},
        {"max_files": -1},
        {"timeout_seconds": -1},
    ],
)
def test_scanner_rejects_invalid_resource_limits(tmp_path, kwargs):
    with pytest.raises(ValueError):
        scan_project(str(tmp_path), **kwargs)
def test_scanner_stops_when_timeout_is_reached(tmp_path, monkeypatch):
    import scanner.engine as engine

    source_file = tmp_path / "sample.py"
    source_file.write_text(
        'query = "SELECT * FROM users WHERE name = " + username\n',
        encoding="utf-8",
    )

    clock = iter([0.0, 0.0, 2.0, 2.0, 2.0])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(clock))

    findings = engine.scan_project(
        str(tmp_path),
        timeout_seconds=1,
    )

    assert findings == []


def test_scanner_file_limit_counts_files_without_findings(tmp_path):
    for filename in ("first.py", "second.py", "third.py"):
        (tmp_path / filename).write_text(
            "value = 1\n",
            encoding="utf-8",
        )

    findings = scan_project(
        str(tmp_path),
        max_files=1,
    )

    assert findings == []