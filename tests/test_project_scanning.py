
import json
import pytest
import stat
import zipfile

from scanner.scan import scan_project
from scanner.engine import find_source_files
from scanner.zip_scan_result import scan_zip_with_status, ZipScanStatus


PROJECT_FILES = {
    "app.py": """password = "admin"
print(password)
""",
    "auth.py": """password = "123456"
print(password)
""",
    "database.py": """import pickle
data = pickle.loads(request.data)
""",
    "api.py": """from flask import request
import requests

user_url = request.args.get("url")
requests.get(user_url)
""",
    "config.py": """app.run(debug=True)
""",
}


def create_project(project_path):
    project_path.mkdir()

    for file_name, code in PROJECT_FILES.items():
        (project_path / file_name).write_text(
            code,
            encoding="utf-8",
        )


def create_project_zip(project_path, zip_path):
    with zipfile.ZipFile(
        zip_path,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        for file_name in PROJECT_FILES:
            file_path = project_path / file_name
            archive.write(
                file_path,
                arcname=file_name,
            )


def test_multi_file_project_scanning(tmp_path):
    project_path = tmp_path / "project"
    create_project(project_path)

    findings = scan_project(str(project_path))

    assert len(findings) == 7

    file_names = {
        finding["file_name"]
        for finding in findings
    }

    assert any(name.endswith("app.py") for name in file_names)
    assert any(name.endswith("auth.py") for name in file_names)
    assert any(name.endswith("database.py") for name in file_names)
    assert any(name.endswith("api.py") for name in file_names)
    assert any(name.endswith("config.py") for name in file_names)


def test_multi_file_findings_retain_location_and_code(tmp_path):
    project_path = tmp_path / "project"
    create_project(project_path)

    findings = scan_project(str(project_path))

    ssrf_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SSRF"
    ]

    assert len(ssrf_findings) == 1

    finding = ssrf_findings[0]

    assert finding["file_name"].endswith("api.py")
    assert finding["line_number"] == 5
    assert finding["code"] == "requests.get(user_url)"


def test_zip_project_scanning(tmp_path):
    project_path = tmp_path / "project"
    zip_path = tmp_path / "project.zip"

    create_project(project_path)
    create_project_zip(project_path, zip_path)

    findings = scan_project(str(zip_path))

    assert len(findings) == 7

    file_names = {
        finding["file_name"]
        for finding in findings
    }

    assert "app.py" in file_names
    assert "auth.py" in file_names
    assert "database.py" in file_names
    assert "api.py" in file_names
    assert "config.py" in file_names


def test_zip_findings_retain_location_and_code(tmp_path):
    project_path = tmp_path / "project"
    zip_path = tmp_path / "project.zip"

    create_project(project_path)
    create_project_zip(project_path, zip_path)

    findings = scan_project(str(zip_path))

    ssrf_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SSRF"
    ]

    assert len(ssrf_findings) == 1

    finding = ssrf_findings[0]

    assert finding["file_name"] == "api.py"
    assert finding["line_number"] == 5
    assert finding["code"] == "requests.get(user_url)"


def test_scan_project_rejects_invalid_path_types():
    for invalid_path in (None, [], {}):
        assert scan_project(invalid_path) == []


def test_scan_project_rejects_integer_path():
    assert scan_project(123) == []


# ============================================================
# Adversarial ZIP regression tests
# ============================================================

def test_zip_rejects_path_traversal(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    outside_file = tmp_path / "outside.py"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../outside.py", 'print("test")')

    findings = scan_project(str(zip_path))

    assert findings == []
    assert not outside_file.exists()


def test_zip_rejects_windows_style_path_traversal(tmp_path):
    zip_path = tmp_path / "windows_traversal.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(r"..\outside.py", 'print("test")')

    assert scan_project(str(zip_path)) == []


@pytest.mark.parametrize(
    "member_name",
    [
        r"C:\outside.py",
        r"\\server\share\outside.py",
        "/outside.py",
    ],
)
def test_zip_rejects_absolute_member_paths(tmp_path, member_name):
    zip_path = tmp_path / "absolute_path.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(member_name, 'print("test")')

    assert scan_project(str(zip_path)) == []


def test_zip_rejects_symbolic_link_entries(tmp_path):
    from scanner.scan import scan_zip

    zip_path = tmp_path / "symlink_entry.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "app.py",
            "import pickle\n"
            "data = pickle.loads(request.data)\n",
        )

        link = zipfile.ZipInfo("link.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "app.py")

    assert scan_zip(zip_path) == []


def test_zip_rejects_malformed_archive(tmp_path):
    zip_path = tmp_path / "malformed.zip"
    zip_path.write_bytes(b"this is not a valid zip archive")

    assert scan_project(str(zip_path)) == []


def test_zip_rejects_too_many_files(tmp_path):
    zip_path = tmp_path / "too_many_files.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        for index in range(1001):
            archive.writestr(
                f"file_{index}.py",
                "x = 1\n",
            )

    assert scan_project(str(zip_path)) == []


def test_zip_rejects_oversized_uncompressed_content(tmp_path):
    zip_path = tmp_path / "oversized.zip"
    oversized_content = b"A" * (100 * 1024 * 1024 + 1)

    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr("large.py", oversized_content)

    assert scan_project(str(zip_path)) == []


def test_scan_zip_rejects_duplicate_member_names(tmp_path):
    """The direct ZIP scanner must reject duplicate entry names."""
    from scanner.scan import scan_zip

    zip_path = tmp_path / "duplicate_members_direct.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("app.py", "print('first')")

        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("app.py", "print('second')")

    assert scan_zip(zip_path) == []


def test_engine_scans_project_inside_ancestor_named_venv(tmp_path):
    project_path = tmp_path / "venv" / "project"
    project_path.mkdir(parents=True)

    source_file = project_path / "app.py"
    source_file.write_text(
        'password = "admin"\nprint(password)\n',
        encoding="utf-8",
    )

    source_files = find_source_files(project_path)

    assert source_file in source_files


def test_zip_rejects_negative_declared_file_size(tmp_path, monkeypatch):
    import scanner.scan as scan_module

    zip_path = tmp_path / "negative_size.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("safe.py", "print('safe')")

    original_zip_file = scan_module.zipfile.ZipFile

    class FakeInfo:
        def __init__(self, original):
            self.filename = original.filename
            self.external_attr = original.external_attr
            self.create_system = original.create_system
            self.file_size = -1

    class FakeArchive:
        def __init__(self, *args, **kwargs):
            self.archive = original_zip_file(*args, **kwargs)

        def __enter__(self):
            self.archive.__enter__()
            return self

        def __exit__(self, *args):
            return self.archive.__exit__(*args)

        def infolist(self):
            return [
                FakeInfo(info)
                for info in self.archive.infolist()
            ]

        def extractall(self, path):
            return self.archive.extractall(path)

    monkeypatch.setattr(
        scan_module.zipfile,
        "ZipFile",
        FakeArchive,
    )

    assert scan_module.scan_zip(zip_path) == []


# ============================================================
# JSON report regression tests
# ============================================================

def test_json_report_round_trip_preserves_findings(tmp_path, monkeypatch):
    from scanner import scan

    expected = [
        {
            "file_name": "app.py",
            "line_number": 1,
            "vulnerability_type": "Hardcoded Password",
            "severity": "HIGH",
            "code": 'password = "admin"',
        }
    ]

    monkeypatch.setattr(scan, "scan_project", lambda path: expected)

    report = scan.generate_json_report(tmp_path)

    assert json.loads(report) == expected


def test_json_report_serializes_empty_results(tmp_path, monkeypatch):
    from scanner import scan

    monkeypatch.setattr(scan, "scan_project", lambda path: [])

    report = scan.generate_json_report(tmp_path)

    assert json.loads(report) == []


def test_deduplicated_findings_remain_consistent_after_json_round_trip():
    from scanner.utils import deduplicate_findings

    findings = [
        {
            "file_name": "app.py",
            "line_number": 1,
            "vulnerability_type": "Hardcoded Password",
            "severity": "HIGH",
            "code": 'password = "admin"',
            "confidence": 90,
        },
        {
            "file_name": "app.py",
            "line_number": 1,
            "vulnerability_type": "Hardcoded Password",
            "severity": "HIGH",
            "code": 'password = "admin"',
            "confidence": 70,
        },
        {
            "file_name": "auth.py",
            "line_number": 2,
            "vulnerability_type": "Hardcoded Password",
            "severity": "HIGH",
            "code": 'password = "123456"',
            "confidence": 80,
        },
    ]

    first_pass = deduplicate_findings(findings)
    restored = json.loads(json.dumps(first_pass))
    second_pass = deduplicate_findings(restored)

    assert len(first_pass) == 2
    assert len(second_pass) == 2
    assert second_pass == restored

    app_finding = next(
        finding
        for finding in second_pass
        if finding["file_name"] == "app.py"
    )

    assert app_finding["confidence"] == 90


# ============================================================
# Allowed-root security regression tests
# ============================================================

def test_scan_denied_when_no_allowed_roots_configured(tmp_path, monkeypatch):
    from scanner.path_security import ALLOWED_ROOTS_ENV

    source = tmp_path / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    monkeypatch.delenv(ALLOWED_ROOTS_ENV, raising=False)

    with pytest.raises(PermissionError, match=ALLOWED_ROOTS_ENV):
        scan_project(str(source))


def test_scan_denied_outside_allowed_root(tmp_path, monkeypatch):
    from scanner.path_security import ALLOWED_ROOTS_ENV

    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    source = outside / "app.py"
    source.write_text("print('outside')\n", encoding="utf-8")

    monkeypatch.setenv(ALLOWED_ROOTS_ENV, str(allowed))

    with pytest.raises(PermissionError, match="outside configured"):
        scan_project(str(source))


def test_scan_denies_symlink_escape(tmp_path, monkeypatch):
    from scanner.path_security import ALLOWED_ROOTS_ENV

    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    source = outside / "app.py"
    source.write_text("print('outside')\n", encoding="utf-8")

    link = allowed / "escape.py"

    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(
            f"Symlinks unavailable in this environment: {exc}"
        )

    monkeypatch.setenv(ALLOWED_ROOTS_ENV, str(allowed))

    with pytest.raises(PermissionError, match="outside configured"):
        scan_project(str(link))


# ============================================================
# ZIP status reporting regression tests
# ============================================================

def test_zip_status_valid_archive_completes(tmp_path):
    zip_path = tmp_path / "valid.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("app.py", "print('hello')")

    expected_findings = [{"file_name": "app.py"}]
    result = scan_zip_with_status(
        zip_path,
        lambda path: expected_findings,
    )

    assert result.status == ZipScanStatus.COMPLETED
    assert result.findings == tuple(expected_findings)


def test_zip_status_rejects_traversal_without_scanning(tmp_path):
    zip_path = tmp_path / "traversal.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../outside.py", "print('unsafe')")

    scanner_called = False

    def scan_callback(path):
        nonlocal scanner_called
        scanner_called = True
        return []

    result = scan_zip_with_status(zip_path, scan_callback)

    assert result.status == ZipScanStatus.REJECTED
    assert scanner_called is False


def test_zip_status_duplicate_member_names(tmp_path):
    zip_path = tmp_path / "duplicates.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("app.py", "print('first')")

        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("app.py", "print('second')")

    result = scan_zip_with_status(zip_path, lambda path: [])

    assert result.status == ZipScanStatus.REJECTED
