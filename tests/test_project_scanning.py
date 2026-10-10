
import zipfile

from scanner.scan import scan_project


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


# Adversarial ZIP regression tests


def test_zip_rejects_path_traversal(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    outside_file = tmp_path / "outside.py"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../outside.py", 'print("test")')

    findings = scan_project(str(zip_path))

    assert findings == []
    assert not outside_file.exists()


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
