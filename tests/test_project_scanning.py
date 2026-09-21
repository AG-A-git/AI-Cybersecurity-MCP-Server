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
            encoding="utf-8"
        )


def create_project_zip(project_path, zip_path):
    with zipfile.ZipFile(
        zip_path,
        "w",
        zipfile.ZIP_DEFLATED
    ) as archive:

        for file_name in PROJECT_FILES:
            file_path = project_path / file_name
            archive.write(
                file_path,
                arcname=file_name
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

    assert any(
        file_name.endswith("app.py")
        for file_name in file_names
    )

    assert any(
        file_name.endswith("auth.py")
        for file_name in file_names
    )

    assert any(
        file_name.endswith("database.py")
        for file_name in file_names
    )

    assert any(
        file_name.endswith("api.py")
        for file_name in file_names
    )

    assert any(
        file_name.endswith("config.py")
        for file_name in file_names
    )


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