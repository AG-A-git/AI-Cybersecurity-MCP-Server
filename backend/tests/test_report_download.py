import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException

# Always prioritize the backend directory over the repository root.
BACKEND_DIR = Path(__file__).resolve().parent.parent

if str(BACKEND_DIR) in sys.path:
    sys.path.remove(str(BACKEND_DIR))

sys.path.insert(0, str(BACKEND_DIR))

from app import app
from routers import scan as scan_router
from services import report_service

client = TestClient(app)


@pytest.fixture
def authenticated_user(monkeypatch):
    class User:
        id = 41

    monkeypatch.setattr(
        scan_router,
        "get_authenticated_user",
        lambda credentials, db: User(),
    )
    return User()


@pytest.mark.parametrize(
    ("report_format", "content_type", "extension", "expected_content"),
    [
        ("json", "application/json", ".json", b'"scan_id": 123'),
        ("html", "text/html; charset=utf-8", ".html", b"No vulnerabilities recorded for this scan."),
        ("pdf", "application/pdf", ".pdf", b"%PDF"),
    ],
)
def test_report_download_returns_attachment(
    tmp_path,
    monkeypatch,
    authenticated_user,
    report_format,
    content_type,
    extension,
    expected_content,
):
    report_dir = tmp_path / "generated_reports"
    monkeypatch.setattr(report_service, "REPORT_DIR", report_dir)
    monkeypatch.setattr(scan_router, "REPORT_DIR", report_dir)

    monkeypatch.setattr(
        scan_router,
        f"generate_{report_format}_report",
        lambda db, scan_id, user_id: {
            "scan_id": scan_id,
            "title": "Test report",
            "vulnerabilities": [],
        },
    )
    response = client.get(
        "/scans/123/report",
        params={"format": report_format},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        content_type.split(";")[0]
    )
    assert f"scan_123{extension}" in response.headers.get(
        "content-disposition", ""
    )
    assert expected_content in response.content


def test_report_download_rejects_unsupported_format(
    monkeypatch,
    authenticated_user,
):
    response = client.get(
        "/scans/123/report",
        params={"format": "exe"},
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 400


def test_report_download_rejects_missing_authentication():
    response = client.get(
        "/scans/123/report",
        params={"format": "pdf"},
    )

    assert response.status_code == 401


def test_report_download_propagates_ownership_rejection(
    monkeypatch,
    authenticated_user,
):
    def reject_other_user(db, scan_id, user_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    monkeypatch.setattr(
        scan_router,
        "generate_pdf_report",
        reject_other_user,
    )

    response = client.get(
        "/scans/123/report",
        params={"format": "pdf"},
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 404


def test_report_download_returns_404_if_generated_file_is_missing(
    tmp_path,
    monkeypatch,
    authenticated_user,
):
    report_dir = tmp_path / "generated_reports"
    report_dir.mkdir()
    monkeypatch.setattr(scan_router, "REPORT_DIR", report_dir)

    monkeypatch.setattr(
        scan_router,
        "generate_pdf_report",
        lambda db, scan_id, user_id: {
            "scan_id": scan_id,
            "title": "Test report",
            "vulnerabilities": [],
        },
    )

    def report_without_file(**kwargs):
        return {
            "file_name": "scan_123.pdf",
            "format": "pdf",
            "content_type": "application/pdf",
            "file_size_bytes": 0,
            "relative_path": "generated_reports/scan_123.pdf",
        }

    monkeypatch.setattr(
        scan_router,
        "render_report_file",
        report_without_file,
    )

    response = client.get(
        "/scans/123/report",
        params={"format": "pdf"},
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 404
