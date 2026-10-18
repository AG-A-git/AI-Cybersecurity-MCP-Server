import pytest

import services.report_service as report_service


@pytest.mark.parametrize(
    "report_function",
    [
        report_service.generate_json_report,
        report_service.generate_html_report,
        report_service.generate_pdf_report,
    ],
    ids=["json", "html", "pdf"],
)
def test_report_functions_delegate_to_scan_result_service(
    monkeypatch,
    report_function,
):
    expected_data = {
        "id": 123,
        "project_id": 14,
        "total_findings": 1,
        "risk_score": 82.5,
        "vulnerabilities": [
            {
                "file_name": "src/app.py",
                "line_number": 42,
                "severity": "High",
                "recommendation": "Use parameterized queries.",
            }
        ],
    }
    calls = []

    def fake_get_scan_result(db, scan_id, user_id):
        calls.append(
            {
                "db": db,
                "scan_id": scan_id,
                "user_id": user_id,
            }
        )
        return expected_data

    monkeypatch.setattr(
        report_service,
        "get_scan_result",
        fake_get_scan_result,
    )

    fake_db = object()
    result = report_function(
        db=fake_db,
        scan_id=123,
        user_id=9,
    )

    assert result == expected_data
    assert calls == [
        {
            "db": fake_db,
            "scan_id": 123,
            "user_id": 9,
        }
    ]


def test_get_report_data_delegates_to_scan_result_service(monkeypatch):
    expected_data = {"id": 456, "risk_score": 0}
    calls = []

    def fake_get_scan_result(db, scan_id, user_id):
        calls.append((db, scan_id, user_id))
        return expected_data

    monkeypatch.setattr(
        report_service,
        "get_scan_result",
        fake_get_scan_result,
    )

    fake_db = object()
    result = report_service.get_report_data(
        db=fake_db,
        scan_id=456,
        user_id=12,
    )

    assert result == expected_data
    assert calls == [(fake_db, 456, 12)]
