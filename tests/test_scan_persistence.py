import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scanner.scan_persistence import save_scan, get_scan, list_scans
from scanner.scan_state import ScanOutcome, ScanStatus


def finding(severity, fingerprint):
    return {
        "file_name": "sample.py",
        "line_number": 3,
        "vulnerability_type": "Test",
        "severity": severity,
        "confidence": 0.9,
        "code": "example()",
        "fingerprint": fingerprint,
    }


def outcome(status=ScanStatus.COMPLETED):
    return ScanOutcome(status=status, files_scanned=2, error_count=0,
                       message="test run")


def test_round_trip_summary_findings_and_timestamps(tmp_path):
    db = tmp_path / "history.sqlite"
    findings = [finding("High", "a"), finding("Low", "b"),
                finding("High", "c")]
    scan_id = save_scan(db, "project", findings, outcome())
    saved = get_scan(db, scan_id)

    assert saved["status"] == "completed"
    assert saved["files_scanned"] == 2
    assert saved["total_findings"] == len(findings)
    assert saved["severity_counts"] == {"High": 2, "Low": 1}
    assert saved["findings"] == findings
    assert saved["started_at"] and saved["finished_at"]


def test_terminal_statuses_are_preserved(tmp_path):
    db = tmp_path / "history.sqlite"
    for status in ScanStatus:
        scan_id = save_scan(db, "project", [], outcome(status))
        assert get_scan(db, scan_id)["status"] == status.value


def test_concurrent_persistence_keeps_scan_records_isolated(tmp_path):
    db = tmp_path / "history.sqlite"

    def write(i):
        item = finding("High" if i % 2 else "Low", f"fp-{i}")
        return save_scan(db, f"project-{i}", [item], outcome())

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(write, range(12)))

    assert len(set(ids)) == 12
    for i, scan_id in enumerate(ids):
        saved = get_scan(db, scan_id)
        assert saved["project_path"] == f"project-{i}"
        assert saved["findings"][0]["fingerprint"] == f"fp-{i}"


def test_unknown_scan_returns_none_and_history_is_newest_first(tmp_path):
    db = tmp_path / "history.sqlite"
    first = save_scan(db, "first", [], outcome())
    second = save_scan(db, "second", [], outcome())

    assert get_scan(db, -1) is None
    assert [item["id"] for item in list_scans(db)] == [second, first]


def test_supplied_timestamps_are_preserved(tmp_path):
    db = tmp_path / "history.sqlite"
    start = "2026-10-19T10:00:00+00:00"
    finish = "2026-10-19T10:00:01+00:00"
    scan_id = save_scan(db, "project", [], outcome(),
                        started_at=start, finished_at=finish)
    saved = get_scan(db, scan_id)
    assert saved["started_at"] == start
    assert saved["finished_at"] == finish

from scanner.persistent_scanner import scan_project_and_persist


def test_real_scan_is_persisted_with_findings_and_summary(tmp_path):
    import sqlite3

    source = tmp_path / "app.py"
    source.write_text('password = "hardcoded-secret"\n', encoding="utf-8")
    db = tmp_path / "scan-history.sqlite"

    findings = scan_project_and_persist(source, db)
    with sqlite3.connect(db) as conn:
        scan_id = conn.execute("SELECT MAX(id) FROM scan_runs").fetchone()[0]

    saved = get_scan(db, scan_id)
    assert saved["project_path"] == str(source)
    assert saved["total_findings"] == len(findings)
    assert saved["findings"] == findings
    assert saved["status"] in {status.value for status in ScanStatus}
    assert saved["started_at"] <= saved["finished_at"]


def test_failed_scan_is_persisted_when_engine_raises(tmp_path):
    import sqlite3

    source = tmp_path / "missing.py"
    db = tmp_path / "scan-history.sqlite"

    try:
        scan_project_and_persist(source, db)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")

    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT status, error_count FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert row is not None
    assert row[0] == "failed"
    assert row[1] >= 1

def test_concurrent_real_scans_persist_independently(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    sources = []
    for index in range(4):
        source = tmp_path / f"app_{index}.py"
        source.write_text(
            f'password = "secret-{index}"\n',
            encoding="utf-8",
        )
        sources.append(source)

    db = tmp_path / "concurrent-history.sqlite"

    def run(source):
        findings = scan_project_and_persist(source, db)
        return str(source), findings

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(run, sources))

    import sqlite3
    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT id, project_path, status, total_findings "
            "FROM scan_runs ORDER BY project_path"
        ).fetchall()

    assert len(rows) == 4
    saved_by_path = {row[1]: row for row in rows}
    for path, findings in results:
        row = saved_by_path[path]
        assert row[2] == "completed"
        assert row[3] == len(findings)
        saved = get_scan(db, row[0])
        assert saved["findings"] == findings
