import pytest

import scanner.engine as engine
from scanner.scan_state import ScanStatus


def test_successful_scan_records_completed(tmp_path):
    source = tmp_path / "app.py"
    source.write_text('message = "hello"\n', encoding="utf-8")

    engine.scan_project(source)

    outcome = engine.get_last_scan_outcome()
    assert outcome.status == ScanStatus.COMPLETED
    assert outcome.files_scanned == 1
    assert outcome.error_count == 0


def test_zero_timeout_records_timed_out(tmp_path):
    source = tmp_path / "app.py"
    source.write_text('message = "hello"\n', encoding="utf-8")

    result = engine.scan_project(source, timeout_seconds=0)

    assert result == []
    assert engine.get_last_scan_outcome().status == ScanStatus.TIMED_OUT


def test_missing_path_records_failed(tmp_path):
    missing = tmp_path / "does_not_exist.py"

    with pytest.raises(FileNotFoundError):
        engine.scan_project(missing)

    outcome = engine.get_last_scan_outcome()
    assert outcome.status == ScanStatus.FAILED
    assert outcome.error_count >= 1


def test_unexpected_error_records_failed(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text('message = "hello"\n', encoding="utf-8")

    def raise_unexpected_error(_file_path):
        raise TypeError("simulated unexpected error")

    monkeypatch.setattr(engine, "run_all_rules", raise_unexpected_error)

    with pytest.raises(TypeError, match="simulated unexpected error"):
        engine.scan_project(source)

    assert engine.get_last_scan_outcome().status == ScanStatus.FAILED

def test_malformed_zip_records_failed_terminal_state(tmp_path):
    import scanner.engine as engine
    from scanner.scan_state import ScanStatus

    zip_path = tmp_path / "malformed.zip"
    zip_path.write_bytes(b"not a valid zip archive")

    findings = engine.scan_project(zip_path)

    assert findings == []
    outcome = engine.get_last_scan_outcome()
    assert outcome.status == ScanStatus.FAILED
    assert outcome.error_count >= 1


def test_unsafe_zip_records_failed_terminal_state(tmp_path):
    import zipfile

    import scanner.engine as engine
    from scanner.scan_state import ScanStatus

    zip_path = tmp_path / "unsafe.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../outside.py", "print('test')")

    findings = engine.scan_project(zip_path)

    assert findings == []
    outcome = engine.get_last_scan_outcome()
    assert outcome.status == ScanStatus.FAILED
    assert outcome.error_count >= 1
