
import time

import scanner.engine as engine
from scanner.scan_state import ScanStatus
from scanner.scan_worker import run_file_with_hard_timeout


def _hanging_worker(file_path, result_queue):
    """Simulate a worker that never completes."""
    time.sleep(30)


def test_hard_timeout_terminates_hanging_worker(tmp_path):
    source = tmp_path / "hang.py"
    source.write_text('message = "hello"\n', encoding="utf-8")

    started = time.monotonic()
    status, result = run_file_with_hard_timeout(
        source,
        timeout_seconds=2,
        worker_target=_hanging_worker,
    )

    assert status == "timeout"
    assert result is None
    assert time.monotonic() - started < 10


def test_engine_records_timed_out_when_worker_times_out(
    tmp_path, monkeypatch
):
    source = tmp_path / "app.py"
    source.write_text('message = "hello"\n', encoding="utf-8")

    def fake_timeout(_file_path, _timeout_seconds):
        return "timeout", None

    monkeypatch.setattr(engine, "run_file_with_hard_timeout", fake_timeout)

    findings = engine.scan_project(
        source,
        timeout_seconds=10,
        hard_timeout=True,
    )

    assert findings == []
    outcome = engine.get_last_scan_outcome()
    assert outcome.status == ScanStatus.TIMED_OUT
    assert outcome.files_scanned == 0
