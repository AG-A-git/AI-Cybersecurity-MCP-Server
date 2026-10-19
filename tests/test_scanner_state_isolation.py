from concurrent.futures import ThreadPoolExecutor

from scanner.engine import scan_project


def _create_projects(base, prefix):
    project_a = base / f"{prefix}_vulnerable"
    project_b = base / f"{prefix}_clean"
    project_a.mkdir()
    project_b.mkdir()

    (project_a / "app.py").write_text(
        'from flask import request\n'
        'import requests\n'
        'url = request.args.get("url")\n'
        'requests.get(url)\n',
        encoding="utf-8",
    )
    (project_b / "app.py").write_text(
        'message = "hello"\n'
        'print(message)\n',
        encoding="utf-8",
    )
    return project_a, project_b

def test_sequential_scans_do_not_leak_findings(tmp_path):
    project_a = tmp_path / "project_a"
    project_b = tmp_path / "project_b"
    project_a.mkdir()
    project_b.mkdir()

    (project_a / "app.py").write_text(
        'from flask import request\n'
        'import requests\n'
        'url = request.args.get("url")\n'
        'requests.get(url)\n',
        encoding="utf-8",
    )
    (project_b / "app.py").write_text(
        'message = "hello"\n'
        'print(message)\n',
        encoding="utf-8",
    )

    findings_a_first = scan_project(project_a)
    findings_b_after_a = scan_project(project_b)
    findings_b_first = scan_project(project_b)
    findings_a_after_b = scan_project(project_a)

    assert findings_a_first
    assert findings_b_after_a == []
    assert findings_b_first == []
    assert findings_a_after_b == findings_a_first


def test_concurrent_scans_do_not_leak_findings(tmp_path):
    project_a = tmp_path / "concurrent_a"
    project_b = tmp_path / "concurrent_b"
    project_a.mkdir()
    project_b.mkdir()

    (project_a / "app.py").write_text(
        'from flask import request\n'
        'import requests\n'
        'url = request.args.get("url")\n'
        'requests.get(url)\n',
        encoding="utf-8",
    )
    (project_b / "app.py").write_text(
        'message = "hello"\n'
        'print(message)\n',
        encoding="utf-8",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(scan_project, project_a)
        future_b = executor.submit(scan_project, project_b)
        findings_a = future_a.result()
        findings_b = future_b.result()

    assert findings_a
    assert findings_b == []


def test_repeated_concurrent_scans_remain_isolated(tmp_path):
    project_a, project_b = _create_projects(tmp_path, "repeated")
    expected_a = scan_project(project_a)

    assert expected_a
    assert scan_project(project_b) == []

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(scan_project, project_a if i % 2 == 0 else project_b)
            for i in range(12)
        ]
        results = [future.result() for future in futures]

    for i, findings in enumerate(results):
        if i % 2 == 0:
            assert findings == expected_a
        else:
            assert findings == []


def test_mutating_returned_findings_does_not_affect_later_scan(tmp_path):
    project_a, _ = _create_projects(tmp_path, "mutation")
    first_results = scan_project(project_a)
    assert first_results

    first_results.clear()

    second_results = scan_project(project_a)
    assert second_results



def test_zip_scan_cleans_up_temporary_directory(tmp_path, monkeypatch):
    import zipfile
    import scanner.scan as scan_module

    zip_path = tmp_path / "cleanup_test.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "app.py",
            'message = "hello"\n'
            'print(message)\n',
        )

    created_directories = []
    real_temporary_directory = scan_module.tempfile.TemporaryDirectory

    def tracking_temporary_directory(*args, **kwargs):
        temporary_directory = real_temporary_directory(*args, **kwargs)
        created_directories.append(temporary_directory)
        return temporary_directory

    monkeypatch.setattr(
        scan_module.tempfile,
        "TemporaryDirectory",
        tracking_temporary_directory,
    )

    from scanner.scan import scan_zip

    scan_zip(zip_path)

    assert created_directories
    assert all(
        not __import__("os").path.exists(directory.name)
        for directory in created_directories
    )


def test_scan_recovers_after_unexpected_rule_failure(tmp_path, monkeypatch):
    import pytest
    import scanner.engine as engine

    project = tmp_path / "recovery_project"
    project.mkdir()
    (project / "app.py").write_text(
        'message = "hello"\nprint(message)\n',
        encoding="utf-8",
    )

    real_run_all_rules = engine.run_all_rules
    calls = 0

    def fail_once_then_scan(file_path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TypeError("simulated unexpected rule error")
        return real_run_all_rules(file_path)

    monkeypatch.setattr(engine, "run_all_rules", fail_once_then_scan)

    with pytest.raises(TypeError, match="simulated unexpected rule error"):
        engine.scan_project(project)

    findings = engine.scan_project(project)

    assert calls >= 2
    assert isinstance(findings, list)
    assert findings == []
