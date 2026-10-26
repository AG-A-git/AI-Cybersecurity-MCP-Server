import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def configure_scanner_allowed_roots(monkeypatch, tmp_path):
    repository_root = Path(__file__).resolve().parents[1]
    approved_roots = [str(repository_root), str(tmp_path)]

    monkeypatch.setenv(
        "SCANNER_ALLOWED_ROOTS",
        os.pathsep.join(approved_roots),
    )
