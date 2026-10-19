import asyncio
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services import upload_service


class FakeUpload:
    def __init__(self, *chunks):
        self.chunks = list(chunks)

    async def read(self, size=-1):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


def test_save_file_rejects_oversized_upload(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(upload_service, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(upload_service, "MAX_FILE_SIZE", 4)

    with pytest.raises(ValueError, match="10 MB limit|size exceeds"):
        asyncio.run(
            upload_service.save_file(
                FakeUpload(b"123", b"456"),
                "large.py",
            )
        )

    assert not (upload_dir / "large.py").exists()


def test_save_file_does_not_overwrite_existing_upload(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(upload_service, "UPLOAD_DIR", upload_dir)

    first_path = asyncio.run(
        upload_service.save_file(FakeUpload(b"first"), "main.py")
    )
    second_path = asyncio.run(
        upload_service.save_file(FakeUpload(b"second"), "main.py")
    )

    assert first_path != second_path, "Uploads must have distinct storage paths"
    assert first_path.read_bytes() == b"first"
    assert second_path.read_bytes() == b"second"


def test_extract_zip_rejects_path_traversal(tmp_path, monkeypatch):
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    monkeypatch.setattr(upload_service, "EXTRACT_DIR", extract_dir)

    archive = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escaped.txt", "should not escape")

    with pytest.raises(ValueError, match="path traversal"):
        upload_service.extract_zip(archive)

    assert not (extract_dir / "escaped.txt").exists()
    assert not (tmp_path / "escaped.txt").exists()


def test_extract_zip_enforces_uncompressed_size_limit(
    tmp_path, monkeypatch
):
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    monkeypatch.setattr(upload_service, "EXTRACT_DIR", extract_dir)
    monkeypatch.setattr(upload_service, "MAX_ZIP_EXTRACTED_SIZE", 5)

    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("file.py", "123456")

    with pytest.raises(ValueError, match="50 MB extraction limit|exceed"):
        upload_service.extract_zip(archive)


def test_extract_zip_enforces_entry_count_limit(tmp_path, monkeypatch):
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    monkeypatch.setattr(upload_service, "EXTRACT_DIR", extract_dir)
    monkeypatch.setattr(upload_service, "MAX_ZIP_FILES", 1)

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("one.py", "print(1)")
        zf.writestr("two.py", "print(2)")

    with pytest.raises(ValueError, match="too many files"):
        upload_service.extract_zip(archive)


def test_extract_zip_cleans_partial_files_on_extraction_failure(
    tmp_path, monkeypatch
):
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    monkeypatch.setattr(upload_service, "EXTRACT_DIR", extract_dir)

    archive = tmp_path / "broken.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("partial.py", "print('partial')")

    def simulate_partial_extraction(self, path, *args, **kwargs):
        Path(path, "partial.py").write_text("partial data")
        raise zipfile.BadZipFile("Simulated CRC failure")

    monkeypatch.setattr(
        zipfile.ZipFile, "extractall", simulate_partial_extraction
    )

    with pytest.raises(zipfile.BadZipFile):
        upload_service.extract_zip(archive)

    assert not (extract_dir / "broken").exists(), (
        "Failed extraction must not leave partial files behind"
    )
