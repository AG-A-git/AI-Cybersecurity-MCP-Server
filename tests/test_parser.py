import pytest

from scanner.parser import (
    MAX_FILE_SIZE,
    read_file,
    supported_language,
)
from scanner.scan import scan_file


def test_supported_python_file():
    assert supported_language("example.py")


def test_supported_javascript_file():
    assert supported_language("example.js")


def test_supported_extensions_are_case_insensitive():
    assert supported_language("example.PY")
    assert supported_language("example.JS")


def test_unsupported_file_type():
    assert not supported_language("example.txt")
    assert not supported_language("example.json")


@pytest.mark.parametrize("invalid_path", [None, 123, [], {}])
def test_supported_language_rejects_invalid_path_types(invalid_path):
    assert not supported_language(invalid_path)


def test_read_file_returns_content(tmp_path):
    file_path = tmp_path / "example.py"
    file_path.write_text("print('hello')\n", encoding="utf-8")
    assert read_file(file_path) == "print('hello')\n"


def test_read_file_rejects_invalid_path_type():
    with pytest.raises(ValueError):
        read_file(None)


def test_read_file_rejects_unsupported_extension(tmp_path):
    file_path = tmp_path / "example.txt"
    file_path.write_text("sample text", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported file type"):
        read_file(file_path)


def test_read_file_rejects_missing_file(tmp_path):
    file_path = tmp_path / "missing.py"
    with pytest.raises(ValueError, match="does not exist"):
        read_file(file_path)


def test_read_file_rejects_oversized_file(tmp_path):
    file_path = tmp_path / "large.py"
    file_path.write_bytes(b"a" * (MAX_FILE_SIZE + 1))
    with pytest.raises(ValueError, match="5 MB"):
        read_file(file_path)


def test_scan_file_skips_oversized_file(tmp_path):
    file_path = tmp_path / "large.py"
    file_path.write_bytes(b"a" * (MAX_FILE_SIZE + 1))
    assert scan_file(file_path) == []


def test_read_file_enforces_byte_limit_for_multibyte_utf8(tmp_path):
    file_path = tmp_path / "large_utf8.py"
    content = (chr(233) * (MAX_FILE_SIZE // 2 + 1)).encode("utf-8")
    file_path.write_bytes(content)
    with pytest.raises(ValueError, match="5 MB"):
        read_file(file_path)
