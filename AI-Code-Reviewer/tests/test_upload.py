"""Unit tests for repository upload and extraction security."""

import io
import os
import zipfile
import pytest
from backend.upload import (
    UploadSecurityError,
    cleanup_extraction,
    extract_repository,
    save_single_python_file,
)


def create_zip_bytes(files_dict: dict) -> bytes:
    """Helper to create an in-memory zip file from a dict of {filename: content}."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files_dict.items():
            zf.writestr(fname, content)
    buffer.seek(0)
    return buffer.getvalue()


def test_valid_zip_extraction():
    """Test standard extraction classifying Python vs unsupported files."""
    files = {
        "main.py": "print('hello world')",
        "utils/helpers.py": "def add(a, b): return a + b",
        "frontend/app.js": "console.log('hi')",
        "index.html": "<h1>Test</h1>",
        "binary.bin": b"\x00\x01\x02\x03",
    }
    zip_bytes = create_zip_bytes(files)
    result = extract_repository(zip_bytes)

    try:
        assert os.path.exists(result["extract_dir"])
        assert "main.py" in result["python_files"]
        assert "utils/helpers.py" in result["python_files"]
        assert "frontend/app.js" in result["unsupported_files"]
        assert "index.html" in result["unsupported_files"]
        assert result["total_files"] == 4
    finally:
        cleanup_extraction(result["extract_dir"])
        assert not os.path.exists(result["extract_dir"])


def test_path_traversal_rejection():
    """Test that relative path traversal in ZIP member names is rejected."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../../malicious.py", "import os; os.system('calc')")
    buffer.seek(0)

    with pytest.raises(UploadSecurityError, match="[Pp]ath traversal"):
        extract_repository(buffer.getvalue())


def test_file_count_limit_rejection():
    """Test rejection when archive exceeds maximum file count limit."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.py", "x = 1")
    buffer.seek(0)

    with pytest.raises(UploadSecurityError, match="maximum allowed file count"):
        # We test with a small limit of 10
        with zipfile.ZipFile(buffer, "r") as archive:
            from backend.upload import validate_zip_archive
            validate_zip_archive(archive, max_files=10)


def test_save_single_python_file():
    """Test single .py file upload."""
    content = b"print('single file analysis')"
    result = save_single_python_file(content, "single_app.py")
    try:
        assert "single_app.py" in result["python_files"]
        assert result["total_files"] == 1
    finally:
        cleanup_extraction(result["extract_dir"])


def test_single_file_rejects_non_python():
    """Ensure non-python single files are rejected."""
    with pytest.raises(UploadSecurityError, match="must have a .py extension"):
        save_single_python_file(b"console.log('hi')", "index.js")
