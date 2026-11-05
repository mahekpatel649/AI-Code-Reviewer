"""Secure repository upload and archive extraction handler.

Implements strict validation, path-traversal prevention, zip-bomb defense,
and file classification for the AI Code Intelligence & Security Reviewer.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# Configuration limits
DEFAULT_MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
DEFAULT_MAX_FILE_COUNT = 500
DEFAULT_MAX_SINGLE_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# Language categories
ACTIVE_SCAN_EXTENSIONS = {".py"}
UNSUPPORTED_SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".java", ".cpp",
    ".c", ".h", ".hpp", ".html", ".htm", ".css", ".sql", ".php", ".go", ".rs"
}

# Explicitly excluded paths and secrets
EXCLUDED_NAMES = {
    ".git", "__pycache__", ".venv", "venv", "env", ".env", ".env.local",
    ".env.production", ".idea", ".vscode", ".pytest_cache", ".tox",
    "node_modules", ".DS_Store", "Thumbs.db"
}

BINARY_EXTENSIONS = {
    ".pyc", ".pyd", ".exe", ".dll", ".so", ".dylib", ".bin", ".iso",
    ".tar", ".gz", ".rar", ".7z", ".png", ".jpg", ".jpeg", ".gif",
    ".webp", ".ico", ".pdf", ".docx", ".xlsx", ".zip", ".woff", ".woff2"
}


class UploadSecurityError(Exception):
    """Raised when an uploaded repository fails security checks."""
    pass


def is_safe_path(target_dir: str, file_path: str) -> bool:
    """Ensure extracting file_path stays strictly inside target_dir.
    
    Prevents directory traversal (Zip Slip vulnerability).
    """
    resolved_target = os.path.abspath(target_dir)
    resolved_dest = os.path.abspath(os.path.join(target_dir, file_path))
    return resolved_dest.startswith(resolved_target + os.sep) or resolved_dest == resolved_target


def validate_zip_archive(
    archive: zipfile.ZipFile,
    max_files: int = DEFAULT_MAX_FILE_COUNT,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_SIZE,
) -> None:
    """Verify archive member count, uncompressed size and path security."""
    infolist = archive.infolist()
    if len(infolist) > max_files:
        raise UploadSecurityError(
            f"Archive exceeds maximum allowed file count ({len(infolist)} > {max_files})."
        )

    total_uncompressed = 0
    for member in infolist:
        # Check relative path traversal attempts
        norm_name = os.path.normpath(member.filename)
        if norm_name.startswith("..") or os.path.isabs(norm_name) or ":\\" in norm_name:
            raise UploadSecurityError(
                f"Path traversal detected in archive member: '{member.filename}'"
            )

        total_uncompressed += member.file_size
        if total_uncompressed > max_uncompressed_bytes:
            raise UploadSecurityError(
                f"Decompressed archive size exceeds limit of {max_uncompressed_bytes // (1024*1024)} MB."
            )


def extract_repository(
    upload_source: bytes | io.BytesIO | str,
    target_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Safely extracts a ZIP repository and indexes its contents.
    
    Returns:
        Dict with:
          - 'extract_dir': absolute path to extracted files
          - 'python_files': list of relative file paths ready for Bandit/AST scan
          - 'unsupported_files': list of relative paths for other code files
          - 'ignored_files': list of excluded or binary files
          - 'total_files': count of recognized files
          - 'extension_counts': map of extension -> count
    """
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="reviewer_repo_")
    else:
        os.makedirs(target_dir, exist_ok=True)

    if isinstance(upload_source, bytes):
        zip_file_obj = io.BytesIO(upload_source)
    elif isinstance(upload_source, io.BytesIO):
        zip_file_obj = upload_source
    elif isinstance(upload_source, str):
        if not os.path.exists(upload_source):
            raise UploadSecurityError(f"File not found: {upload_source}")
        zip_file_obj = open(upload_source, "rb")
    else:
        raise UploadSecurityError("Invalid upload source type.")

    try:
        with zipfile.ZipFile(zip_file_obj, "r") as archive:
            validate_zip_archive(archive)

            # Safe extraction
            for member in archive.infolist():
                # Skip pure directories
                if member.is_dir():
                    continue

                clean_name = os.path.normpath(member.filename)
                if not is_safe_path(target_dir, clean_name):
                    raise UploadSecurityError(f"Unsafe path traversal rejected: {clean_name}")

                # Check path components for excluded directory names
                parts = Path(clean_name).parts
                if any(part in EXCLUDED_NAMES for part in parts):
                    continue

                dest_path = os.path.join(target_dir, clean_name)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                with archive.open(member) as src, open(dest_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    except zipfile.BadZipFile as e:
        cleanup_extraction(target_dir)
        raise UploadSecurityError(f"Corrupted or invalid ZIP file: {str(e)}")
    except Exception:
        cleanup_extraction(target_dir)
        raise
    finally:
        if isinstance(upload_source, str) and hasattr(zip_file_obj, "close"):
            zip_file_obj.close()

    # Index extracted files
    return classify_repository_files(target_dir)


def save_single_python_file(
    content: bytes,
    filename: str,
    target_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Save a single uploaded Python source file and return extraction metadata."""
    if not filename.endswith(".py"):
        raise UploadSecurityError("Single file upload must have a .py extension.")

    if len(content) > DEFAULT_MAX_SINGLE_FILE_SIZE:
        raise UploadSecurityError(
            f"File size exceeds maximum limit of {DEFAULT_MAX_SINGLE_FILE_SIZE // (1024*1024)} MB."
        )

    clean_filename = os.path.basename(filename)
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix="reviewer_single_")
    else:
        os.makedirs(target_dir, exist_ok=True)

    dest_path = os.path.join(target_dir, clean_filename)
    with open(dest_path, "wb") as f:
        f.write(content)

    return classify_repository_files(target_dir)


def classify_repository_files(base_dir: str) -> Dict[str, Any]:
    """Classify repository files into scannable Python, unsupported languages, and ignored."""
    python_files: List[str] = []
    unsupported_files: List[str] = []
    ignored_files: List[str] = []
    extension_counts: Dict[str, int] = {}

    for root, dirs, files in os.walk(base_dir):
        # Prune excluded directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDED_NAMES and not d.startswith(".")]

        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, base_dir).replace("\\", "/")
            ext = os.path.splitext(file)[1].lower()

            if file in EXCLUDED_NAMES or ext in BINARY_EXTENSIONS:
                ignored_files.append(rel_path)
                continue

            extension_counts[ext] = extension_counts.get(ext, 0) + 1

            if ext in ACTIVE_SCAN_EXTENSIONS:
                python_files.append(rel_path)
            elif ext in UNSUPPORTED_SOURCE_EXTENSIONS:
                unsupported_files.append(rel_path)
            else:
                ignored_files.append(rel_path)

    total_files = len(python_files) + len(unsupported_files)

    return {
        "extract_dir": base_dir,
        "python_files": sorted(python_files),
        "unsupported_files": sorted(unsupported_files),
        "ignored_files": sorted(ignored_files),
        "total_files": total_files,
        "extension_counts": extension_counts,
    }


def cleanup_extraction(target_dir: Optional[str]) -> None:
    """Safely removes temporary extraction directory."""
    if target_dir and os.path.exists(target_dir):
        try:
            shutil.rmtree(target_dir, ignore_errors=True)
        except Exception:
            pass
