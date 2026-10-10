"""Safe static file feature extraction — M7 Multi-Vector Threat Detection.

This module is pure static inspection: it accepts file bytes and filename/MIME metadata,
computes cryptographic hashes, checks magic byte signatures, inspects archives safely
without extracting files to disk, and extracts static risk features.

Zero execution, zero subprocesses, zero network requests.
"""

from __future__ import annotations

import hashlib
import io
import mimetypes
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Hard Archive & Inspection Limits (Zip bomb and resource protection)
# ---------------------------------------------------------------------------

MAX_ARCHIVE_ENTRIES = 100
MAX_UNCOMPRESSED_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_ARCHIVE_FILENAME_LEN = 255
MAX_COMPRESSION_RATIO = 100.0  # > 100:1 flagged as potential compression bomb
MAX_INSPECTION_BUFFER_BYTES = 5 * 1024 * 1024  # 5 MB inspection cap

# ---------------------------------------------------------------------------
# High-Risk Extensions
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".ps1",
        ".ps2",
        ".sh",
        ".bash",
        ".elf",
        ".dylib",
        ".dll",
        ".so",
        ".hta",
        ".cpl",
        ".jar",
        ".msi",
        ".msp",
        ".reg",
        ".wsf",
        ".wsh",
        ".iso",
        ".img",
    }
)

MACRO_OFFICE_EXTENSIONS = frozenset(
    {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".xlam",
        ".pptm",
        ".potm",
        ".ppam",
        ".ppsm",
    }
)

ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar", ".gz", ".bz2", ".7z", ".rar"})


# ---------------------------------------------------------------------------
# Magic Byte Signatures
# ---------------------------------------------------------------------------


def detect_file_signature(data: bytes) -> str:
    """Identify true file type from magic bytes in header."""
    if len(data) == 0:
        return "EMPTY_FILE"

    # Windows PE executable (MZ header + PE signature check)
    if data.startswith(b"MZ"):
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little")
            if 0 < pe_offset < len(data) - 4:
                if data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    return "PE_EXECUTABLE"
        return "DOS_OR_PE_EXECUTABLE"

    # Linux ELF executable
    if data.startswith(b"\x7fELF"):
        return "ELF_EXECUTABLE"

    # Mach-O executable
    if data.startswith(
        (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    ):
        return "MACHO_EXECUTABLE"

    # PDF Document
    if data.startswith(b"%PDF-"):
        return "PDF_DOCUMENT"

    # ZIP / Office OpenXML (docx, xlsx, pptx) / JAR
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP_ARCHIVE"

    # Legacy OLE Compound Document (doc, xls, ppt)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE_COMPOUND_DOCUMENT"

    # Archive signatures
    if data.startswith(b"\x1f\x8b"):
        return "GZIP_ARCHIVE"
    if data.startswith(b"BZh"):
        return "BZIP2_ARCHIVE"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7ZIP_ARCHIVE"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR_ARCHIVE"

    # Images
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG_IMAGE"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG_IMAGE"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF_IMAGE"

    # Script shebang
    if data.startswith(b"#!"):
        return "SHELL_SCRIPT"

    # HTML / XML
    stripped = data.lstrip()
    if stripped.startswith((b"<!DOCTYPE html", b"<html", b"<?xml")):
        return "TEXT_HTML_XML"

    # Plain text check
    try:
        data[:1024].decode("utf-8")
        return "PLAIN_TEXT"
    except UnicodeDecodeError:
        pass

    return "UNKNOWN_BINARY"


@dataclass(frozen=True)
class ArchiveInspectionResult:
    """Safe metadata from read-only archive directory inspection."""

    is_archive: bool = False
    entry_count: int = 0
    total_uncompressed_size: int = 0
    compression_ratio: float = 0.0
    has_nested_executables: bool = False
    has_path_traversal: bool = False
    is_compression_bomb: bool = False
    nested_files: list[str] = field(default_factory=list)
    inspection_error: str | None = None


def inspect_archive_safely(data: bytes) -> ArchiveInspectionResult:
    """Safely inspect a ZIP archive in memory without extracting any file to disk."""
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return ArchiveInspectionResult(is_archive=False)

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            infolist = zf.infolist()
            entry_count = len(infolist)

            if entry_count > MAX_ARCHIVE_ENTRIES:
                return ArchiveInspectionResult(
                    is_archive=True,
                    entry_count=entry_count,
                    is_compression_bomb=True,
                    inspection_error=f"Archive contains {entry_count} entries (limit is {MAX_ARCHIVE_ENTRIES}).",
                )

            total_compressed = sum(info.compress_size for info in infolist)
            total_uncompressed = sum(info.file_size for info in infolist)

            ratio = 1.0
            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed

            is_bomb = (
                total_uncompressed > MAX_UNCOMPRESSED_SIZE_BYTES or ratio > MAX_COMPRESSION_RATIO
            )

            has_exec = False
            has_traversal = False
            nested_names: list[str] = []

            for info in infolist[:MAX_ARCHIVE_ENTRIES]:
                filename = info.filename
                nested_names.append(filename)

                if len(filename) > MAX_ARCHIVE_FILENAME_LEN:
                    is_bomb = True

                # Path traversal attempt check
                if ".." in filename or filename.startswith("/") or "\\" in filename:
                    has_traversal = True

                _, ext = os.path.splitext(filename.lower())
                if ext in EXECUTABLE_EXTENSIONS or ext in MACRO_OFFICE_EXTENSIONS:
                    has_exec = True

            return ArchiveInspectionResult(
                is_archive=True,
                entry_count=entry_count,
                total_uncompressed_size=total_uncompressed,
                compression_ratio=round(ratio, 2),
                has_nested_executables=has_exec,
                has_path_traversal=has_traversal,
                is_compression_bomb=is_bomb,
                nested_files=nested_names[:20],  # cap stored list
            )
    except Exception as exc:
        return ArchiveInspectionResult(
            is_archive=True,
            inspection_error=f"Archive structure unreadable or invalid: {type(exc).__name__}",
        )


@dataclass(frozen=True)
class FileFeatures:
    """Extracted safe static file features."""

    filename: str
    extension: str
    file_size_bytes: int
    sha256: str
    md5: str
    detected_signature: str
    declared_mime_type: str
    inferred_mime_type: str

    is_executable_extension: bool
    is_macro_extension: bool
    is_double_extension: bool
    is_mime_mismatch: bool
    is_hidden_executable: bool

    archive_info: ArchiveInspectionResult

    def to_dict(self) -> dict[str, Any]:
        """Serialize features to dictionary."""
        return {
            "filename": self.filename,
            "extension": self.extension,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "detected_signature": self.detected_signature,
            "declared_mime_type": self.declared_mime_type,
            "inferred_mime_type": self.inferred_mime_type,
            "is_executable_extension": self.is_executable_extension,
            "is_macro_extension": self.is_macro_extension,
            "is_double_extension": self.is_double_extension,
            "is_mime_mismatch": self.is_mime_mismatch,
            "is_hidden_executable": self.is_hidden_executable,
            "archive_entry_count": self.archive_info.entry_count,
            "archive_compression_ratio": self.archive_info.compression_ratio,
            "archive_has_nested_executables": self.archive_info.has_nested_executables,
            "archive_has_path_traversal": self.archive_info.has_path_traversal,
            "archive_is_compression_bomb": self.archive_info.is_compression_bomb,
        }


def extract_file_features(
    file_bytes: bytes,
    filename: str,
    declared_mime: str | None = None,
) -> FileFeatures:
    """Extract deterministic static security features from raw bytes and metadata."""
    # Sanitize filename (remove path components)
    safe_name = os.path.basename(filename.replace("\\", "/"))
    _, ext = os.path.splitext(safe_name.lower())

    file_size = len(file_bytes)
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()

    # Magic byte signature
    detected_sig = detect_file_signature(file_bytes)

    # Inferred MIME type from extension
    inferred_mime, _ = mimetypes.guess_type(safe_name)
    inferred_mime = inferred_mime or "application/octet-stream"
    declared_mime = declared_mime or inferred_mime

    # Double extension check: e.g. "invoice.pdf.exe", "photo.jpg.vbs"
    is_double_ext = False
    parts = safe_name.split(".")
    if len(parts) >= 3:
        penultimate_ext = f".{parts[-2].lower()}"
        last_ext = f".{parts[-1].lower()}"
        if last_ext in EXECUTABLE_EXTENSIONS and penultimate_ext in {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".jpg",
            ".jpeg",
            ".png",
            ".txt",
        }:
            is_double_ext = True

    is_exec_ext = ext in EXECUTABLE_EXTENSIONS
    is_macro_ext = ext in MACRO_OFFICE_EXTENSIONS

    # Hidden executable: extension appears benign (e.g. .pdf, .jpg, .txt),
    # but magic bytes indicate an executable
    is_hidden_exec = False
    if detected_sig in {"PE_EXECUTABLE", "ELF_EXECUTABLE", "MACHO_EXECUTABLE"}:
        if ext not in EXECUTABLE_EXTENSIONS:
            is_hidden_exec = True

    # MIME / signature mismatch check
    is_mismatch = False
    if detected_sig == "PE_EXECUTABLE" and not declared_mime.startswith(
        ("application/x-dosexec", "application/x-msdownload", "application/octet-stream")
    ):
        is_mismatch = True
    elif detected_sig == "PDF_DOCUMENT" and ext not in {".pdf"}:
        is_mismatch = True
    elif detected_sig == "PNG_IMAGE" and ext not in {".png"}:
        is_mismatch = True

    # Archive safety inspection
    archive_info = inspect_archive_safely(file_bytes)

    return FileFeatures(
        filename=safe_name,
        extension=ext,
        file_size_bytes=file_size,
        sha256=sha256_hash,
        md5=md5_hash,
        detected_signature=detected_sig,
        declared_mime_type=declared_mime,
        inferred_mime_type=inferred_mime,
        is_executable_extension=is_exec_ext,
        is_macro_extension=is_macro_ext,
        is_double_extension=is_double_ext,
        is_mime_mismatch=is_mismatch,
        is_hidden_executable=is_hidden_exec,
        archive_info=archive_info,
    )
