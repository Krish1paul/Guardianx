"""Unit tests for safe archive inspection and zip bomb protection — M7."""

from __future__ import annotations

import io
import zipfile

from ml.features.file_features import (
    MAX_ARCHIVE_ENTRIES,
    MAX_COMPRESSION_RATIO,
    inspect_archive_safely,
)


class TestArchiveSafety:
    def test_benign_zip(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("document.txt", "Plain text content")
            zf.writestr("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)

        res = inspect_archive_safely(buf.getvalue())
        assert res.is_archive is True
        assert res.entry_count == 2
        assert res.has_nested_executables is False
        assert res.has_path_traversal is False
        assert res.is_compression_bomb is False

    def test_detect_nested_executable(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("readme.txt", "Read me")
            zf.writestr("setup.exe", b"MZ" + b"\x00" * 50)

        res = inspect_archive_safely(buf.getvalue())
        assert res.is_archive is True
        assert res.has_nested_executables is True

    def test_detect_path_traversal(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:root")

        res = inspect_archive_safely(buf.getvalue())
        assert res.is_archive is True
        assert res.has_path_traversal is True

    def test_max_entries_limit_enforced(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(MAX_ARCHIVE_ENTRIES + 10):
                zf.writestr(f"file_{i}.txt", f"data {i}")

        res = inspect_archive_safely(buf.getvalue())
        assert res.is_archive is True
        assert res.entry_count > MAX_ARCHIVE_ENTRIES
        assert res.is_compression_bomb is True
        assert "limit is" in (res.inspection_error or "")

    def test_compression_bomb_ratio_detected(self) -> None:
        """Simulate a compression bomb with high uncompressed-to-compressed ratio."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1 MB of repeated zeros compresses to < 1 KB, yielding > 1000:1 ratio
            zf.writestr("zeroes.bin", b"\x00" * (1024 * 1024))

        res = inspect_archive_safely(buf.getvalue())
        assert res.is_archive is True
        assert res.compression_ratio > MAX_COMPRESSION_RATIO
        assert res.is_compression_bomb is True
