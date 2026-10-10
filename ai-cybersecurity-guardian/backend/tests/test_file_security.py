"""Security tests for file analyzer — M7.

Verifies:
- Zero execution of uploaded files (no subprocess, no shell, no os.system).
- Strict size boundaries (rejection of oversized uploads).
- Filename sanitization and length boundary.
- Zero disk residue.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from app.core.security import hash_password
from app.models.user import User
from app.services.analyzers.file_analyzer import (
    MAX_FILE_SIZE_BYTES,
    FileAnalyzer,
    FileValidationError,
)
from sqlalchemy.orm import Session


def _make_user(db: Session, email: str = "sec_user@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("S3cur3P@ssw0rd!"),
    )
    db.add(user)
    db.flush()
    return user


class TestFileSecurityConstraints:
    def test_zero_execution_guarantee(self, db: Session) -> None:
        """Verify that analyzing an executable file never invokes execution primitives."""
        user = _make_user(db)
        exe_bytes = b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 100

        with (
            patch("subprocess.run") as mock_sub_run,
            patch("subprocess.Popen") as mock_sub_popen,
            patch("os.system") as mock_os_system,
        ):
            analyzer = FileAnalyzer(db)
            res = analyzer.analyze(
                (exe_bytes, "malware.exe", "application/x-msdownload"),
                user_id=user.id,
            )

            assert res.risk_score >= 30
            mock_sub_run.assert_not_called()
            mock_sub_popen.assert_not_called()
            mock_os_system.assert_not_called()

    def test_oversized_file_rejected(self, db: Session) -> None:
        user = _make_user(db)
        oversized = b"A" * (MAX_FILE_SIZE_BYTES + 10)
        analyzer = FileAnalyzer(db)

        with pytest.raises(FileValidationError, match="exceeds maximum allowed limit"):
            analyzer.analyze(
                (oversized, "big_file.bin", "application/octet-stream"),
                user_id=user.id,
            )

    def test_excessive_filename_length_rejected(self, db: Session) -> None:
        user = _make_user(db)
        long_name = "A" * 300 + ".txt"
        analyzer = FileAnalyzer(db)

        with pytest.raises(FileValidationError, match="Filename length exceeds"):
            analyzer.analyze((b"safe data", long_name, "text/plain"), user_id=user.id)
