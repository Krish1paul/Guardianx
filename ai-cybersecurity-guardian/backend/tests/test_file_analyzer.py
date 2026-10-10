"""Unit and integration tests for safe static file analyzer — M7."""

from __future__ import annotations

import uuid

from app.core.security import hash_password
from app.models.file_scan import FileScan
from app.models.user import User
from app.schemas.url_analysis import RiskClassification
from app.services.analyzers.file_analyzer import FileAnalyzer
from ml.features.file_features import extract_file_features
from sqlalchemy.orm import Session


def _make_user(db: Session, email: str = "file_user@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("S3cur3P@ssw0rd!"),
    )
    db.add(user)
    db.flush()
    return user


class TestFileFeatureExtraction:
    def test_detect_pe_executable(self) -> None:
        data = bytearray(b"MZ" + b"\x00" * 58)
        data.extend((0x40).to_bytes(4, byteorder="little"))
        data.extend(b"PE\x00\x00" + b"\x00" * 20)

        features = extract_file_features(bytes(data), "malware.exe")
        assert features.detected_signature == "PE_EXECUTABLE"
        assert features.is_executable_extension is True
        assert features.is_hidden_executable is False

    def test_detect_disguised_executable(self) -> None:
        data = bytearray(b"MZ" + b"\x00" * 58)
        data.extend((0x40).to_bytes(4, byteorder="little"))
        data.extend(b"PE\x00\x00" + b"\x00" * 20)

        features = extract_file_features(bytes(data), "invoice.pdf")
        assert features.detected_signature == "PE_EXECUTABLE"
        assert features.extension == ".pdf"
        assert features.is_hidden_executable is True

    def test_detect_double_extension(self) -> None:
        data = b"Plain text content inside disguised script"
        features = extract_file_features(data, "statement.pdf.exe")
        assert features.is_double_extension is True
        assert features.is_executable_extension is True

    def test_detect_elf_executable(self) -> None:
        data = b"\x7fELF" + b"\x01\x01\x01\x00" + b"\x00" * 16
        features = extract_file_features(data, "payload.bin")
        assert features.detected_signature == "ELF_EXECUTABLE"
        assert features.is_hidden_executable is True

    def test_detect_macro_extension(self) -> None:
        data = b"Dummy docm content"
        features = extract_file_features(data, "resume.docm")
        assert features.is_macro_extension is True

    def test_benign_pdf(self) -> None:
        data = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        features = extract_file_features(data, "annual_report.pdf", declared_mime="application/pdf")
        assert features.detected_signature == "PDF_DOCUMENT"
        assert features.is_hidden_executable is False
        assert features.is_mime_mismatch is False


class TestFileAnalyzerService:
    def test_analyze_malicious_double_extension(self, db: Session) -> None:
        user = _make_user(db, "file_tester@example.com")
        data = b"Malicious batch payload"
        analyzer = FileAnalyzer(db)
        res = analyzer.analyze(
            (data, "invoice.pdf.vbs", "application/octet-stream"),
            user_id=user.id,
        )

        assert res.risk_score >= 60
        assert res.classification in {RiskClassification.HIGH_RISK, RiskClassification.CRITICAL}
        assert any(r.title == "Suspicious Double File Extension" for r in res.reasons)

        # Verify DB persistence and privacy
        record = db.get(FileScan, res.id)
        assert record is not None
        assert record.file_hash == res.file_hash
        assert record.user_id == user.id
        assert not hasattr(record, "content")

    def test_analyze_benign_text_file(self, db: Session) -> None:
        user = _make_user(db, "clean_file_user@example.com")
        data = b"Hello, this is a clean and harmless text document for testing purposes."
        analyzer = FileAnalyzer(db)
        res = analyzer.analyze((data, "notes.txt", "text/plain"), user_id=user.id)

        assert res.risk_score < 30
        assert res.classification == RiskClassification.LOW_RISK
        assert res.detected_type == "PLAIN_TEXT"

    def test_file_tenant_isolation(self, db: Session) -> None:
        user1 = _make_user(db, "file_u1@example.com")
        user2 = _make_user(db, "file_u2@example.com")

        analyzer = FileAnalyzer(db)
        res1 = analyzer.analyze((b"content 1", "file1.txt", "text/plain"), user_id=user1.id)
        res2 = analyzer.analyze((b"content 2", "file2.txt", "text/plain"), user_id=user2.id)

        u1_scans = db.query(FileScan).filter(FileScan.user_id == user1.id).all()
        assert len(u1_scans) == 1
        assert u1_scans[0].id == res1.id

        u2_scans = db.query(FileScan).filter(FileScan.user_id == user2.id).all()
        assert len(u2_scans) == 1
        assert u2_scans[0].id == res2.id
