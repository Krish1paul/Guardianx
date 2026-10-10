"""Safe Static File Threat Analyzer — M7.

Safely evaluates uploaded files without execution:
- Zero execution, zero subprocesses, zero shell commands, zero network requests.
- Enforces strict size, filename length, and archive limits.
- Magic byte identification and MIME/signature mismatch detection.
- Double extension and disguised executable detection.
- Archive safety analysis (zip bomb prevention, path traversal check, nested executable check).
- Privacy: raw file content is never stored permanently; only SHA-256 digest and
  metadata are persisted.
"""

from __future__ import annotations

import os
import uuid

from ml.features.file_features import FileFeatures, extract_file_features
from sqlalchemy.orm import Session

from app.models.file_scan import FileScan
from app.schemas.unified_analysis import (
    ExplainableReason,
    FileScanResponse,
    ThreatCategory,
)
from app.schemas.url_analysis import Severity
from app.services.analyzers.base import BaseAnalyzer, NormalizedAnalysisResult
from app.services.analyzers.unified_risk_engine import (
    UnifiedRiskEngine,
    clamp_score,
    score_to_classification,
)

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_FILENAME_LEN = 255


class FileValidationError(ValueError):
    """Raised when an uploaded file violates safety or size limits."""


class FileAnalyzer(BaseAnalyzer[tuple[bytes, str, str | None], FileScanResponse]):
    """Safe static file threat analyzer."""

    def __init__(self, db: Session) -> None:
        self.db = db

    @property
    def analyzer_type(self) -> str:
        return "file"

    @property
    def analyzer_version(self) -> str:
        return "file-v1"

    def analyze(
        self,
        input_data: tuple[bytes, str, str | None],
        user_id: uuid.UUID,
    ) -> FileScanResponse:
        """Execute safe static file inspection and persist scan record.

        Parameters
        ----------
        input_data:
            Tuple of (file_bytes, filename, declared_mime_type).
        user_id:
            Authenticated user ID.
        """
        file_bytes, raw_filename, declared_mime = input_data

        # 1. Strict input safety limits
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            max_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
            raise FileValidationError(f"File size exceeds maximum allowed limit of {max_mb} MB.")

        if len(raw_filename) > MAX_FILENAME_LEN:
            raise FileValidationError(
                f"Filename length exceeds maximum limit of {MAX_FILENAME_LEN} characters."
            )

        # Sanitize filename (strip directory components)
        clean_filename = os.path.basename(raw_filename.replace("\\", "/")) or "unnamed_file"

        # 2. Extract static features
        features: FileFeatures = extract_file_features(
            file_bytes=file_bytes,
            filename=clean_filename,
            declared_mime=declared_mime,
        )

        # 3. Rule-based static scoring & reason generation
        reasons: list[ExplainableReason] = []
        rule_score = 0

        # Hidden executable disguise (e.g. extension says .pdf or .jpg, but bytes are PE/ELF)
        if features.is_hidden_executable:
            contrib = 50
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.MALICIOUS_SIGNATURE,
                    severity=Severity.CRITICAL,
                    title="Disguised Executable Binary",
                    explanation=(
                        f"File possesses a benign extension ('{features.extension}'), "
                        f"but underlying magic bytes match an executable binary "
                        f"({features.detected_signature})."
                    ),
                    score_contribution=contrib,
                )
            )

        # Double extension attack (e.g. invoice.pdf.exe)
        if features.is_double_extension:
            contrib = 35
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.FILE_ANOMALY,
                    severity=Severity.HIGH,
                    title="Suspicious Double File Extension",
                    explanation=(
                        f"Filename '{clean_filename}' contains multiple file extensions "
                        "to mask an executable format."
                    ),
                    score_contribution=contrib,
                )
            )

        # Standalone executable file extension
        if features.is_executable_extension and not features.is_hidden_executable:
            contrib = 30
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.FILE_ANOMALY,
                    severity=Severity.HIGH,
                    title="Direct Executable File Extension",
                    explanation=(
                        f"File has an executable program extension ('{features.extension}')."
                    ),
                    score_contribution=contrib,
                )
            )

        # Macro-enabled Office file
        if features.is_macro_extension:
            contrib = 25
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.FILE_ANOMALY,
                    severity=Severity.MEDIUM,
                    title="Macro-Enabled Office Document",
                    explanation=(
                        "Document extension indicates embedded VBA macros capable of "
                        "executing code."
                    ),
                    score_contribution=contrib,
                )
            )

        # MIME vs Signature discrepancy
        if features.is_mime_mismatch and not features.is_hidden_executable:
            contrib = 20
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.METADATA_MISMATCH,
                    severity=Severity.MEDIUM,
                    title="MIME Type Mismatch",
                    explanation=(
                        f"Declared content type ('{features.declared_mime_type}') conflicts with "
                        f"detected binary structure ('{features.detected_signature}')."
                    ),
                    score_contribution=contrib,
                )
            )

        # Archive security indicators
        if features.archive_info.is_archive:
            if features.archive_info.is_compression_bomb:
                contrib = 45
                rule_score += contrib
                ratio = features.archive_info.compression_ratio
                count = features.archive_info.entry_count
                reasons.append(
                    UnifiedRiskEngine.create_reason(
                        category=ThreatCategory.ARCHIVE_RISK,
                        severity=Severity.CRITICAL,
                        title="Compression Bomb / Resource Exhaustion Risk",
                        explanation=(
                            f"Archive exceeds safety parameters (compression ratio: {ratio}:1, "
                            f"entries: {count})."
                        ),
                        score_contribution=contrib,
                    )
                )

            if features.archive_info.has_path_traversal:
                contrib = 40
                rule_score += contrib
                reasons.append(
                    UnifiedRiskEngine.create_reason(
                        category=ThreatCategory.ARCHIVE_RISK,
                        severity=Severity.CRITICAL,
                        title="Archive Path Traversal Indicator",
                        explanation=(
                            "Archive contains path traversal sequences ('../' or absolute roots) "
                            "targeting directory escapes."
                        ),
                        score_contribution=contrib,
                    )
                )

            if features.archive_info.has_nested_executables:
                contrib = 25
                rule_score += contrib
                reasons.append(
                    UnifiedRiskEngine.create_reason(
                        category=ThreatCategory.ARCHIVE_RISK,
                        severity=Severity.HIGH,
                        title="Nested Executable in Archive",
                        explanation=(
                            "Archive packages executable files or macro documents "
                            "inside compressed archive."
                        ),
                        score_contribution=contrib,
                    )
                )

        # 4. Unified score & classification
        final_score = clamp_score(rule_score)
        classification = score_to_classification(final_score)

        # Confidence: static analysis has high confidence in signature and structure rules
        high_sev = sum(1 for r in reasons if r.severity in {Severity.HIGH, Severity.CRITICAL})
        confidence = 0.95 if high_sev > 0 else (0.85 if len(reasons) > 0 else 0.90)

        # 5. Persist to DB (User isolated, never stores raw file content)
        feature_dict = features.to_dict()
        feature_dict["detection_mode"] = "static-analysis"
        feature_dict["ml_analysis"] = None  # ML extension point

        db_reasons = [r.model_dump() for r in reasons]

        scan_record = FileScan(
            user_id=user_id,
            file_hash=features.sha256,
            filename=clean_filename,
            file_size=features.file_size_bytes,
            detected_type=features.detected_signature,
            declared_mime=features.declared_mime_type,
            risk_score=final_score,
            classification=classification.value,
            confidence=confidence,
            features=feature_dict,
            reasons=db_reasons,
            analyzer_version=self.analyzer_version,
        )

        self.db.add(scan_record)
        self.db.commit()
        self.db.refresh(scan_record)

        # Trigger M8 Incident Correlation (fail-safe)
        try:
            from app.services.intelligence.correlation_engine import CorrelationEngine

            CorrelationEngine(self.db).correlate_file_scan(scan_record)
            self.db.commit()
        except Exception:
            pass

        return FileScanResponse(
            id=scan_record.id,
            file_hash=features.sha256,
            filename=clean_filename,
            file_size=features.file_size_bytes,
            detected_type=features.detected_signature,
            declared_mime=features.declared_mime_type,
            risk_score=final_score,
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            features=feature_dict,
            analyzer_version=self.analyzer_version,
            created_at=scan_record.created_at,
        )

    def analyze_normalized(
        self, input_data: tuple[bytes, str, str | None], user_id: uuid.UUID
    ) -> NormalizedAnalysisResult:
        """Execute file analysis returning common normalized result."""
        res = self.analyze(input_data=input_data, user_id=user_id)
        return NormalizedAnalysisResult(
            id=res.id,
            analyzer_type="file",
            risk_score=res.risk_score,
            classification=res.classification,
            confidence=res.confidence,
            reasons=res.reasons,
            extracted_features=res.features,
            analyzer_version=res.analyzer_version,
            created_at=res.created_at,
            processing_metadata={"file_hash": res.file_hash, "file_size": res.file_size},
        )
