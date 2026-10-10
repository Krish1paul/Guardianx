"""URL dataset loading, validation and splitting — M3.

This module is the single entry-point for dataset ingestion.

Responsibilities
----------------
1. Load a CSV dataset.
2. Validate required columns (``url``, ``label``).
3. Validate labels (must be 0 or 1).
4. Normalise URLs using the M2 ``normalize_url()`` utility so deduplication
   is consistent with production inference.
5. Drop rows with invalid/missing values (logged at WARNING level).
6. Detect and drop rows with conflicting labels for the same normalized URL
   (same URL → two different labels).
7. Detect and collapse exact-duplicate rows (same URL, same label → keep one).
8. Produce a stratified 70 / 15 / 15 train / validation / test split.
9. Return typed ``DatasetSplit`` containing lists of ``(normalized_url, label)``
   tuples, ready to pass into the feature pipeline.

Data leakage prevention
-----------------------
Deduplication and conflict removal happen on the *normalized* URL **before**
splitting.  This ensures that the same URL cannot appear in both train and test
sets under different normalizations.

Splitting uses ``sklearn.model_selection.train_test_split`` with
``stratify=y``, ``random_state=SEED`` so results are deterministic.

No network requests are made — URL normalization is a pure string transform.

Split strategy
--------------
    train : 70 %
    val   : 15 %
    test  : 15 %

These ratios are controlled by ``TRAIN_RATIO`` / ``VAL_RATIO`` constants.
"""

from __future__ import annotations

import csv
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Make the ``ml`` package importable when run from the project root.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from app.core.url_utils import normalize_url  # noqa: E402 — project-root import

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Deterministic random seed for all splits.
SEED: int = 42

#: Fraction used for training.
TRAIN_RATIO: float = 0.70

#: Fraction used for validation (of the 30 % remainder, 50 % → val, 50 % → test).
VAL_RATIO: float = 0.50  # of the 30 % remainder → 15 % total

REQUIRED_COLUMNS: frozenset[str] = frozenset({"url", "label"})
VALID_LABELS: frozenset[int] = frozenset({0, 1})


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


@dataclass
class DatasetSplit:
    """Stratified train / validation / test split.

    Each partition is a list of ``(normalized_url, label)`` tuples.
    Labels are integers (0 = benign, 1 = malicious).
    """

    train: list[tuple[str, int]]
    val: list[tuple[str, int]]
    test: list[tuple[str, int]]

    @property
    def train_size(self) -> int:
        return len(self.train)

    @property
    def val_size(self) -> int:
        return len(self.val)

    @property
    def test_size(self) -> int:
        return len(self.test)

    @property
    def total_size(self) -> int:
        return self.train_size + self.val_size + self.test_size


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class DatasetValidationError(ValueError):
    """Raised when a dataset fails structural validation."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def load_dataset(path: str) -> list[tuple[str, int]]:
    """Load and validate a CSV dataset.

    Parameters
    ----------
    path:
        Absolute or relative filesystem path to the CSV file.

    Returns
    -------
    list[tuple[str, int]]:
        Clean list of ``(normalized_url, label)`` tuples after:
        - Row-level validation
        - URL normalization
        - Deduplication
        - Conflict removal

    Raises
    ------
    DatasetValidationError:
        If the file cannot be read, is missing required columns, or has no
        usable rows after cleaning.
    FileNotFoundError:
        If ``path`` does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")

    logger.info("Loading dataset from %s", path)

    raw_rows: list[dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise DatasetValidationError("Dataset CSV has no header row.")
        field_set = {name.strip().lower() for name in reader.fieldnames}
        missing = REQUIRED_COLUMNS - field_set
        if missing:
            raise DatasetValidationError(
                f"Dataset is missing required columns: {missing}. "
                f"Found: {sorted(field_set)}"
            )
        for i, row in enumerate(reader, start=2):  # start=2: row 1 is header
            raw_rows.append({"_line": i, **row})

    logger.info("Loaded %d raw rows", len(raw_rows))

    # ------------------------------------------------------------------
    # Row-level validation and normalization
    # ------------------------------------------------------------------
    valid_rows: list[tuple[str, int]] = []
    skip_count = 0

    for row in raw_rows:
        line = row["_line"]

        # --- URL ---
        raw_url = (row.get("url") or "").strip()
        if not raw_url:
            logger.warning("Line %d: empty URL — skipped", line)
            skip_count += 1
            continue

        # Normalize the URL so deduplication is canonical
        try:
            norm_url = normalize_url(raw_url)
        except Exception:
            # Malformed URL that can't be normalized — skip
            logger.warning("Line %d: URL cannot be normalized (%r) — skipped", line, raw_url[:80])
            skip_count += 1
            continue

        # --- Label ---
        raw_label = (str(row.get("label") or "")).strip()
        try:
            label = int(raw_label)
        except (ValueError, TypeError):
            logger.warning("Line %d: non-integer label %r — skipped", line, raw_label)
            skip_count += 1
            continue

        if label not in VALID_LABELS:
            logger.warning("Line %d: invalid label %d (must be 0 or 1) — skipped", line, label)
            skip_count += 1
            continue

        valid_rows.append((norm_url, label))

    logger.info(
        "After validation: %d valid rows, %d skipped",
        len(valid_rows),
        skip_count,
    )

    # ------------------------------------------------------------------
    # Deduplication and conflict detection
    # ------------------------------------------------------------------
    url_labels: dict[str, set[int]] = {}
    for url, label in valid_rows:
        url_labels.setdefault(url, set()).add(label)

    conflict_urls = {u for u, lbls in url_labels.items() if len(lbls) > 1}
    if conflict_urls:
        logger.warning(
            "%d URLs have conflicting labels and will be dropped: %s",
            len(conflict_urls),
            list(conflict_urls)[:5],
        )

    # Build deduplicated list: keep first occurrence, skip conflicts.
    seen: set[str] = set()
    deduped: list[tuple[str, int]] = []
    for url, label in valid_rows:
        if url in conflict_urls:
            continue  # drop conflicting URL
        if url in seen:
            continue  # drop duplicate (same url, same label — already have it)
        seen.add(url)
        deduped.append((url, label))

    n_conflicts = len(conflict_urls)
    n_exact_dups = len(valid_rows) - len(deduped) - n_conflicts
    logger.info(
        "After dedup: %d rows (removed %d exact duplicates, %d conflict URLs)",
        len(deduped),
        n_exact_dups,
        n_conflicts,
    )

    if not deduped:
        raise DatasetValidationError("No usable rows remain after validation and deduplication.")

    # Verify we have at least two classes (required for stratification)
    labels_present = {label for _, label in deduped}
    if len(labels_present) < 2:
        raise DatasetValidationError(
            f"Dataset has only one class present: {labels_present}. "
            "Both 0 (benign) and 1 (malicious) are required."
        )

    return deduped


def split_dataset(
    rows: list[tuple[str, int]],
    seed: int = SEED,
) -> DatasetSplit:
    """Split a clean dataset into train / validation / test partitions.

    Parameters
    ----------
    rows:
        Clean list of ``(normalized_url, label)`` tuples from ``load_dataset()``.
    seed:
        Random seed for reproducibility.

    Returns
    -------
    DatasetSplit:
        Stratified 70 / 15 / 15 split.

    Notes
    -----
    Stratification preserves class ratios across all three splits.
    The split is deterministic for a given ``seed`` and dataset order.
    """
    from sklearn.model_selection import train_test_split  # lazy import

    urls = [r[0] for r in rows]
    labels = [r[1] for r in rows]

    # Step 1: split 70 % train / 30 % remaining
    train_urls, temp_urls, train_labels, temp_labels = train_test_split(
        urls, labels,
        test_size=1.0 - TRAIN_RATIO,
        stratify=labels,
        random_state=seed,
    )

    # Step 2: split remaining 30 % into 15 % val / 15 % test (50-50 split)
    val_urls, test_urls, val_labels, test_labels = train_test_split(
        temp_urls, temp_labels,
        test_size=VAL_RATIO,
        stratify=temp_labels,
        random_state=seed,
    )

    train = list(zip(train_urls, train_labels))
    val = list(zip(val_urls, val_labels))
    test = list(zip(test_urls, test_labels))

    logger.info(
        "Split: train=%d, val=%d, test=%d (total=%d)",
        len(train), len(val), len(test), len(rows),
    )
    return DatasetSplit(train=train, val=val, test=test)


def load_and_split(path: str, seed: int = SEED) -> DatasetSplit:
    """Convenience function: load + validate + split in one call.

    Parameters
    ----------
    path:
        Path to the CSV dataset file.
    seed:
        Random seed for reproducibility.

    Returns
    -------
    DatasetSplit:
        Stratified 70 / 15 / 15 split.
    """
    rows = load_dataset(path)
    return split_dataset(rows, seed=seed)
