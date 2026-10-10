"""Tests for url_dataset — preprocessing, validation, deduplication, splitting.

Verifies:
- Valid CSV loads correctly
- Missing url/label columns raise DatasetValidationError
- Invalid labels (non 0/1) are dropped with warning
- Exact duplicate rows (same url, same label) are collapsed
- Conflicting label rows (same url, different labels) are dropped
- Train/val/test split is stratified and non-overlapping
- Split is deterministic with same seed
- Empty URL rows are dropped
- Missing file raises FileNotFoundError
"""

from __future__ import annotations

import csv
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.preprocessing.url_dataset import (  # noqa: E402
    DatasetSplit,
    DatasetValidationError,
    load_and_split,
    load_dataset,
    split_dataset,
)

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(rows: list[list[str]], tmp_dir: str, filename: str = "test.csv") -> str:
    """Write a CSV to a temp directory and return path."""
    path = os.path.join(tmp_dir, filename)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)
    return path


def _make_balanced_dataset(n: int = 100) -> list[list[str]]:
    """Create a simple balanced dataset header + rows."""
    rows: list[list[str]] = [["url", "label"]]
    for i in range(n // 2):
        rows.append([f"https://benign-{i}.com/", "0"])
    for i in range(n // 2):
        rows.append([f"http://192.168.1.{i % 254 + 1}/login", "1"])
    return rows


# ---------------------------------------------------------------------------
# Loading tests
# ---------------------------------------------------------------------------


class TestLoadDataset:
    def test_valid_dataset_loads(self, tmp_path: object) -> None:
        rows = _make_balanced_dataset(40)
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        assert len(result) > 0

    def test_returns_list_of_tuples(self, tmp_path: object) -> None:
        rows = _make_balanced_dataset(10)
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        for url, label in result:
            assert isinstance(url, str)
            assert label in (0, 1)

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_dataset("/does/not/exist/dataset.csv")

    def test_missing_url_column_raises(self, tmp_path: object) -> None:
        rows = [["link", "label"], ["https://example.com/", "0"]]
        path = _write_csv(rows, str(tmp_path))
        with pytest.raises(DatasetValidationError, match="url"):
            load_dataset(path)

    def test_missing_label_column_raises(self, tmp_path: object) -> None:
        rows = [["url", "class"], ["https://example.com/", "0"]]
        path = _write_csv(rows, str(tmp_path))
        with pytest.raises(DatasetValidationError, match="label"):
            load_dataset(path)

    def test_empty_url_rows_skipped(self, tmp_path: object) -> None:
        rows = [
            ["url", "label"],
            ["", "0"],          # empty url
            ["https://example.com/", "0"],
            ["http://192.168.1.1/login", "1"],
        ]
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        # Empty URL row must not appear in result
        assert all(url for url, _ in result)

    def test_invalid_label_rows_skipped(self, tmp_path: object) -> None:
        rows = [
            ["url", "label"],
            ["https://example.com/", "0"],
            ["https://evil.xyz/login", "2"],    # invalid
            ["https://another.com/", "bad"],    # invalid
            ["http://192.168.1.1/", "1"],
        ]
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        urls = [u for u, _ in result]
        assert "https://evil.xyz/login" not in urls
        assert "https://another.com/" not in urls

    def test_exact_duplicate_rows_collapsed(self, tmp_path: object) -> None:
        rows = [
            ["url", "label"],
            ["https://example.com/", "0"],
            ["https://example.com/", "0"],  # exact duplicate
            ["http://192.168.1.1/login", "1"],
        ]
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        urls = [u for u, _ in result]
        # Should only appear once
        assert urls.count("https://example.com/") <= 1

    def test_conflicting_label_urls_dropped(self, tmp_path: object) -> None:
        rows = [
            ["url", "label"],
            ["https://example.com/", "0"],
            ["https://example.com/", "1"],  # conflict!
            ["https://safe.org/", "0"],
            ["http://192.168.1.1/login", "1"],
        ]
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        urls = [u for u, _ in result]
        assert "https://example.com/" not in urls

    def test_only_one_class_raises(self, tmp_path: object) -> None:
        rows = [
            ["url", "label"],
            ["https://example.com/", "0"],
            ["https://another.com/", "0"],
        ]
        path = _write_csv(rows, str(tmp_path))
        with pytest.raises(DatasetValidationError, match="one class"):
            load_dataset(path)

    def test_extra_columns_preserved(self, tmp_path: object) -> None:
        """Extra columns (source, date) are ignored without error."""
        rows = [
            ["url", "label", "source", "date"],
            ["https://example.com/", "0", "alexa", "2024-01"],
            ["http://192.168.1.1/login", "1", "phishtank", "2024-01"],
        ]
        path = _write_csv(rows, str(tmp_path))
        result = load_dataset(path)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Split tests
# ---------------------------------------------------------------------------


class TestSplitDataset:
    def _make_rows(self, n: int = 200) -> list[tuple[str, int]]:
        rows: list[tuple[str, int]] = []
        for i in range(n // 2):
            rows.append((f"https://benign-{i}.com/", 0))
        for i in range(n // 2):
            rows.append((f"http://192.168.1.{i % 254 + 1}/login", 1))
        return rows

    def test_split_sizes_sum_to_total(self) -> None:
        rows = self._make_rows(200)
        split = split_dataset(rows, seed=42)
        assert split.total_size == len(rows)

    def test_train_is_roughly_70_percent(self) -> None:
        rows = self._make_rows(200)
        split = split_dataset(rows, seed=42)
        assert 0.65 <= split.train_size / split.total_size <= 0.75

    def test_val_and_test_are_roughly_15_each(self) -> None:
        rows = self._make_rows(200)
        split = split_dataset(rows, seed=42)
        assert 0.10 <= split.val_size / split.total_size <= 0.20
        assert 0.10 <= split.test_size / split.total_size <= 0.20

    def test_no_overlap_between_train_val_test(self) -> None:
        rows = self._make_rows(200)
        split = split_dataset(rows, seed=42)
        train_urls = {u for u, _ in split.train}
        val_urls = {u for u, _ in split.val}
        test_urls = {u for u, _ in split.test}
        assert not train_urls & val_urls, "Train / val overlap"
        assert not train_urls & test_urls, "Train / test overlap"
        assert not val_urls & test_urls, "Val / test overlap"

    def test_deterministic_same_seed(self) -> None:
        rows = self._make_rows(200)
        split_a = split_dataset(rows, seed=42)
        split_b = split_dataset(rows, seed=42)
        assert [u for u, _ in split_a.train] == [u for u, _ in split_b.train]
        assert [u for u, _ in split_a.test] == [u for u, _ in split_b.test]

    def test_different_seed_different_split(self) -> None:
        rows = self._make_rows(200)
        split_a = split_dataset(rows, seed=42)
        split_b = split_dataset(rows, seed=99)
        # With high probability, different seeds give different splits
        assert [u for u, _ in split_a.train] != [u for u, _ in split_b.train]

    def test_both_classes_in_all_splits(self) -> None:
        rows = self._make_rows(200)
        split = split_dataset(rows, seed=42)
        for partition_name, partition in [
            ("train", split.train), ("val", split.val), ("test", split.test),
        ]:
            labels = {label for _, label in partition}
            assert labels == {0, 1}, f"Split '{partition_name}' missing a class"

    def test_dataset_split_properties(self) -> None:
        rows = self._make_rows(100)
        split = split_dataset(rows, seed=42)
        assert split.train_size == len(split.train)
        assert split.val_size == len(split.val)
        assert split.test_size == len(split.test)
        assert split.total_size == split.train_size + split.val_size + split.test_size


class TestLoadAndSplit:
    def test_load_and_split_fixture(self) -> None:
        fixture_path = os.path.join(
            _PROJECT_ROOT, "ml", "datasets", "fixtures", "sample_urls.csv"
        )
        if not os.path.exists(fixture_path):
            pytest.skip("Fixture dataset not available")
        split = load_and_split(fixture_path, seed=42)
        assert isinstance(split, DatasetSplit)
        assert split.total_size > 0
        assert split.train_size > split.val_size
