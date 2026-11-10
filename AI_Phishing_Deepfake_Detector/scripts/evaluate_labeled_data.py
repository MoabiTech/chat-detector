"""Compute dataset-level binary metrics without retaining sample contents."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Iterable
from pathlib import Path

_LABELS = {
    "1": "phishing",
    "positive": "phishing",
    "phishing": "phishing",
    "0": "benign",
    "negative": "benign",
    "benign": "benign",
}


def normalize_label(value: str, row_number: int, column: str) -> str:
    normalized = value.strip().lower()
    if normalized not in _LABELS:
        raise ValueError(
            f"CSV row {row_number}: {column} must be phishing/benign or 1/0."
        )
    return _LABELS[normalized]


def evaluate_rows(rows: Iterable[dict[str, str]]) -> dict:
    """Return confusion counts and standard metrics; never return sample data."""
    confusion = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    record_count = 0
    for row_number, row in enumerate(rows, start=2):
        record_count += 1
        truth = normalize_label(row.get("label", ""), row_number, "label")
        prediction = normalize_label(row.get("prediction", ""), row_number, "prediction")
        if truth == "phishing" and prediction == "phishing":
            confusion["tp"] += 1
        elif truth == "benign" and prediction == "benign":
            confusion["tn"] += 1
        elif truth == "benign":
            confusion["fp"] += 1
        else:
            confusion["fn"] += 1

    if not record_count:
        raise ValueError("The labeled dataset contains no records.")
    total = record_count
    precision_denominator = confusion["tp"] + confusion["fp"]
    recall_denominator = confusion["tp"] + confusion["fn"]
    precision = confusion["tp"] / precision_denominator if precision_denominator else 0.0
    recall = confusion["tp"] / recall_denominator if recall_denominator else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "records": total,
        "confusion": confusion,
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "accuracy": round((confusion["tp"] + confusion["tn"]) / total, 6),
        },
        "limitations": (
            "Metrics describe only the supplied labeled split. This harness does not "
            "assess calibration, dataset representativeness, or forensic validity."
        ),
    }


def evaluate_csv(path: Path, dataset: str, license_name: str, split: str) -> dict:
    if not dataset.strip() or not license_name.strip() or not split.strip():
        raise ValueError("Dataset name, license, and split description are required.")
    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames or not {"label", "prediction"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain 'label' and 'prediction' columns.")
        result = evaluate_rows(reader)
    result["dataset"] = dataset.strip()
    result["license"] = license_name.strip()
    result["split"] = split.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--dataset", required=True, help="Dataset name or controlled-sample identifier.")
    parser.add_argument("--license", required=True, dest="license_name", help="Dataset license or authorization basis.")
    parser.add_argument("--split", required=True, help="Exact split description, e.g. held-out test.")
    args = parser.parse_args(argv)
    try:
        result = evaluate_csv(args.csv_path, args.dataset, args.license_name, args.split)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
