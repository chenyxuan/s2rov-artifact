#!/usr/bin/env python3
"""Independently audit one dual-stack policy-scale run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


LEVELS = (0, 64, 256, 1024)
TRANSITIONS = ("remove", "restore")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--address-family", choices=("ipv4", "ipv6"), required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    samples_path = run_dir / "policy-scale-samples.csv"
    payloads_path = run_dir / "policy-scale-payloads.csv"
    summary_path = run_dir / "summary.json"
    with samples_path.open(newline="", encoding="utf-8") as handle:
        sample_rows = list(csv.DictReader(handle))
    with payloads_path.open(newline="", encoding="utf-8") as handle:
        payload_rows = list(csv.DictReader(handle))
    summary = load_json(summary_path)

    expected_cells = {
        (level, transition) for level in LEVELS for transition in TRANSITIONS
    }
    grouped: dict[tuple[int, str], list[float]] = defaultdict(list)
    trial_matrix: Counter[tuple[int, str, int]] = Counter()
    finite_positive = True
    for row in sample_rows:
        key = (int(row["background_stripes"]), str(row["transition"]))
        value = float(row["milliseconds"])
        grouped[key].append(value)
        trial_matrix[(key[0], key[1], int(row["trial"]))] += 1
        finite_positive = finite_positive and math.isfinite(value) and value > 0.0

    enforcement_files = sorted(
        run_dir.glob("background-*/trial-*/*/enforcement.json")
    )
    route_checks = []
    for path in enforcement_files:
        payload = load_json(path)
        if not isinstance(payload, list):
            payload = []
        route_checks.append(payload)

    timing = {
        (int(item["background_stripes"]), str(item["transition"])): item
        for item in summary.get("timing", [])
    }
    medians_match = set(timing) == expected_cells
    if medians_match:
        for key, values in grouped.items():
            medians_match = medians_match and math.isclose(
                float(timing[key]["median_ms"]),
                statistics.median(values),
                rel_tol=0.0,
                abs_tol=0.001,
            )

    payload_levels = [int(row["background_stripes"]) for row in payload_rows]
    checks = {
        "address_family_matches": summary.get("address_family") == args.address_family,
        "exact_80_sample_matrix": (
            len(sample_rows) == 80
            and set(grouped) == expected_cells
            and all(len(values) == 10 for values in grouped.values())
            and len(trial_matrix) == 80
            and all(count == 1 for count in trial_matrix.values())
        ),
        "durations_are_finite_and_positive": finite_positive,
        "payload_levels_are_complete": payload_levels == list(LEVELS),
        "one_enforcement_snapshot_per_sample": len(enforcement_files) == 80,
        "one_route_check_per_transition": (
            bool(route_checks)
            and len({len(items) for items in route_checks}) == 1
            and len(route_checks[0]) == 1
        ),
        "all_route_checks_pass": all(
            item.get("pass") is True for items in route_checks for item in items
        ),
        "raw_medians_match_summary": medians_match,
        "summary_counts_match_raw": (
            int(summary.get("transition_samples", -1)) == len(sample_rows)
            and int(summary.get("enforcement_snapshots", -1))
            == len(enforcement_files)
            and int(summary.get("route_outcome_checks", -1))
            == sum(len(items) for items in route_checks)
        ),
        "summary_passed": summary.get("passed") is True,
    }
    output = {
        "schema_version": "dual-stack-policy-scale-audit-v1",
        "run": run_dir.name,
        "address_family": args.address_family,
        "passed": all(checks.values()),
        "checks": checks,
        "counts": {
            "samples": len(sample_rows),
            "payload_levels": len(payload_rows),
            "enforcement_snapshots": len(enforcement_files),
            "route_outcome_checks": sum(len(items) for items in route_checks),
        },
        "sha256": {
            "policy-scale-samples.csv": sha256(samples_path),
            "policy-scale-payloads.csv": sha256(payloads_path),
            "summary.json": sha256(summary_path),
        },
    }
    Path(args.output).write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
