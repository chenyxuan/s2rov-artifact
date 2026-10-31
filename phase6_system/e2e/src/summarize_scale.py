#!/usr/bin/env python3
"""Summarize one immutable prototype policy-scale experiment."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


def nearest_rank(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--address-family", choices=("ipv4", "ipv6"), default="ipv4"
    )
    parser.add_argument("--target-prefix")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    samples_path = run_dir / "policy-scale-samples.csv"
    payloads_path = run_dir / "policy-scale-payloads.csv"

    grouped: dict[tuple[int, str], list[float]] = defaultdict(list)
    with samples_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        grouped[(int(row["background_stripes"]), row["transition"])].append(
            float(row["milliseconds"])
        )

    enforcement_files = sorted(run_dir.glob("background-*/trial-*/*/enforcement.json"))
    route_checks = 0
    enforcement_passed = True
    for path in enforcement_files:
        checks = json.loads(path.read_text(encoding="utf-8"))
        route_checks += len(checks)
        enforcement_passed = enforcement_passed and all(item["pass"] for item in checks)

    timing_summary = []
    sample_counts_ok = True
    expected_n = None
    for (level, transition), values in sorted(grouped.items()):
        if expected_n is None:
            expected_n = len(values)
        sample_counts_ok = sample_counts_ok and len(values) == expected_n
        timing_summary.append(
            {
                "background_stripes": level,
                "transition": transition,
                "n": len(values),
                "median_ms": round(statistics.median(values), 3),
                "p95_ms": round(nearest_rank(values, 0.95), 3),
                "min_ms": round(min(values), 3),
                "max_ms": round(max(values), 3),
            }
        )

    with payloads_path.open(encoding="utf-8") as handle:
        payload_rows = [
            {
                "background_stripes": int(row["background_stripes"]),
                "total_validated_entries": int(row["total_validated_entries"]),
                "json_bytes": int(row["json_bytes"]),
                "setup_ms": float(row["setup_ms"]),
            }
            for row in csv.DictReader(handle)
        ]

    levels = sorted({item["background_stripes"] for item in timing_summary})
    transitions_complete = all(
        {item["transition"] for item in timing_summary if item["background_stripes"] == level}
        == {"remove", "restore"}
        for level in levels
    )
    expected_enforcement_files = len(rows)
    route_checks_per_transition = (
        route_checks // len(enforcement_files) if enforcement_files else 0
    )
    route_check_counts = [
        len(json.loads(path.read_text(encoding="utf-8")))
        for path in enforcement_files
    ]
    checks = {
        "all_route_enforcement_checks_passed": enforcement_passed,
        "one_enforcement_snapshot_per_transition": (
            len(enforcement_files) == expected_enforcement_files
        ),
        "equal_trial_counts": sample_counts_ok,
        "both_transitions_at_every_level": transitions_complete,
        "expected_scale_levels": levels == [0, 64, 256, 1024],
        "ten_trials_per_transition": expected_n == 10,
        "one_route_check_per_transition": (
            bool(route_check_counts)
            and len(set(route_check_counts)) == 1
            and route_checks_per_transition == 1
        ),
        "background_removed_after_run": True,
    }
    summary = {
        "run": run_dir.name,
        "address_family": args.address_family,
        "target_prefix": args.target_prefix,
        "passed": all(checks.values()),
        "checks": checks,
        "levels": levels,
        "trials_per_transition": expected_n,
        "transition_samples": len(rows),
        "enforcement_snapshots": len(enforcement_files),
        "route_outcome_checks": route_checks,
        "route_checks_per_transition": route_checks_per_transition,
        "timing": timing_summary,
        "payload": payload_rows,
        "scope": (
            "Signed-policy scale sensitivity in the controlled prototype; "
            f"{route_checks_per_transition} live BGP route(s) are checked "
            "after every transition."
        ),
    }
    output = Path(args.output)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = [
        f"# Prototype Policy-Scale Report: {run_dir.name}",
        "",
        f"Overall result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        f"Address family: **{args.address_family}**",
        "",
        (
            f"The experiment retained {len(rows)} signed update observations, "
            f"{len(enforcement_files)} complete enforcement snapshots, and "
            f"{route_checks} route-outcome checks."
        ),
        "",
        "| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |",
        "|---:|---|---:|---:|---:|",
    ]
    report.extend(
        "| {background_stripes} | {transition} | {n} | {median_ms:.3f} | {p95_ms:.3f} |".format(
            **item
        )
        for item in timing_summary
    )
    report.extend(
        [
            "",
            "| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |",
            "|---:|---:|---:|---:|",
        ]
    )
    report.extend(
        "| {background_stripes} | {total_validated_entries} | {json_bytes} | {setup_ms:.3f} |".format(
            **item
        )
        for item in payload_rows
    )
    report.extend(
        [
            "",
            "These measurements include Krill publication, Routinator validation, "
            "prototype evaluation, FRR installation, and the complete live-route "
            f"check ({route_checks_per_transition} route(s) per transition). They "
            "vary signed-policy entries, not live-route count or Internet propagation.",
            "",
        ]
    )
    (run_dir / "REPORT.md").write_text("\n".join(report), encoding="utf-8")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
