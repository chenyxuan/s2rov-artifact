#!/usr/bin/env python3
"""Summarize one immutable end-to-end experiment run."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def sample_stats(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    baseline_decisions = read_json(run_dir / "baseline" / "decisions.json")
    baseline_enforcement = read_json(run_dir / "baseline" / "enforcement.json")
    da_decisions = read_json(run_dir / "da" / "decisions.json")
    da_enforcement = read_json(run_dir / "da" / "enforcement.json")
    observed = read_json(run_dir / "da" / "observed-check.json")
    without_closed = read_json(
        run_dir / "updates" / "without-closed-stripe.json"
    )
    restored = read_json(run_dir / "updates" / "restored-decisions.json")
    outage = read_json(
        run_dir / "failures" / "routinator-outage" / "result.json"
    )

    timings = {}
    with (run_dir / "timings.csv").open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            timings[row["metric"]] = float(row["milliseconds"])

    recovery_values = []
    with (run_dir / "recovery-samples.csv").open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            recovery_values.append(float(row["milliseconds"]))

    frr_recovery_values = []
    with (run_dir / "frr-recovery-samples.csv").open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            frr_recovery_values.append(float(row["milliseconds"]))

    remove_values = []
    restore_values = []
    with (run_dir / "override-update-samples.csv").open(
        encoding="utf-8"
    ) as handle:
        for row in csv.DictReader(handle):
            remove_values.append(float(row["remove_ms"]))
            restore_values.append(float(row["restore_ms"]))

    no_closed_customer = next(
        item for item in without_closed if item["name"] == "listed_customer"
    )
    restored_customer = next(
        item for item in restored if item["name"] == "listed_customer"
    )

    checks = {
        "baseline_semantics": all(item["pass"] for item in baseline_decisions),
        "baseline_frr_enforcement": all(
            item["pass"] for item in baseline_enforcement
        ),
        "all_bgp_cases_observed": all(item["observed"] for item in observed),
        "da_semantics": all(item["pass"] for item in da_decisions),
        "da_frr_enforcement": all(item["pass"] for item in da_enforcement),
        "closed_override_removal_to_delegated": (
            no_closed_customer["state"] == "Delegated"
        ),
        "closed_override_restored_to_explicit": (
            restored_customer["state"] == "Explicit"
        ),
        "routinator_outage_policy_retained": bool(outage["policy_retained"]),
    }

    summary = {
        "run": run_dir.name,
        "passed": all(checks.values()),
        "checks": checks,
        "baseline_state_counts": dict(
            Counter(item["state"] for item in baseline_decisions)
        ),
        "da_state_counts": dict(Counter(item["state"] for item in da_decisions)),
        "timings_ms": timings,
        "recovery_timing": sample_stats(recovery_values),
        "frr_recovery_timing": sample_stats(frr_recovery_values),
        "override_remove_timing": sample_stats(remove_values),
        "override_restore_timing": sample_stats(restore_values),
        "routinator_outage": outage,
        "security_boundary": {
            "aggregate_attacker": next(
                item["state"]
                for item in da_decisions
                if item["name"] == "aggregate_attacker"
            ),
            "private_origin": next(
                item["state"]
                for item in da_decisions
                if item["name"] == "private_origin"
            ),
            "public_subprefix_attacker": next(
                item["state"]
                for item in da_decisions
                if item["name"] == "public_subprefix_attacker"
            ),
            "interpretation": (
                "Open policy preserves self-protection at the exact aggregate "
                "and excludes non-public origins, but it cannot authenticate "
                "or distinguish an arbitrary eligible public subprefix origin."
            ),
        },
    }

    output = Path(args.output)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    csv_path = output.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case", "prefix", "origin", "baseline", "da"])
        baseline_by_name = {item["name"]: item for item in baseline_decisions}
        for item in da_decisions:
            writer.writerow(
                [
                    item["name"],
                    item["prefix"],
                    item["origin"],
                    baseline_by_name[item["name"]]["state"],
                    item["state"],
                ]
            )

    report = [
        f"# End-to-End Experiment Report: {run_dir.name}",
        "",
        f"Overall result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "",
        "## Semantic and enforcement checks",
        "",
        "| Check | Result |",
        "|---|:---:|",
    ]
    report.extend(
        f"| {name.replace('_', ' ')} | {'PASS' if passed else 'FAIL'} |"
        for name, passed in checks.items()
    )
    report.extend(
        [
            "",
            "## Route decisions",
            "",
            "| Case | Prefix | Origin | RFC 6811 baseline | S2-ROV |",
            "|---|---|---:|---|---|",
        ]
    )
    baseline_by_name = {item["name"]: item for item in baseline_decisions}
    report.extend(
        "| {name} | `{prefix}` | AS{origin} | {baseline} | {da} |".format(
            name=item["name"],
            prefix=item["prefix"],
            origin=item["origin"],
            baseline=baseline_by_name[item["name"]]["state"],
            da=item["state"],
        )
        for item in da_decisions
    )
    report.extend(
        [
            "",
            "## Timing",
            "",
            "| Metric | Milliseconds |",
            "|---|---:|",
        ]
    )
    report.extend(
        f"| {name.replace('_', ' ')} | {value:.3f} |"
        for name, value in timings.items()
    )
    for label, stats in (
        (
            "Routinator restart to S2-ROV policy recovery in FRR",
            summary["recovery_timing"],
        ),
        ("FRR restart to S2-ROV policy recovery", summary["frr_recovery_timing"]),
        (
            "Closed override removal to Delegated in FRR",
            summary["override_remove_timing"],
        ),
        (
            "Closed override restoration to Explicit in FRR",
            summary["override_restore_timing"],
        ),
    ):
        report.append(
            f"| {label} (n={stats['n']}, median/p95) | "
            f"{stats['median_ms']:.3f} / {stats['p95_ms']:.3f} |"
        )
    report.extend(
        [
            (
                f"| Routinator outage policy hold "
                f"({outage['hold_seconds']} s) | "
                f"{'PASS' if outage['policy_retained'] else 'FAIL'} |"
            ),
            "",
            "## Security boundary",
            "",
            summary["security_boundary"]["interpretation"],
            "",
            "In particular, the public-AS subprefix test is **Delegated**, not "
            "Explicit or Valid. This is an intentional negative control.",
            "",
        ]
    )
    (run_dir / "REPORT.md").write_text("\n".join(report), encoding="utf-8")

    if not summary["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
