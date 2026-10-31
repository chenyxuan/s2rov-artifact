#!/usr/bin/env python3
"""Summarize one immutable prototype origin-churn run."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


FLOAT_FIELDS = (
    "invalid_exposure_ms",
    "unavailable_ms",
    "end_to_end_ms",
    "bgp_observation_ms",
    "authorization_to_completion_ms",
    "signed_request_to_routinator_ms",
    "routinator_to_rtr_ms",
    "rtr_to_enforcement_ms",
)
INT_FIELDS = (
    "global_order",
    "lane_trial",
    "block",
    "block_trial",
    "from_origin",
    "to_origin",
    "signed_update_transactions",
    "authorization_entry_changes",
    "final_local_preference",
    "final_origin",
)


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot summarize an empty sample")
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def sample_stats(values: Iterable[float]) -> dict[str, float | int]:
    sample = list(values)
    if not sample:
        raise ValueError("cannot summarize an empty sample")
    return {
        "n": len(sample),
        "median_ms": round(statistics.median(sample), 3),
        "p95_ms": round(nearest_rank(sample, 0.95), 3),
        "min_ms": round(min(sample), 3),
        "max_ms": round(max(sample), 3),
    }


def load_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        for field in FLOAT_FIELDS:
            row[field] = float(row[field])
        for field in INT_FIELDS:
            row[field] = int(row[field])
        row["passed"] = row["passed"].lower() == "true"
    return rows


def summarize_rows(
    rows: list[dict[str, Any]], expected_trials: int
) -> dict[str, Any]:
    by_lane: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_lane[row["lane"]].append(row)

    checks = {
        "all_trials_retained": len(rows) == 2 * expected_trials,
        "lane_counts_match": all(
            len(by_lane.get(lane, [])) == expected_trials
            for lane in ("exact", "da")
        ),
        "all_trial_assertions_pass": bool(rows)
        and all(row["passed"] for row in rows),
        "exact_updates_each_transition": bool(by_lane.get("exact"))
        and all(
            row["signed_update_transactions"] == 1
            and row["authorization_entry_changes"] == 2
            for row in by_lane["exact"]
        ),
        "da_policy_unchanged_during_churn": bool(by_lane.get("da"))
        and all(
            row["signed_update_transactions"] == 0
            and row["authorization_entry_changes"] == 0
            for row in by_lane["da"]
        )
        and len({row["policy_digest"] for row in by_lane["da"]}) == 1,
        "exact_finishes_valid_and_accepted": bool(by_lane.get("exact"))
        and all(
            row["final_state"] == "Valid"
            and row["final_action"] == "accept"
            and row["final_local_preference"] == 300
            and row["final_origin"] == row["to_origin"]
            for row in by_lane["exact"]
        ),
        "da_finishes_delegated_and_accepted": bool(by_lane.get("da"))
        and all(
            row["final_state"] == "Delegated"
            and row["final_action"] == "accept"
            and row["final_local_preference"] == 200
            and row["final_origin"] == row["to_origin"]
            for row in by_lane["da"]
        ),
        "exact_exposes_invalid_new_route": bool(by_lane.get("exact"))
        and all(row["invalid_exposure_ms"] > 0 for row in by_lane["exact"]),
        "da_has_no_invalid_state": bool(by_lane.get("da"))
        and all(row["invalid_exposure_ms"] == 0 for row in by_lane["da"]),
    }

    lane_summaries: dict[str, Any] = {}
    for lane in ("exact", "da"):
        sample = by_lane.get(lane, [])
        if not sample:
            continue
        lane_summaries[lane] = {
            "trials": len(sample),
            "signed_update_transactions_total": sum(
                row["signed_update_transactions"] for row in sample
            ),
            "authorization_entry_changes_total": sum(
                row["authorization_entry_changes"] for row in sample
            ),
            "invalid_exposure": sample_stats(
                row["invalid_exposure_ms"] for row in sample
            ),
            "unavailability": sample_stats(row["unavailable_ms"] for row in sample),
            "end_to_end_completion": sample_stats(
                row["end_to_end_ms"] for row in sample
            ),
            "bgp_observation": sample_stats(
                row["bgp_observation_ms"] for row in sample
            ),
            "authorization_to_completion": sample_stats(
                row["authorization_to_completion_ms"] for row in sample
            ),
            "signed_request_to_routinator": sample_stats(
                row["signed_request_to_routinator_ms"] for row in sample
            ),
            "routinator_to_rtr": sample_stats(
                row["routinator_to_rtr_ms"] for row in sample
            ),
            "rtr_to_enforcement": sample_stats(
                row["rtr_to_enforcement_ms"] for row in sample
            ),
            "final_state_counts": dict(Counter(row["final_state"] for row in sample)),
            "final_action_counts": dict(
                Counter(row["final_action"] for row in sample)
            ),
            "policy_digests": sorted({row["policy_digest"] for row in sample}),
        }

    block_summaries: dict[str, Any] = {}
    for (lane, block), sample in sorted(
        {
            (row["lane"], row["block"]): [
                candidate
                for candidate in rows
                if candidate["lane"] == row["lane"]
                and candidate["block"] == row["block"]
            ]
            for row in rows
        }.items()
    ):
        block_summaries[f"{lane}-{block}"] = {
            "lane": lane,
            "block": block,
            "trials": len(sample),
            "end_to_end_completion": sample_stats(
                row["end_to_end_ms"] for row in sample
            ),
            "unavailability": sample_stats(row["unavailable_ms"] for row in sample),
        }

    return {
        "passed": all(checks.values()),
        "checks": checks,
        "total_trials": len(rows),
        "expected_trials_per_lane": expected_trials,
        "lanes": lane_summaries,
        "execution_blocks": block_summaries,
    }


def write_summary_csv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "lane",
                "trials",
                "signed_update_transactions",
                "authorization_entry_changes",
                "invalid_median_ms",
                "invalid_p95_ms",
                "unavailable_median_ms",
                "unavailable_p95_ms",
                "completion_median_ms",
                "completion_p95_ms",
                "final_state",
                "final_action",
            ]
        )
        for lane in ("exact", "da"):
            item = summary["lanes"][lane]
            writer.writerow(
                [
                    lane,
                    item["trials"],
                    item["signed_update_transactions_total"],
                    item["authorization_entry_changes_total"],
                    item["invalid_exposure"]["median_ms"],
                    item["invalid_exposure"]["p95_ms"],
                    item["unavailability"]["median_ms"],
                    item["unavailability"]["p95_ms"],
                    item["end_to_end_completion"]["median_ms"],
                    item["end_to_end_completion"]["p95_ms"],
                    ";".join(item["final_state_counts"]),
                    ";".join(item["final_action_counts"]),
                ]
            )


def make_report(summary: dict[str, Any], run_name: str) -> str:
    exact = summary["lanes"]["exact"]
    da = summary["lanes"]["da"]
    lines = [
        f"# Origin-churn prototype report: {run_name}",
        "",
        f"Overall result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "",
        "## Direct result",
        "",
        "| Lane | Trials | Signed updates | Invalid exposure, median / p95 (ms) | Unavailable, median / p95 (ms) | Completion, median / p95 (ms) | Final state / action |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for label, item, state in (
        ("Exact child ROA", exact, "Valid / accept"),
        ("Open S2-ROV policy", da, "Delegated / accept"),
    ):
        lines.append(
            f"| {label} | {item['trials']} | "
            f"{item['signed_update_transactions_total']} | "
            f"{item['invalid_exposure']['median_ms']:.3f} / "
            f"{item['invalid_exposure']['p95_ms']:.3f} | "
            f"{item['unavailability']['median_ms']:.3f} / "
            f"{item['unavailability']['p95_ms']:.3f} | "
            f"{item['end_to_end_completion']['median_ms']:.3f} / "
            f"{item['end_to_end_completion']['p95_ms']:.3f} | {state} |"
        )
    lines.extend(
        [
            "",
            "One signed update is one atomic Krill authorization transaction. "
            "Each exact transition changes two entries (remove old, add new); "
            "the open-policy setup publication is excluded from S2-ROV handoff counts.",
            "",
            "### Exact-update path",
            "",
            "| Segment | Median / p95 (ms) |",
            "|---|---:|",
            f"| Signed request to Routinator validation | {exact['signed_request_to_routinator']['median_ms']:.3f} / {exact['signed_request_to_routinator']['p95_ms']:.3f} |",
            f"| Routinator validation to FRR RTR table | {exact['routinator_to_rtr']['median_ms']:.3f} / {exact['routinator_to_rtr']['p95_ms']:.3f} |",
            f"| RTR table to verified FRR enforcement | {exact['rtr_to_enforcement']['median_ms']:.3f} / {exact['rtr_to_enforcement']['p95_ms']:.3f} |",
            "",
            "## Acceptance checks",
            "",
            "| Check | Result |",
            "|---|:---:|",
        ]
    )
    lines.extend(
        f"| {name.replace('_', ' ')} | {'PASS' if passed else 'FAIL'} |"
        for name, passed in summary["checks"].items()
    )
    lines.extend(
        [
            "",
            "## Fairness and order",
            "",
            "Both lanes use the same `/24`, origin ASes, FRR topology, "
            "break-before-make BGP commands, polling path, and final-state stop "
            "condition. The recorded order sandwiches the S2-ROV block between two "
            "exact-ROA blocks; no timing observation is discarded.",
            "",
            "## Boundary",
            "",
            "This experiment measures a reactive handoff after the new origin "
            "appears. Pre-authorizing both exact origins can avoid its Invalid "
            "interval when the handoff is known in advance, but needs additional "
            "signed authorization and temporarily broadens the exact set. Results "
            "are laboratory control-plane measurements, not Internet propagation "
            "or native four-state RTR measurements. Delegated does not authenticate "
            "which downstream origin is legitimate.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    with (run_dir / "protocol.json").open(encoding="utf-8") as handle:
        protocol = json.load(handle)
    rows = load_rows(run_dir / "trials.csv")
    summary = summarize_rows(rows, int(protocol["trials_per_lane"]))
    summary["protocol"] = protocol

    output = Path(args.output)
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_summary_csv(summary, run_dir / "summary.csv")
    (run_dir / "REPORT.md").write_text(
        make_report(summary, run_dir.name), encoding="utf-8"
    )
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
