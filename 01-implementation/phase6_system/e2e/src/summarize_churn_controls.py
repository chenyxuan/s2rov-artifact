#!/usr/bin/env python3
"""Validate and summarize one immutable four-arm churn-control campaign."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from summarize_churn import load_rows, sample_stats


ARMS = ("exact", "da", "bgp_only", "prepublished_exact")
LABELS = {
    "exact": "Reactive exact ROA",
    "da": "Open DA policy",
    "bgp_only": "BGP-only",
    "prepublished_exact": "Prepublished exact ROAs",
}
FINAL = {
    "exact": ("Valid", 300),
    "da": ("Delegated", 200),
    "bgp_only": ("BGPOnly", 100),
    "prepublished_exact": ("Valid", 300),
}


def load_block_order(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["round"] = int(row["round"])
    return rows


def schedule_is_complete(
    schedule: list[dict[str, Any]], rounds: int
) -> bool:
    if len(schedule) != rounds * len(ARMS):
        return False
    by_round: dict[int, list[str]] = defaultdict(list)
    for row in schedule:
        by_round[row["round"]].append(row["lane"])
    return set(by_round) == set(range(1, rounds + 1)) and all(
        sorted(lanes) == sorted(ARMS) for lanes in by_round.values()
    )


def summarize_rows(
    rows: list[dict[str, Any]],
    expected_trials: int,
    block_size: int,
    rounds: int,
    schedule: list[dict[str, Any]],
) -> dict[str, Any]:
    by_lane: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_block: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_lane[row["lane"]].append(row)
        by_block[row["block"]].append(row)

    no_update_lanes = ("da", "bgp_only", "prepublished_exact")
    checks = {
        "all_trials_retained": len(rows) == len(ARMS) * expected_trials,
        "lane_counts_match": all(
            len(by_lane.get(lane, [])) == expected_trials for lane in ARMS
        ),
        "all_trial_assertions_pass": bool(rows)
        and all(row["passed"] for row in rows),
        "randomized_complete_block_schedule": schedule_is_complete(
            schedule, rounds
        ),
        "trial_blocks_match_schedule": len(by_block) == rounds * len(ARMS)
        and all(len(sample) == block_size for sample in by_block.values())
        and all(
            sample[0]["lane"] == schedule[block - 1]["lane"]
            for block, sample in sorted(by_block.items())
        ),
        "exact_updates_each_transition": bool(by_lane.get("exact"))
        and all(
            row["signed_update_transactions"] == 1
            and row["authorization_entry_changes"] == 2
            for row in by_lane["exact"]
        ),
        "controls_issue_no_handoff_updates": all(
            row["signed_update_transactions"] == 0
            and row["authorization_entry_changes"] == 0
            for lane in no_update_lanes
            for row in by_lane.get(lane, [])
        ),
        "static_policy_digests_unchanged": all(
            len({row["policy_digest"] for row in by_lane.get(lane, [])}) == 1
            for lane in no_update_lanes
        ),
        "final_states_and_actions_match": all(
            row["final_state"] == FINAL[lane][0]
            and row["final_action"] == "accept"
            and row["final_local_preference"] == FINAL[lane][1]
            and row["final_origin"] == row["to_origin"]
            for lane in ARMS
            for row in by_lane.get(lane, [])
        ),
        "exact_exposes_invalid_new_route": bool(by_lane.get("exact"))
        and all(row["invalid_exposure_ms"] > 0 for row in by_lane["exact"]),
        "nonreactive_arms_have_no_invalid_interval": all(
            row["invalid_exposure_ms"] == 0
            for lane in no_update_lanes
            for row in by_lane.get(lane, [])
        ),
    }

    lane_summaries: dict[str, Any] = {}
    for lane in ARMS:
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
            "unavailability": sample_stats(
                row["unavailable_ms"] for row in sample
            ),
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
            "final_state_counts": dict(
                Counter(row["final_state"] for row in sample)
            ),
            "final_action_counts": dict(
                Counter(row["final_action"] for row in sample)
            ),
            "policy_digests": sorted(
                {row["policy_digest"] for row in sample}
            ),
        }

    block_summaries: dict[str, Any] = {}
    for block, sample in sorted(by_block.items()):
        lane = sample[0]["lane"]
        block_summaries[str(block)] = {
            "lane": lane,
            "trials": len(sample),
            "unavailability": sample_stats(
                row["unavailable_ms"] for row in sample
            ),
            "end_to_end_completion": sample_stats(
                row["end_to_end_ms"] for row in sample
            ),
        }

    return {
        "passed": all(checks.values()),
        "checks": checks,
        "total_trials": len(rows),
        "expected_trials_per_lane": expected_trials,
        "trials_per_block": block_size,
        "randomized_complete_block_rounds": rounds,
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
        for lane in ARMS:
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
    lines = [
        f"# Four-arm churn-control report: {run_name}",
        "",
        f"Overall result: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "",
        "## Direct result",
        "",
        "| Arm | Trials | Signed updates | Invalid median / p95 (ms) | Unavailable median / p95 (ms) | Completion median / p95 (ms) | Final state / action |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for lane in ARMS:
        item = summary["lanes"][lane]
        state, _ = FINAL[lane]
        lines.append(
            f"| {LABELS[lane]} | {item['trials']} | "
            f"{item['signed_update_transactions_total']} | "
            f"{item['invalid_exposure']['median_ms']:.3f} / "
            f"{item['invalid_exposure']['p95_ms']:.3f} | "
            f"{item['unavailability']['median_ms']:.3f} / "
            f"{item['unavailability']['p95_ms']:.3f} | "
            f"{item['end_to_end_completion']['median_ms']:.3f} / "
            f"{item['end_to_end_completion']['p95_ms']:.3f} | "
            f"{state} / accept |"
        )
    lines.extend(
        [
            "",
            "Timing uses a persistent monotonic clock. Policy setup is outside "
            "the handoff intervals and is retained separately in `setup.csv`.",
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
            "## Design boundary",
            "",
            "The randomized complete-block schedule balances slow drift across "
            "the four controlled workflows. BGP-only isolates the same local "
            "break-before-make handoff without inbound RPKI enforcement. "
            "Prepublished exact ROAs represent advance knowledge of both candidate "
            "origins; they are not a solution to an origin that cannot be named "
            "before the handoff. Results remain laboratory control-plane "
            "measurements, not Internet propagation measurements.",
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
    protocol = json.loads(
        (run_dir / "protocol.json").read_text(encoding="utf-8")
    )
    rows = load_rows(run_dir / "trials.csv")
    schedule = load_block_order(run_dir / "block-order.csv")
    summary = summarize_rows(
        rows,
        int(protocol["trials_per_lane"]),
        int(protocol["trials_per_block"]),
        int(protocol["randomized_complete_block_rounds"]),
        schedule,
    )
    summary["protocol"] = protocol

    output = Path(args.output)
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_summary_csv(summary, run_dir / "summary.csv")
    (run_dir / "REPORT.md").write_text(
        make_report(summary, run_dir.name), encoding="utf-8"
    )
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
