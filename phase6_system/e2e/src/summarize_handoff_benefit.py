#!/usr/bin/env python3
"""Summarize a matched unknown-origin handoff experiment.

The experiment uses randomized complete rounds with three workflows.  Trial
rows are never filtered by their outcome.  A missing timing value remains an
explicit missing observation, and a round enters a timing contrast only when
that metric is present for every scheduled trial in both compared arms.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping


ARMS = ("reactive_exact", "open_dynamic", "prepublished_exact")
LABELS = {
    "reactive_exact": "Reactive exact ROA",
    "open_dynamic": "Dynamic OpenScope",
    "prepublished_exact": "Prepublished exact ROAs",
}
METRICS = (
    "observed_to_action_ms",
    "observed_to_probe_ms",
    "switch_to_action_ms",
    "switch_to_probe_ms",
)
PRIMARY_METRICS = ("observed_to_action_ms", "observed_to_probe_ms")
CONTRASTS = (
    (
        "reactive_exact_minus_open_dynamic",
        "reactive_exact",
        "open_dynamic",
    ),
    (
        "reactive_exact_minus_prepublished_exact",
        "reactive_exact",
        "prepublished_exact",
    ),
    (
        "open_dynamic_minus_prepublished_exact",
        "open_dynamic",
        "prepublished_exact",
    ),
)
DEFAULT_BOOTSTRAP_REPLICATES = 100_000
DEFAULT_BOOTSTRAP_SEED = 20_260_828


class SummaryError(RuntimeError):
    """Raised when the trial input cannot be summarized safely."""


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    """Return a nearest-rank quantile."""

    sample = sorted(float(value) for value in values)
    if not sample:
        raise ValueError("cannot summarize an empty sample")
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be in (0, 1]")
    return sample[max(1, math.ceil(fraction * len(sample))) - 1]


def _rounded(value: float | None, digits: int = 3) -> float | None:
    return None if value is None else round(float(value), digits)


def sample_stats(values: Iterable[float | None]) -> dict[str, Any]:
    """Describe observed values while reporting missing values explicitly."""

    materialized = list(values)
    sample = [float(value) for value in materialized if value is not None]
    missing = len(materialized) - len(sample)
    if not sample:
        return {
            "n_total": len(materialized),
            "n_observed": 0,
            "n_missing": missing,
            "mean_ms": None,
            "median_ms": None,
            "p95_nearest_rank_ms": None,
            "min_ms": None,
            "max_ms": None,
            "quantile_method": "nearest-rank p95",
        }
    return {
        "n_total": len(materialized),
        "n_observed": len(sample),
        "n_missing": missing,
        "mean_ms": _rounded(statistics.fmean(sample)),
        "median_ms": _rounded(statistics.median(sample)),
        "p95_nearest_rank_ms": _rounded(nearest_rank(sample, 0.95)),
        "min_ms": _rounded(min(sample)),
        "max_ms": _rounded(max(sample)),
        "quantile_method": "nearest-rank p95",
    }


def _first(
    row: Mapping[str, Any], names: Iterable[str], default: Any = None
) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return default


def _parse_int(
    row: Mapping[str, Any], *names: str, default: int | None = None
) -> int | None:
    value = _first(row, names, default)
    if value is None or str(value).strip() == "":
        return None
    return int(value)


def _parse_float(
    row: Mapping[str, Any], *names: str, default: float | None = None
) -> float | None:
    value = _first(row, names, default)
    if value is None or str(value).strip() == "":
        return None
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite value for {names[0]}: {value}")
    return parsed


def parse_bool(value: Any, *, default: bool | None = None) -> bool | None:
    """Parse common CSV boolean spellings without treating blanks as false."""

    if value is None or str(value).strip() == "":
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "pass", "passed"}:
        return True
    if normalized in {"0", "false", "no", "n", "fail", "failed"}:
        return False
    raise ValueError(f"cannot parse boolean value {value!r}")


def _completion_success(value: Any) -> bool | None:
    try:
        parsed = parse_bool(value, default=None)
    except ValueError:
        parsed = None
    if parsed is not None:
        return parsed
    if value is None or str(value).strip() == "":
        return None
    normalized = str(value).strip().lower()
    if normalized in {
        "complete",
        "completed",
        "success",
        "succeeded",
        "action_installed",
    }:
        return True
    if normalized in {
        "incomplete",
        "timeout",
        "timed_out",
        "error",
        "aborted",
    }:
        return False
    return None


def normalize_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the canonical CSV schema and a small set of old aliases."""

    lane = str(_first(row, ("lane", "arm"), "")).strip()
    if not lane:
        raise SummaryError("trial row has no lane")
    round_id = _parse_int(row, "round", "randomized_round")
    trial = _parse_int(row, "trial", "lane_trial")
    if round_id is None or trial is None:
        raise SummaryError("trial row requires round and trial identifiers")

    completion_raw = _first(row, ("completion",), "")
    normalized = {
        "global_order": _parse_int(row, "global_order"),
        "round": round_id,
        "block": _parse_int(row, "block"),
        "block_trial": _parse_int(row, "block_trial"),
        "lane": lane,
        "trial": trial,
        "from_origin": _parse_int(row, "from_origin"),
        "to_origin": _parse_int(row, "to_origin"),
        "direction": str(_first(row, ("direction",), "")).strip(),
        "signed_update_transactions": _parse_int(
            row, "signed_update_transactions", default=0
        ),
        "roa_entry_changes": _parse_int(
            row,
            "roa_entry_changes",
            "authorization_entry_changes",
            default=0,
        ),
        "completion": str(completion_raw).strip(),
        "completion_success": _completion_success(completion_raw),
        "deadline_miss": parse_bool(
            _first(row, ("deadline_miss",), None), default=False
        ),
        "status": str(_first(row, ("status",), "")).strip(),
        "failure_category": str(
            _first(row, ("failure_category",), "")
        ).strip(),
        "final_state": str(
            _first(row, ("final_state_paper", "final_state"), "")
        ).strip(),
        "final_state_raw": str(
            _first(row, ("final_state_raw", "final_state"), "")
        ).strip(),
        "final_action": str(
            _first(row, ("final_action",), "")
        ).strip(),
        "final_lp": _parse_int(
            row, "final_local_preference", "final_lp"
        ),
        "final_origin": _parse_int(row, "final_origin"),
        "policy_digest": str(
            _first(row, ("policy_digest",), "")
        ).strip(),
        "passed": parse_bool(_first(row, ("passed",), None), default=False),
    }
    for metric in METRICS:
        normalized[metric] = _parse_float(row, metric)
    return normalized


def load_rows(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return [normalize_row(row) for row in csv.DictReader(handle)]
    except OSError as exc:
        raise SummaryError(f"cannot read {path}: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise SummaryError(f"cannot parse {path}: {exc}") from exc


def _round_cells(
    rows: list[dict[str, Any]], expected_per_cell: int
) -> tuple[dict[str, Any], set[int]]:
    grouped: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        grouped[row["round"]][row["lane"]].append(row)

    output: dict[str, Any] = {}
    design_complete: set[int] = set()
    for round_id in sorted(grouped):
        output[str(round_id)] = {}
        if all(
            len(grouped[round_id].get(lane, [])) == expected_per_cell
            for lane in ARMS
        ):
            design_complete.add(round_id)
        for lane in ARMS:
            sample = grouped[round_id].get(lane, [])
            item: dict[str, Any] = {
                "n_scheduled": len(sample),
                "n_passed": sum(row["passed"] is True for row in sample),
                "n_failed": sum(row["passed"] is not True for row in sample),
                "metrics": {},
            }
            for metric in METRICS:
                observed = [
                    row[metric] for row in sample if row[metric] is not None
                ]
                item["metrics"][metric] = {
                    "n_observed": len(observed),
                    "mean_ms": (
                        _rounded(statistics.fmean(observed), 6)
                        if observed
                        else None
                    ),
                }
            output[str(round_id)][lane] = item
    return output, design_complete


def _bootstrap_contrasts(
    round_cells: dict[str, Any],
    design_complete_rounds: set[int],
    expected_per_cell: int,
    replicates: int,
    seed: int,
) -> dict[str, Any]:
    if replicates <= 0:
        raise ValueError("bootstrap replicates must be positive")

    output: dict[str, Any] = {}
    rng = random.Random(seed)
    for contrast_name, lane_a, lane_b in CONTRASTS:
        metrics: dict[str, Any] = {}
        for metric in PRIMARY_METRICS:
            differences: list[tuple[int, float]] = []
            excluded: list[int] = []
            for round_id in sorted(design_complete_rounds):
                left = round_cells[str(round_id)][lane_a]["metrics"][metric]
                right = round_cells[str(round_id)][lane_b]["metrics"][metric]
                if (
                    left["n_observed"] != expected_per_cell
                    or right["n_observed"] != expected_per_cell
                ):
                    excluded.append(round_id)
                    continue
                differences.append(
                    (round_id, left["mean_ms"] - right["mean_ms"])
                )

            if differences:
                values = [value for _, value in differences]
                bootstrap = []
                for _ in range(replicates):
                    bootstrap.append(
                        statistics.fmean(
                            values[rng.randrange(len(values))]
                            for _ in values
                        )
                    )
                estimate = statistics.fmean(values)
                ci95 = [
                    nearest_rank(bootstrap, 0.025),
                    nearest_rank(bootstrap, 0.975),
                ]
            else:
                estimate = None
                ci95 = [None, None]
            metrics[metric] = {
                "estimate_ms": _rounded(estimate),
                "ci95_nearest_rank_ms": [
                    _rounded(ci95[0]),
                    _rounded(ci95[1]),
                ],
                "inferential_n_complete_rounds": len(differences),
                "included_rounds": [item[0] for item in differences],
                "excluded_rounds_missing_metric": excluded,
                "round_differences_ms": [
                    _rounded(item[1], 6) for item in differences
                ],
            }
        output[contrast_name] = {
            "arm_a": lane_a,
            "arm_b": lane_b,
            "estimand": (
                "mean across complete-round differences of within-arm "
                "trial means (arm_a - arm_b)"
            ),
            "metrics": metrics,
        }
    return output


def summarize_rows(
    rows: list[dict[str, Any]],
    *,
    expected_trials_per_lane: int | None = None,
    trials_per_arm_per_round: int = 1,
    expected_rounds: int | None = None,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Return a deterministic summary without dropping unsuccessful trials."""

    if not rows:
        raise SummaryError("trials.csv contains no rows")
    if trials_per_arm_per_round <= 0:
        raise ValueError("trials_per_arm_per_round must be positive")

    by_lane: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_lane[row["lane"]].append(row)
    unexpected_lanes = sorted(set(by_lane) - set(ARMS))
    duplicate_keys = [
        key
        for key, count in Counter(
            (row["lane"], row["trial"]) for row in rows
        ).items()
        if count > 1
    ]
    observed_rounds = sorted({row["round"] for row in rows})
    if expected_rounds is None:
        expected_rounds = len(observed_rounds)
    if expected_trials_per_lane is None:
        expected_trials_per_lane = (
            expected_rounds * trials_per_arm_per_round
        )

    round_cells, design_complete_rounds = _round_cells(
        rows, trials_per_arm_per_round
    )
    expected_round_ids = set(range(1, expected_rounds + 1))
    checks = {
        "only_expected_lanes": not unexpected_lanes,
        "no_duplicate_lane_trial_keys": not duplicate_keys,
        "all_rows_retained": sum(len(sample) for sample in by_lane.values())
        == len(rows),
        "lane_counts_match_protocol": all(
            len(by_lane.get(lane, [])) == expected_trials_per_lane
            for lane in ARMS
        ),
        "all_randomized_rounds_present": set(observed_rounds)
        == expected_round_ids,
        "all_rounds_are_complete": design_complete_rounds
        == expected_round_ids,
        "reactive_exact_updates_each_handoff": bool(
            by_lane.get("reactive_exact")
        )
        and all(
            row["signed_update_transactions"] == 1
            and row["roa_entry_changes"] == 2
            for row in by_lane["reactive_exact"]
        ),
        "nonreactive_arms_issue_no_handoff_roa_update": all(
            row["signed_update_transactions"] == 0
            and row["roa_entry_changes"] == 0
            for lane in ("open_dynamic", "prepublished_exact")
            for row in by_lane.get(lane, [])
        ),
        "all_trials_passed": all(row["passed"] is True for row in rows),
        "no_deadline_miss": all(row["deadline_miss"] is False for row in rows),
    }

    lanes: dict[str, Any] = {}
    for lane in ARMS:
        sample = by_lane.get(lane, [])
        lanes[lane] = {
            "label": LABELS[lane],
            "n_trials": len(sample),
            "n_passed": sum(row["passed"] is True for row in sample),
            "n_failed": sum(row["passed"] is not True for row in sample),
            "n_deadline_miss": sum(
                row["deadline_miss"] is True for row in sample
            ),
            "completion_counts": dict(
                sorted(Counter(row["completion"] for row in sample).items())
            ),
            "status_counts": dict(
                sorted(Counter(row["status"] for row in sample).items())
            ),
            "failure_category_counts": dict(
                sorted(
                    Counter(
                        row["failure_category"] or "none" for row in sample
                    ).items()
                )
            ),
            "signed_update_transactions_total": sum(
                row["signed_update_transactions"] for row in sample
            ),
            "roa_entry_changes_total": sum(
                row["roa_entry_changes"] for row in sample
            ),
            "metrics": {
                metric: sample_stats(row[metric] for row in sample)
                for metric in METRICS
            },
        }

    contrasts = _bootstrap_contrasts(
        round_cells,
        design_complete_rounds,
        trials_per_arm_per_round,
        bootstrap_replicates,
        bootstrap_seed,
    )
    failed_trials = [
        {
            "lane": row["lane"],
            "trial": row["trial"],
            "round": row["round"],
            "completion": row["completion"],
            "deadline_miss": row["deadline_miss"],
            "status": row["status"],
            "failure_category": row["failure_category"],
            "observed_to_action_ms": row["observed_to_action_ms"],
            "observed_to_probe_ms": row["observed_to_probe_ms"],
        }
        for row in rows
        if row["passed"] is not True
    ]

    return {
        "schema_version": 1,
        "passed": all(checks.values()),
        "checks": checks,
        "design": {
            "arms": list(ARMS),
            "trial_n_per_arm_expected": expected_trials_per_lane,
            "trials_per_arm_per_round": trials_per_arm_per_round,
            "randomized_complete_rounds_expected": expected_rounds,
            "randomized_complete_rounds_observed": len(
                design_complete_rounds
            ),
            "total_trial_rows": len(rows),
            "unexpected_lanes": unexpected_lanes,
            "duplicate_lane_trial_keys": [list(key) for key in duplicate_keys],
        },
        "trial_level": lanes,
        "all_trial_records": rows,
        "failed_trials": failed_trials,
        "round_arm_means": round_cells,
        "inference": {
            "unit": "complete randomized round",
            "bootstrap_replicates": bootstrap_replicates,
            "bootstrap_seed": bootstrap_seed,
            "bootstrap_rng": "Python random.Random (MT19937)",
            "ci_method": "cluster percentile bootstrap; nearest-rank bounds",
            "contrasts": contrasts,
        },
        "missingness_policy": (
            "All scheduled trials remain in trial-level counts. A metric "
            "contrast excludes a complete design round only when either arm "
            "has a missing value for that metric; no value is imputed."
        ),
    }


def write_summary_csv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            (
                "lane",
                "trials",
                "passed",
                "failed",
                "deadline_miss",
                "signed_update_transactions",
                "roa_entry_changes",
                "observed_to_action_median_ms",
                "observed_to_action_p95_ms",
                "observed_to_probe_median_ms",
                "observed_to_probe_p95_ms",
            )
        )
        for lane in ARMS:
            item = summary["trial_level"][lane]
            action = item["metrics"]["observed_to_action_ms"]
            probe = item["metrics"]["observed_to_probe_ms"]
            writer.writerow(
                (
                    lane,
                    item["n_trials"],
                    item["n_passed"],
                    item["n_failed"],
                    item["n_deadline_miss"],
                    item["signed_update_transactions_total"],
                    item["roa_entry_changes_total"],
                    action["median_ms"],
                    action["p95_nearest_rank_ms"],
                    probe["median_ms"],
                    probe["p95_nearest_rank_ms"],
                )
            )


def make_report(summary: dict[str, Any], run_name: str) -> str:
    lines = [
        f"# Matched unknown-origin handoff: {run_name}",
        "",
        f"Overall acceptance: **{'PASS' if summary['passed'] else 'FAIL'}**",
        "",
        "| Workflow | Trials | Passed | Signed updates | ROA-entry changes | Observed to action, median / p95 (ms) | Observed to probe, median / p95 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for lane in ARMS:
        item = summary["trial_level"][lane]
        action = item["metrics"]["observed_to_action_ms"]
        probe = item["metrics"]["observed_to_probe_ms"]
        lines.append(
            f"| {LABELS[lane]} | {item['n_trials']} | {item['n_passed']} | "
            f"{item['signed_update_transactions_total']} | "
            f"{item['roa_entry_changes_total']} | "
            f"{action['median_ms']} / {action['p95_nearest_rank_ms']} | "
            f"{probe['median_ms']} / {probe['p95_nearest_rank_ms']} |"
        )
    primary = summary["inference"]["contrasts"][
        "reactive_exact_minus_open_dynamic"
    ]["metrics"]["observed_to_action_ms"]
    lines.extend(
        [
            "",
            "## Primary complete-round contrast",
            "",
            (
                "Reactive exact minus dynamic OpenScope for observed-to-action "
                f"time: {primary['estimate_ms']} ms, 95% cluster-bootstrap CI "
                f"{primary['ci95_nearest_rank_ms']}; "
                f"n={primary['inferential_n_complete_rounds']} complete rounds."
            ),
            "",
            "Every failed trial remains in the JSON output and in the lane "
            "counts. Missing timing values are not imputed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--bootstrap-replicates",
        type=int,
        default=DEFAULT_BOOTSTRAP_REPLICATES,
    )
    parser.add_argument(
        "--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED
    )
    args = parser.parse_args()

    protocol_path = args.run_dir / "protocol.json"
    protocol = (
        json.loads(protocol_path.read_text(encoding="utf-8"))
        if protocol_path.is_file()
        else {}
    )
    rows = load_rows(args.run_dir / "trials.csv")
    expected_trials = protocol.get("trials_per_lane")
    block_size = int(protocol.get("trials_per_block", 1))
    rounds = protocol.get("randomized_complete_block_rounds")
    if rounds is None:
        rounds = protocol.get("randomized_complete_rounds")
    summary = summarize_rows(
        rows,
        expected_trials_per_lane=(
            int(expected_trials) if expected_trials is not None else None
        ),
        trials_per_arm_per_round=block_size,
        expected_rounds=int(rounds) if rounds is not None else None,
        bootstrap_replicates=args.bootstrap_replicates,
        bootstrap_seed=args.bootstrap_seed,
    )
    summary["protocol"] = protocol
    output = args.output or (args.run_dir / "summary.json")
    output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_summary_csv(summary, args.run_dir / "summary.csv")
    (args.run_dir / "REPORT.md").write_text(
        make_report(summary, args.run_dir.name), encoding="utf-8"
    )
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
