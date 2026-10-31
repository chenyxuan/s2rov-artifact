#!/usr/bin/env python3
"""Independently audit a four-arm origin-churn control campaign.

The audit intentionally does not read ``summary.csv``, ``summary.json``, or
``REPORT.md``.  Durations come from ``events.jsonl``; trial metadata, router
captures, policy captures, the randomized schedule, and source hashes are
used only to validate the event-derived measurements and run invariants.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ARMS = ("exact", "da", "bgp_only", "prepublished_exact")
EVENT_SEQUENCE = {
    "exact": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "signed_authorization_requested",
        "routinator_validated",
        "frr_rtr_table_updated",
        "valid_route_accepted",
    ),
    "da": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "delegated_route_accepted",
    ),
    "bgp_only": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "route_accepted",
    ),
    "prepublished_exact": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "route_accepted",
    ),
}
FINAL_EVENT = {
    "exact": "valid_route_accepted",
    "da": "delegated_route_accepted",
    "bgp_only": "route_accepted",
    "prepublished_exact": "route_accepted",
}
FINAL_METADATA = {
    "exact": ("Valid", 300, "65000:10"),
    "da": ("Delegated", 200, "65000:20"),
    "bgp_only": ("BGPOnly", 100, None),
    "prepublished_exact": ("Valid", 300, "65000:10"),
}
FINAL_DECISION = {
    "exact": "Valid",
    "da": "Delegated",
    "bgp_only": "NotFound",
    "prepublished_exact": "Valid",
}
DIRECT_DURATION_FIELDS = (
    "invalid_exposure_ms",
    "unavailable_ms",
    "end_to_end_ms",
    "authorization_to_completion_ms",
    "signed_request_to_routinator_ms",
    "routinator_to_rtr_ms",
    "rtr_to_enforcement_ms",
)
METADATA_DURATION_FIELDS = (
    "invalid_exposure_ms",
    "unavailable_ms",
    "end_to_end_ms",
    "signed_request_to_routinator_ms",
    "routinator_to_rtr_ms",
    "rtr_to_enforcement_ms",
)
CONTRASTS = (
    ("exact_minus_prepublished_exact", "exact", "prepublished_exact"),
    ("exact_minus_da", "exact", "da"),
    ("da_minus_bgp_only", "da", "bgp_only"),
    (
        "prepublished_exact_minus_bgp_only",
        "prepublished_exact",
        "bgp_only",
    ),
    ("da_minus_prepublished_exact", "da", "prepublished_exact"),
)
ROUNDING_TOLERANCE_MS = 0.001


class AuditError(RuntimeError):
    """Raised when a required run artifact cannot be parsed."""


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    """Return a nearest-rank sample quantile."""

    sample = sorted(values)
    if not sample:
        raise ValueError("cannot summarize an empty sample")
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be in (0, 1]")
    rank = max(1, math.ceil(fraction * len(sample)))
    return sample[rank - 1]


def _rounded(value: float, digits: int = 3) -> float:
    return round(float(value), digits)


def sample_stats(values: Iterable[float]) -> dict[str, float | int | str]:
    """Return trial-level descriptive statistics with nearest-rank tails."""

    sample = list(values)
    if not sample:
        raise ValueError("cannot summarize an empty sample")
    q1 = nearest_rank(sample, 0.25)
    q3 = nearest_rank(sample, 0.75)
    return {
        "n_trials": len(sample),
        "mean_ms": _rounded(statistics.fmean(sample)),
        "median_ms": _rounded(statistics.median(sample)),
        "q1_nearest_rank_ms": _rounded(q1),
        "q3_nearest_rank_ms": _rounded(q3),
        "iqr_nearest_rank_ms": _rounded(q3 - q1),
        "p95_nearest_rank_ms": _rounded(nearest_rank(sample, 0.95)),
        "min_ms": _rounded(min(sample)),
        "max_ms": _rounded(max(sample)),
        "quantile_method": "nearest-rank for q1, q3, and p95",
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read JSON artifact {path}: {exc}") from exc


def _read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as exc:
        raise AuditError(f"cannot read CSV artifact {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"cannot hash source artifact {path}: {exc}") from exc
    return digest.hexdigest()


def _policy_roas(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in document.get("roas", [])
        if item.get("prefix") in ("10.0.10.0/24", "10.0.0.0/16")
    ]


def _policy_digest(document: dict[str, Any]) -> str:
    serialized = json.dumps(
        _policy_roas(document), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(f"{serialized}\n".encode()).hexdigest()


def _policy_signature(document: dict[str, Any]) -> list[list[Any]]:
    return sorted(
        [
            item.get("prefix"),
            item.get("asn"),
            item.get("minLength"),
            item.get("maxLength"),
            item.get("inclusivity"),
        ]
        for item in _policy_roas(document)
    )


def _expected_policy(lane: str, origin: int) -> list[list[Any]]:
    if lane == "exact":
        return [["10.0.10.0/24", f"AS{origin}", 24, 24, None]]
    if lane == "da":
        return [["10.0.0.0/16", "AS64501", 16, 24, "inclusive"]]
    if lane == "bgp_only":
        return []
    return sorted(
        [
            ["10.0.10.0/24", "AS8075", 24, 24, None],
            ["10.0.10.0/24", "AS18403", 24, 24, None],
        ]
    )


def _rib_path(document: dict[str, Any]) -> dict[str, Any] | None:
    paths = document.get("paths", [])
    return paths[0] if len(paths) == 1 else None


def _rib_origin(document: dict[str, Any]) -> int | None:
    path = _rib_path(document)
    if path is None:
        return None
    segments = path.get("aspath", {}).get("segments", [])
    if segments and segments[-1].get("list"):
        return int(segments[-1]["list"][-1])
    text = path.get("aspath", {}).get("string")
    if text:
        try:
            return int(str(text).split()[-1])
        except ValueError:
            return None
    return None


def _received_origin(document: dict[str, Any], prefix: str) -> int | None:
    route = document.get("receivedRoutes", {}).get(prefix, {})
    path = str(route.get("path", "")).split()
    if not path:
        return None
    try:
        return int(path[-1])
    except ValueError:
        return None


def _derive_durations(lane: str, by_name: dict[str, int]) -> dict[str, float]:
    final = by_name[FINAL_EVENT[lane]]
    durations = {
        "end_to_end_ms": (final - by_name["switch_requested"]) / 1e6,
        "unavailable_ms": (final - by_name["old_route_absent"]) / 1e6,
        "post_absence_to_adj_rib_ms": (
            by_name["new_route_in_adj_rib_in"]
            - by_name["old_route_absent"]
        )
        / 1e6,
        "invalid_exposure_ms": 0.0,
        "authorization_to_completion_ms": 0.0,
        "signed_request_to_routinator_ms": 0.0,
        "routinator_to_rtr_ms": 0.0,
        "rtr_to_enforcement_ms": 0.0,
    }
    if lane == "exact":
        durations.update(
            {
                "invalid_exposure_ms": (
                    final - by_name["new_route_in_adj_rib_in"]
                )
                / 1e6,
                "authorization_to_completion_ms": (
                    final - by_name["signed_authorization_requested"]
                )
                / 1e6,
                "signed_request_to_routinator_ms": (
                    by_name["routinator_validated"]
                    - by_name["signed_authorization_requested"]
                )
                / 1e6,
                "routinator_to_rtr_ms": (
                    by_name["frr_rtr_table_updated"]
                    - by_name["routinator_validated"]
                )
                / 1e6,
                "rtr_to_enforcement_ms": (
                    final - by_name["frr_rtr_table_updated"]
                )
                / 1e6,
            }
        )
    return durations


def _expected_schedule(rounds: int, seed: int) -> list[tuple[int, str]]:
    rng = random.Random(seed)
    expected: list[tuple[int, str]] = []
    for round_id in range(1, rounds + 1):
        order = list(ARMS)
        rng.shuffle(order)
        expected.extend((round_id, lane) for lane in order)
    return expected


def _setup_update_counts(
    schedule: list[tuple[int, str]], *, include_keepalive: bool = True
) -> tuple[int, int]:
    entries = {
        "none": 0,
        "bgp_only": 0,
        "exact": 1,
        "da": 1,
        "prepublished_exact": 2,
    }
    transactions = 1 if include_keepalive else 0
    changes = 1 if include_keepalive else 0
    previous = "none"
    for _, lane in schedule:
        if lane != previous:
            entry_changes = entries[previous] + entries[lane]
            if entry_changes:
                transactions += 1
                changes += entry_changes
        previous = lane
    return transactions, changes


def _source_hash_audit(
    run_dir: Path, source_root: Path
) -> tuple[bool, list[dict[str, Any]], list[str]]:
    manifest = run_dir / "source.sha256"
    failures: list[str] = []
    entries: list[dict[str, Any]] = []
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, [], [f"cannot read {manifest}: {exc}"]
    root = source_root.resolve()
    for line in lines:
        if not line.strip():
            continue
        try:
            expected, relative = line.split(maxsplit=1)
        except ValueError:
            failures.append(f"malformed source hash line: {line!r}")
            continue
        relative = relative.lstrip(" *")
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            failures.append(f"source path escapes root: {relative}")
            continue
        if not candidate.is_file():
            failures.append(f"missing source file: {relative}")
            entries.append(
                {
                    "path": relative,
                    "expected_sha256": expected,
                    "actual_sha256": None,
                    "matches": False,
                }
            )
            continue
        actual = _sha256(candidate)
        matches = actual == expected
        if not matches:
            failures.append(f"source hash mismatch: {relative}")
        entries.append(
            {
                "path": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": matches,
            }
        )
    if not entries:
        failures.append("source hash manifest is empty")
    return not failures, entries, failures


def _bootstrap_contrasts(
    records: list[dict[str, Any]],
    rounds: int,
    replicates: int,
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if replicates <= 0:
        raise ValueError("bootstrap replicates must be positive")
    by_round: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        by_round[record["round"]][record["lane"]].append(record)

    raw_round_means: dict[int, dict[str, dict[str, float]]] = defaultdict(
        dict
    )
    round_means: dict[str, Any] = {}
    for round_id in range(1, rounds + 1):
        round_means[str(round_id)] = {}
        for lane in ARMS:
            sample = by_round[round_id][lane]
            raw_round_means[round_id][lane] = {
                field: statistics.fmean(item[field] for item in sample)
                for field in (
                    "invalid_exposure_ms",
                    "unavailable_ms",
                    "end_to_end_ms",
                )
            }
            round_means[str(round_id)][lane] = {
                field: _rounded(value, 6)
                for field, value in raw_round_means[round_id][lane].items()
            }

    series: list[tuple[str, str, str, str, list[float]]] = []
    for name, lane_a, lane_b in CONTRASTS:
        for field in ("end_to_end_ms", "unavailable_ms"):
            differences = [
                raw_round_means[round_id][lane_a][field]
                - raw_round_means[round_id][lane_b][field]
                for round_id in range(1, rounds + 1)
            ]
            series.append((name, lane_a, lane_b, field, differences))
    invalid_differences = [
        raw_round_means[round_id]["exact"]["invalid_exposure_ms"]
        - raw_round_means[round_id]["bgp_only"]["invalid_exposure_ms"]
        for round_id in range(1, rounds + 1)
    ]
    series.append(
        (
            "exact_minus_bgp_only",
            "exact",
            "bgp_only",
            "invalid_exposure_ms",
            invalid_differences,
        )
    )

    distributions: dict[tuple[str, str], list[float]] = {
        (name, field): [] for name, _, _, field, _ in series
    }
    rng = random.Random(seed)
    for _ in range(replicates):
        indices = [rng.randrange(rounds) for _ in range(rounds)]
        for name, _, _, field, differences in series:
            distributions[(name, field)].append(
                statistics.fmean(differences[index] for index in indices)
            )

    output: dict[str, Any] = {}
    for name, lane_a, lane_b, field, differences in series:
        estimates = distributions[(name, field)]
        output.setdefault(
            name,
            {
                "arm_a": lane_a,
                "arm_b": lane_b,
                "inferential_n_complete_rounds": rounds,
                "estimand": (
                    "mean across complete-round differences of within-arm "
                    "block means (arm_a - arm_b)"
                ),
                "metrics": {},
            },
        )["metrics"][field] = {
            "estimate_ms": _rounded(statistics.fmean(differences)),
            "ci95_nearest_rank_ms": [
                _rounded(nearest_rank(estimates, 0.025)),
                _rounded(nearest_rank(estimates, 0.975)),
            ],
            "round_differences_ms": [
                _rounded(value, 6) for value in differences
            ],
        }
    return output, round_means


def audit_run(
    run_dir: Path,
    *,
    source_root: Path | None = None,
    bootstrap_replicates: int = 100_000,
    bootstrap_seed: int = 20_260_823,
) -> dict[str, Any]:
    """Audit one run and return a deterministic JSON-serializable result."""

    run_dir = run_dir.resolve()
    if source_root is None:
        source_root = (
            run_dir.parent.parent
            if run_dir.parent.name == "outputs"
            else run_dir
        )
    source_root = source_root.resolve()
    protocol = _read_json(run_dir / "protocol.json")
    rounds = int(protocol["randomized_complete_block_rounds"])
    block_size = int(protocol["trials_per_block"])
    trials_per_lane = int(protocol["trials_per_lane"])
    schedule_seed = int(protocol["random_seed"])

    failures: dict[str, list[str]] = defaultdict(list)

    def fail(check: str, message: str) -> None:
        failures[check].append(message)

    schedule_rows = _read_csv(run_dir / "block-order.csv")
    schedule: list[tuple[int, str]] = []
    for row in schedule_rows:
        try:
            schedule.append((int(row["round"]), row["lane"]))
        except (KeyError, ValueError) as exc:
            fail("schedule_rows_parse", f"malformed schedule row {row}: {exc}")
    expected_schedule = _expected_schedule(rounds, schedule_seed)
    if schedule != expected_schedule:
        fail(
            "schedule_matches_seed",
            "block-order.csv does not match the seeded shuffle",
        )
    by_round_schedule: dict[int, list[str]] = defaultdict(list)
    for round_id, lane in schedule:
        by_round_schedule[round_id].append(lane)
    if len(schedule) != rounds * len(ARMS) or any(
        sorted(by_round_schedule.get(round_id, [])) != sorted(ARMS)
        for round_id in range(1, rounds + 1)
    ):
        fail(
            "schedule_is_complete_randomized_block",
            "each round must contain every arm exactly once",
        )
    if tuple(protocol.get("arms", ())) != ARMS:
        fail("protocol_arms_match", f"unexpected protocol arms: {protocol.get('arms')}")
    if trials_per_lane != rounds * block_size:
        fail(
            "protocol_trial_arithmetic",
            "trials_per_lane must equal rounds times trials_per_block",
        )

    events: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(
            (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if line.strip():
                event = json.loads(line)
                event["_line"] = line_number
                events.append(event)
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read events.jsonl: {exc}") from exc

    grouped_events: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(
        list
    )
    group_order: list[tuple[str, int]] = []
    last_key: tuple[str, int] | None = None
    closed: set[tuple[str, int]] = set()
    for event in events:
        try:
            key = (event["lane"], int(event["trial"]))
            event["monotonic_ns"] = int(event["monotonic_ns"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditError(f"malformed event at line {event.get('_line')}: {exc}") from exc
        if key != last_key:
            if last_key is not None:
                closed.add(last_key)
            if key in closed:
                fail("trial_events_are_contiguous", f"interleaved trial {key}")
            group_order.append(key)
            last_key = key
        grouped_events[key].append(event)

    if any(
        right["monotonic_ns"] <= left["monotonic_ns"]
        for left, right in zip(events, events[1:])
    ):
        fail("global_event_clock_is_strictly_monotonic", "event time decreased")

    expected_groups: list[tuple[str, int]] = []
    lane_counts = Counter()
    block_for_group: dict[tuple[str, int], tuple[int, int, int]] = {}
    for block, (round_id, lane) in enumerate(schedule, start=1):
        for block_trial in range(1, block_size + 1):
            lane_counts[lane] += 1
            key = (lane, lane_counts[lane])
            expected_groups.append(key)
            block_for_group[key] = (block, block_trial, round_id)
    if group_order != expected_groups:
        fail(
            "event_trial_order_matches_schedule",
            "event trial order does not match randomized blocks",
        )
    expected_event_count = trials_per_lane * sum(
        len(EVENT_SEQUENCE[lane]) for lane in ARMS
    )
    if len(events) != expected_event_count:
        fail(
            "event_count_matches_protocol",
            f"expected {expected_event_count} events, observed {len(events)}",
        )

    duration_by_key: dict[tuple[str, int], dict[str, float]] = {}
    for lane in ARMS:
        for trial in range(1, trials_per_lane + 1):
            key = (lane, trial)
            sample = grouped_events.get(key, [])
            names = [item.get("event") for item in sample]
            if tuple(names) != EVENT_SEQUENCE[lane]:
                fail(
                    "per_trial_event_sequences_match",
                    f"{lane}/{trial}: {names}",
                )
                continue
            timestamps = [item["monotonic_ns"] for item in sample]
            if any(right <= left for left, right in zip(timestamps, timestamps[1:])):
                fail(
                    "per_trial_event_clock_is_strictly_monotonic",
                    f"{lane}/{trial}",
                )
                continue
            by_name = {
                item["event"]: item["monotonic_ns"] for item in sample
            }
            duration_by_key[key] = _derive_durations(lane, by_name)

    if len(duration_by_key) != len(ARMS) * trials_per_lane:
        raise AuditError("cannot compute all trial durations from events")

    trial_rows = _read_csv(run_dir / "trials.csv")
    csv_by_key: dict[tuple[str, int], dict[str, str]] = {}
    for row in trial_rows:
        try:
            csv_by_key[(row["lane"], int(row["lane_trial"]))] = row
        except (KeyError, ValueError) as exc:
            fail("trials_csv_rows_parse", f"malformed trials.csv row: {exc}")
    if len(trial_rows) != len(ARMS) * trials_per_lane:
        fail(
            "trials_csv_has_no_dropped_rows",
            f"expected {len(ARMS) * trials_per_lane}, got {len(trial_rows)}",
        )

    records: list[dict[str, Any]] = []
    native_rpki_states: dict[str, Counter[str]] = defaultdict(Counter)
    policy_digests: dict[str, set[str]] = defaultdict(set)
    max_metadata_error = 0.0
    max_csv_error = 0.0
    for global_order, key in enumerate(expected_groups, start=1):
        lane, trial = key
        block, block_trial, round_id = block_for_group[key]
        trial_dir = run_dir / "raw" / lane / f"trial-{trial:02d}"
        metadata = _read_json(trial_dir / "metadata.json")
        durations = duration_by_key[key]
        record = {
            "lane": lane,
            "trial": trial,
            "block": block,
            "block_trial": block_trial,
            "round": round_id,
            **durations,
        }
        records.append(record)

        identity_expected = {
            "lane": lane,
            "trial": trial,
            "block": block,
            "prefix": "10.0.10.0/24",
        }
        for field, expected in identity_expected.items():
            if metadata.get(field) != expected:
                fail(
                    "trial_metadata_matches_schedule",
                    f"{lane}/{trial} {field}: {metadata.get(field)} != {expected}",
                )
        for field in METADATA_DURATION_FIELDS:
            try:
                error = abs(float(metadata[field]) - durations[field])
            except (KeyError, TypeError, ValueError):
                fail(
                    "raw_event_durations_match_metadata",
                    f"{lane}/{trial} missing {field}",
                )
                continue
            max_metadata_error = max(max_metadata_error, error)
            if error > ROUNDING_TOLERANCE_MS:
                fail(
                    "raw_event_durations_match_metadata",
                    f"{lane}/{trial} {field} error {error:.9f} ms",
                )

        exact = lane == "exact"
        expected_updates = 1 if exact else 0
        expected_changes = 2 if exact else 0
        if (
            metadata.get("signed_update_transactions") != expected_updates
            or metadata.get("authorization_entry_changes") != expected_changes
        ):
            check = (
                "exact_updates_each_handoff"
                if exact
                else "controls_issue_no_handoff_updates"
            )
            fail(check, f"{lane}/{trial} update count mismatch")
        if metadata.get("passed") is not True:
            fail("all_trial_assertions_pass", f"{lane}/{trial}")

        csv_row = csv_by_key.get(key)
        if csv_row is None:
            fail("trials_csv_has_no_dropped_rows", f"missing row {key}")
        else:
            expected_csv = {
                "global_order": global_order,
                "block": block,
                "block_trial": block_trial,
                "from_origin": metadata.get("from_origin"),
                "to_origin": metadata.get("to_origin"),
                "signed_update_transactions": expected_updates,
                "authorization_entry_changes": expected_changes,
                "final_local_preference": metadata.get(
                    "final_local_preference"
                ),
            }
            for field, expected in expected_csv.items():
                try:
                    actual = int(csv_row[field])
                except (KeyError, ValueError):
                    fail(
                        "trials_csv_matches_raw_artifacts",
                        f"{lane}/{trial} malformed {field}",
                    )
                    continue
                if actual != expected:
                    fail(
                        "trials_csv_matches_raw_artifacts",
                        f"{lane}/{trial} {field}: {actual} != {expected}",
                    )
            expected_csv_text = {
                "lane": lane,
                "final_state": metadata.get("final_state"),
                "final_action": metadata.get("final_action"),
                "policy_digest": metadata.get("policy_digest"),
            }
            for field, expected in expected_csv_text.items():
                if csv_row.get(field) != expected:
                    fail(
                        "trials_csv_matches_raw_artifacts",
                        (
                            f"{lane}/{trial} {field}: "
                            f"{csv_row.get(field)} != {expected}"
                        ),
                    )
            if csv_row.get("passed", "").lower() != "true":
                fail("all_trial_assertions_pass", f"trials.csv {lane}/{trial}")
            try:
                csv_final_origin = int(csv_row["final_origin"])
            except (KeyError, ValueError):
                csv_final_origin = None
            if csv_final_origin != metadata.get("to_origin"):
                fail(
                    "trials_csv_matches_raw_artifacts",
                    f"{lane}/{trial} final origin {csv_final_origin}",
                )
            for field in DIRECT_DURATION_FIELDS:
                try:
                    error = abs(float(csv_row[field]) - durations[field])
                except (KeyError, ValueError):
                    fail(
                        "raw_event_durations_match_trials_csv",
                        f"{lane}/{trial} missing {field}",
                    )
                    continue
                max_csv_error = max(max_csv_error, error)
                if error > ROUNDING_TOLERANCE_MS:
                    fail(
                        "raw_event_durations_match_trials_csv",
                        f"{lane}/{trial} {field} error {error:.9f} ms",
                    )

        from_origin = int(metadata["from_origin"])
        to_origin = int(metadata["to_origin"])
        before_rib = _read_json(trial_dir / "before-rib.json")
        after_withdraw = _read_json(trial_dir / "after-withdraw-rib.json")
        received = _read_json(trial_dir / "new-origin-received.json")
        final_rib = _read_json(trial_dir / "final-rib.json")
        if _rib_origin(before_rib) != from_origin:
            fail("before_route_matches_source_origin", f"{lane}/{trial}")
        if after_withdraw != {}:
            fail("old_route_is_absent_before_announcement", f"{lane}/{trial}")
        if _received_origin(received, "10.0.10.0/24") != to_origin:
            fail("new_route_reaches_adj_rib_in", f"{lane}/{trial}")
        final_path = _rib_path(final_rib)
        state, preference, community = FINAL_METADATA[lane]
        if final_path is None or _rib_origin(final_rib) != to_origin:
            fail("final_route_matches_target_origin", f"{lane}/{trial}")
        else:
            local_preference = final_path.get(
                "locPrf", final_rib.get("defaultLocPrf", 100)
            )
            communities = final_path.get("community", {}).get("list", [])
            if local_preference != preference:
                fail(
                    "final_state_action_preference_match",
                    f"{lane}/{trial} local preference {local_preference}",
                )
            if community is not None and community not in communities:
                fail(
                    "final_state_action_preference_match",
                    f"{lane}/{trial} missing community {community}",
                )
            if community is None and communities:
                fail(
                    "final_state_action_preference_match",
                    f"{lane}/{trial} unexpected communities {communities}",
                )
            native_rpki_states[lane][
                str(final_path.get("rpkiValidationState", "missing"))
            ] += 1
        if (
            metadata.get("final_state") != state
            or metadata.get("final_action") != "accept"
            or metadata.get("final_local_preference") != preference
        ):
            fail("final_state_action_preference_match", f"{lane}/{trial}")

        decision = _read_json(trial_dir / "final-decision.json")
        decision_row = decision[0] if len(decision) == 1 else {}
        if (
            decision_row.get("state") != FINAL_DECISION[lane]
            or decision_row.get("pass") is not True
        ):
            fail("custom_decision_matches_arm", f"{lane}/{trial}")

        before_policy = _read_json(trial_dir / "before-routinator.json")
        final_policy = _read_json(trial_dir / "final-routinator.json")
        if _policy_signature(before_policy) != _expected_policy(
            lane, from_origin
        ):
            fail("policy_contents_match_arm", f"{lane}/{trial} before")
        if _policy_signature(final_policy) != _expected_policy(lane, to_origin):
            fail("policy_contents_match_arm", f"{lane}/{trial} final")
        if not exact and _policy_signature(before_policy) != _policy_signature(
            final_policy
        ):
            fail("static_control_policy_is_unchanged", f"{lane}/{trial}")
        if exact and _policy_signature(before_policy) == _policy_signature(
            final_policy
        ):
            fail("exact_policy_changes_each_handoff", f"{lane}/{trial}")
        digest = _policy_digest(final_policy)
        policy_digests[lane].add(digest)
        if metadata.get("policy_digest") != digest:
            fail("final_policy_digest_matches_capture", f"{lane}/{trial}")

        if exact:
            preauthorization = _read_json(
                trial_dir / "preauthorization-decision.json"
            )
            preauthorization_row = (
                preauthorization[0] if len(preauthorization) == 1 else {}
            )
            if (
                preauthorization_row.get("state") != "Invalid"
                or preauthorization_row.get("pass") is not True
                or _read_json(trial_dir / "preauthorization-rib.json") != {}
            ):
                fail(
                    "exact_route_is_invalid_and_filtered_before_update",
                    f"exact/{trial}",
                )

    for lane in ("da", "bgp_only", "prepublished_exact"):
        if len(policy_digests[lane]) != 1:
            fail(
                "static_policy_digest_is_stable",
                f"{lane}: {sorted(policy_digests[lane])}",
            )

    setup_transactions, setup_changes = _setup_update_counts(
        schedule, include_keepalive=bool(protocol.get("repository_keepalive"))
    )
    if (
        protocol.get("setup_signed_update_transactions")
        != setup_transactions
        or protocol.get("setup_authorization_entry_changes") != setup_changes
    ):
        fail(
            "setup_update_counts_match_schedule",
            (
                f"derived {setup_transactions}/{setup_changes}, protocol "
                f"{protocol.get('setup_signed_update_transactions')}/"
                f"{protocol.get('setup_authorization_entry_changes')}"
            ),
        )

    source_ok, source_entries, source_failures = _source_hash_audit(
        run_dir, source_root
    )
    for message in source_failures:
        fail("source_hashes_match", message)

    lane_summaries: dict[str, Any] = {}
    for lane in ARMS:
        sample = [record for record in records if record["lane"] == lane]
        lane_summaries[lane] = {
            "trial_n": len(sample),
            "inferential_round_n": rounds,
            "invalid_exposure": sample_stats(
                record["invalid_exposure_ms"] for record in sample
            ),
            "unavailability": sample_stats(
                record["unavailable_ms"] for record in sample
            ),
            "end_to_end_completion": sample_stats(
                record["end_to_end_ms"] for record in sample
            ),
            "post_absence_to_adj_rib": sample_stats(
                record["post_absence_to_adj_rib_ms"] for record in sample
            ),
            "native_frr_rpki_state_counts": dict(
                sorted(native_rpki_states[lane].items())
            ),
            "policy_digests": sorted(policy_digests[lane]),
        }
        if lane == "exact":
            for field, label in (
                (
                    "authorization_to_completion_ms",
                    "authorization_to_completion",
                ),
                (
                    "signed_request_to_routinator_ms",
                    "signed_request_to_routinator",
                ),
                ("routinator_to_rtr_ms", "routinator_to_rtr"),
                ("rtr_to_enforcement_ms", "rtr_to_enforcement"),
            ):
                lane_summaries[lane][label] = sample_stats(
                    record[field] for record in sample
                )

    contrasts, round_means = _bootstrap_contrasts(
        records, rounds, bootstrap_replicates, bootstrap_seed
    )

    check_names = (
        "schedule_rows_parse",
        "schedule_matches_seed",
        "schedule_is_complete_randomized_block",
        "protocol_arms_match",
        "protocol_trial_arithmetic",
        "trial_events_are_contiguous",
        "global_event_clock_is_strictly_monotonic",
        "event_trial_order_matches_schedule",
        "event_count_matches_protocol",
        "per_trial_event_sequences_match",
        "per_trial_event_clock_is_strictly_monotonic",
        "trials_csv_rows_parse",
        "trials_csv_has_no_dropped_rows",
        "trial_metadata_matches_schedule",
        "raw_event_durations_match_metadata",
        "exact_updates_each_handoff",
        "controls_issue_no_handoff_updates",
        "all_trial_assertions_pass",
        "trials_csv_matches_raw_artifacts",
        "raw_event_durations_match_trials_csv",
        "before_route_matches_source_origin",
        "old_route_is_absent_before_announcement",
        "new_route_reaches_adj_rib_in",
        "final_route_matches_target_origin",
        "final_state_action_preference_match",
        "custom_decision_matches_arm",
        "policy_contents_match_arm",
        "static_control_policy_is_unchanged",
        "exact_policy_changes_each_handoff",
        "final_policy_digest_matches_capture",
        "exact_route_is_invalid_and_filtered_before_update",
        "static_policy_digest_is_stable",
        "setup_update_counts_match_schedule",
        "source_hashes_match",
    )
    checks = {name: name not in failures for name in check_names}
    # Ensure a missing source manifest can never be masked by an empty list.
    checks["source_hashes_match"] = source_ok and not failures.get(
        "source_hashes_match"
    )
    output = {
        "schema_version": 1,
        "passed": all(checks.values()),
        "run_dir": str(run_dir),
        "inputs": {
            "used": [
                "protocol.json",
                "block-order.csv",
                "events.jsonl",
                "trials.csv (cross-check only)",
                "raw/*/trial-* captures and metadata",
                "source.sha256",
            ],
            "intentionally_not_read": [
                "summary.csv",
                "summary.json",
                "REPORT.md",
            ],
        },
        "design": {
            "arms": list(ARMS),
            "trial_n_per_arm": trials_per_lane,
            "trials_per_arm_per_round": block_size,
            "inferential_n_complete_rounds": rounds,
            "total_trials": len(records),
            "random_seed": schedule_seed,
            "setup_signed_update_transactions_derived": setup_transactions,
            "setup_authorization_entry_changes_derived": setup_changes,
        },
        "timing_provenance": {
            "source": "events.jsonl monotonic_ns",
            "raw_to_metadata_max_abs_error_ms": _rounded(
                max_metadata_error, 6
            ),
            "raw_to_trials_csv_max_abs_error_ms": _rounded(max_csv_error, 6),
            "comparison_tolerance_ms": ROUNDING_TOLERANCE_MS,
            "bgp_observation_ms_independently_recomputable": False,
            "bgp_observation_limitation": (
                "announce_start is not emitted as an event; the audit reports "
                "post_absence_to_adj_rib_ms instead"
            ),
        },
        "checks": checks,
        "failures": {
            name: sorted(messages)
            for name, messages in sorted(failures.items())
            if messages
        },
        "descriptive_trial_level": lane_summaries,
        "round_block_means_ms": round_means,
        "inference": {
            "unit": "complete randomized round",
            "inferential_n_complete_rounds": rounds,
            "bootstrap_replicates": bootstrap_replicates,
            "bootstrap_seed": bootstrap_seed,
            "bootstrap_rng": "Python random.Random (MT19937)",
            "ci_method": "nearest-rank percentile interval",
            "contrasts": contrasts,
        },
        "source_hash_audit": {
            "source_root": str(source_root),
            "entries": source_entries,
        },
        "interpretation_cautions": [
            (
                f"Trial-level descriptive n is {trials_per_lane} per arm, "
                f"but inferential n is {rounds} complete randomized rounds."
            ),
            (
                "A confidence interval spanning zero is not evidence of "
                "equivalence without a prespecified equivalence margin."
            ),
            (
                "S2-ROV is an agent-generated FRR policy decision; FRR's native "
                "rpkiValidationState is diagnostic and is not the S2-ROV state."
            ),
            (
                "Unavailability begins at confirmed old-route absence, not at "
                "the withdrawal request."
            ),
        ],
    }
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bootstrap-replicates", type=int, default=100_000)
    parser.add_argument("--bootstrap-seed", type=int, default=20_260_823)
    args = parser.parse_args()
    try:
        result = audit_run(
            args.run_dir,
            source_root=args.source_root,
            bootstrap_replicates=args.bootstrap_replicates,
            bootstrap_seed=args.bootstrap_seed,
        )
    except (AuditError, KeyError, TypeError, ValueError) as exc:
        result = {
            "schema_version": 1,
            "passed": False,
            "run_dir": str(args.run_dir.resolve()),
            "fatal_error": str(exc),
            "inputs": {
                "intentionally_not_read": [
                    "summary.csv",
                    "summary.json",
                    "REPORT.md",
                ]
            },
        }
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
