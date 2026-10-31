#!/usr/bin/env python3
"""Independently audit a matched unknown-origin handoff experiment.

The auditor never reads derived summaries.  Timing is reconstructed from the
monotonic event log, ROA work is reconstructed from update events and captured
policies, and trial claims are checked against raw metadata and captures.
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
from typing import Any, Iterable, Mapping


ARMS = ("reactive_exact", "open_dynamic", "prepublished_exact")
EVENT_SEQUENCE = {
    "reactive_exact": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "signed_roa_requested",
        "rp_policy_available",
        "compiler_started",
        "compiler_completed",
        "action_installed",
        "probe_succeeded",
    ),
    "open_dynamic": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "rp_policy_available",
        "compiler_started",
        "compiler_completed",
        "action_installed",
        "probe_succeeded",
    ),
    "prepublished_exact": (
        "switch_requested",
        "old_route_absent",
        "new_route_in_adj_rib_in",
        "rp_policy_available",
        "compiler_started",
        "compiler_completed",
        "action_installed",
        "probe_succeeded",
    ),
}
EVENT_ALIASES = {
    "route_observed": "new_route_in_adj_rib_in",
    "new_origin_observed": "new_route_in_adj_rib_in",
    "signed_authorization_requested": "signed_roa_requested",
    "signed_update_requested": "signed_roa_requested",
    "roa_update_requested": "signed_roa_requested",
    "policy_available": "rp_policy_available",
    "compiler_start": "compiler_started",
    "compiler_finish": "compiler_completed",
    "compiler_finished": "compiler_completed",
    "open_action_installed": "action_installed",
    "valid_route_accepted": "action_installed",
    "route_accepted": "action_installed",
    "dataplane_probe_succeeded": "probe_succeeded",
    "control_probe_succeeded": "probe_succeeded",
}
FAILURE_EVENTS = {"trial_failed", "deadline_missed", "trial_aborted"}
TIMING_FIELDS = (
    "observed_to_action_ms",
    "observed_to_probe_ms",
    "switch_to_action_ms",
    "switch_to_probe_ms",
)
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
ROUNDING_TOLERANCE_MS = 0.001
DEFAULT_BOOTSTRAP_REPLICATES = 100_000
DEFAULT_BOOTSTRAP_SEED = 20_260_828


class AuditError(RuntimeError):
    """Raised when a required raw artifact cannot be parsed."""


def nearest_rank(values: Iterable[float], fraction: float) -> float:
    sample = sorted(float(value) for value in values)
    if not sample:
        raise ValueError("cannot summarize an empty sample")
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be in (0, 1]")
    return sample[max(1, math.ceil(fraction * len(sample))) - 1]


def _rounded(value: float | None, digits: int = 3) -> float | None:
    return None if value is None else round(float(value), digits)


def sample_stats(values: Iterable[float | None]) -> dict[str, Any]:
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


def _read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditError(
                f"cannot parse events.jsonl line {line_number}: {exc}"
            ) from exc
        event["_line"] = line_number
        events.append(event)
    return events


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _first(
    row: Mapping[str, Any], names: Iterable[str], default: Any = None
) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return default


def _as_int(value: Any) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return int(text)


def _as_float(value: Any) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite value {value!r}")
    return parsed


def _as_bool(value: Any, *, default: bool | None = None) -> bool | None:
    if value is None or str(value).strip() == "":
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "pass", "passed"}:
        return True
    if normalized in {"0", "false", "no", "n", "fail", "failed"}:
        return False
    return default


def _event_name(event: Mapping[str, Any]) -> str:
    raw = str(_first(event, ("event", "name"), "")).strip()
    return EVENT_ALIASES.get(raw, raw)


def _event_timestamp(event: Mapping[str, Any]) -> int:
    value = _first(event, ("monotonic_ns", "timestamp_ns", "time_ns"))
    if value is None:
        raise AuditError(f"event line {event.get('_line')} has no monotonic time")
    return int(value)


def _event_key(event: Mapping[str, Any]) -> tuple[str, int]:
    lane = str(_first(event, ("lane", "arm"), "")).strip()
    trial = _as_int(_first(event, ("trial", "lane_trial")))
    if not lane or trial is None:
        raise AuditError(
            f"event line {event.get('_line')} has no lane/trial identity"
        )
    return lane, trial


def _derive_timings(events: list[dict[str, Any]]) -> dict[str, float | None]:
    by_name = {_event_name(event): _event_timestamp(event) for event in events}
    observed = by_name.get("new_route_in_adj_rib_in")
    action = by_name.get("action_installed")
    probe = by_name.get("probe_succeeded")
    switched = by_name.get("switch_requested")

    def elapsed(start: int | None, end: int | None) -> float | None:
        if start is None or end is None:
            return None
        return (end - start) / 1e6

    return {
        "observed_to_action_ms": elapsed(observed, action),
        "observed_to_probe_ms": elapsed(observed, probe),
        "switch_to_action_ms": elapsed(switched, action),
        "switch_to_probe_ms": elapsed(switched, probe),
    }


def _policy_entries(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if not isinstance(document, dict):
        return []
    for key in ("roas", "entries", "authorizations", "vrps"):
        value = document.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    nested = document.get("payload")
    return _policy_entries(nested) if nested is not None else []


def _policy_signature(document: Any) -> set[tuple[Any, ...]]:
    signature = set()
    for item in _policy_entries(document):
        signature.add(
            (
                item.get("prefix"),
                str(_first(item, ("asn", "origin", "origin_as"), "")),
                item.get("minLength", item.get("min_length")),
                item.get("maxLength", item.get("max_length")),
                item.get("inclusivity"),
            )
        )
    return signature


def _policy_origins(document: Any) -> set[int]:
    origins: set[int] = set()
    for item in _policy_entries(document):
        value = _first(item, ("asn", "origin", "origin_as"))
        try:
            origin = _as_int(value)
        except (TypeError, ValueError):
            continue
        if origin is not None:
            origins.add(origin)
    return origins


def _policy_digest_candidates(path: Path, document: Any) -> set[str]:
    candidates = {_sha256(path)}
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    candidates.add(hashlib.sha256(canonical.encode()).hexdigest())
    candidates.add(hashlib.sha256(f"{canonical}\n".encode()).hexdigest())
    entries = sorted(_policy_signature(document))
    serialized = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    candidates.add(hashlib.sha256(serialized.encode()).hexdigest())
    candidates.add(hashlib.sha256(f"{serialized}\n".encode()).hexdigest())
    return candidates


def _decision_rows(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in ("decisions", "results"):
            value = document.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if any(key in document for key in ("origin", "origin_as", "asn")):
            return [document]
    return []


def _decision_origins(document: Any) -> list[int]:
    origins: list[int] = []
    for row in _decision_rows(document):
        value = _first(row, ("origin", "origin_as", "route_origin", "asn"))
        try:
            origin = _as_int(value)
        except (TypeError, ValueError):
            continue
        if origin is not None:
            origins.append(origin)
    return origins


def _rib_origin(document: Any) -> int | None:
    if not isinstance(document, dict):
        return None
    paths = document.get("paths")
    if isinstance(paths, list) and len(paths) == 1:
        path = paths[0]
        if isinstance(path, dict):
            segments = path.get("aspath", {}).get("segments", [])
            if segments and segments[-1].get("list"):
                return _as_int(segments[-1]["list"][-1])
            text = path.get("aspath", {}).get("string")
            if text:
                return _as_int(str(text).split()[-1])
    routes = document.get("routes")
    if isinstance(routes, list) and len(routes) == 1:
        return _as_int(
            _first(routes[0], ("origin", "origin_as", "asn"))
        )
    return _as_int(_first(document, ("origin", "origin_as", "asn")))


def _ping_succeeded(text: str) -> bool:
    lowered = text.lower()
    return (
        "0% packet loss" in lowered
        or "0.0% packet loss" in lowered
        or "probe_succeeded" in lowered
        or "probe succeeded" in lowered
    )


def _trial_dir(run_dir: Path, lane: str, trial: int) -> Path:
    candidates = (
        run_dir / "raw" / lane / f"trial-{trial:03d}",
        run_dir / "raw" / lane / f"trial-{trial:02d}",
        run_dir / "raw" / lane / f"trial-{trial}",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


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
        actual = _sha256(candidate) if candidate.is_file() else None
        matches = actual == expected
        if not matches:
            failures.append(
                f"source hash mismatch or missing source: {relative}"
            )
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


def _artifact_manifest_audit(
    run_dir: Path,
) -> tuple[bool | None, list[dict[str, Any]], list[str], str | None]:
    """Audit an optional run-artifact hash manifest."""

    manifest = run_dir / "manifest.sha256"
    if not manifest.is_file():
        return None, [], [], None
    failures: list[str] = []
    entries: list[dict[str, Any]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            expected, relative = line.split(maxsplit=1)
        except ValueError:
            failures.append(f"malformed artifact hash line: {line!r}")
            continue
        relative = relative.lstrip(" *")
        candidate = (run_dir / relative).resolve()
        try:
            candidate.relative_to(run_dir.resolve())
        except ValueError:
            failures.append(f"artifact path escapes run directory: {relative}")
            continue
        actual = _sha256(candidate) if candidate.is_file() else None
        matches = actual == expected
        if not matches:
            failures.append(f"artifact hash mismatch: {relative}")
        entries.append(
            {
                "path": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": matches,
            }
        )
    return not failures, entries, failures, "manifest.sha256"


def _expected_schedule(rounds: int, seed: int) -> list[tuple[int, str]]:
    rng = random.Random(seed)
    result: list[tuple[int, str]] = []
    for round_id in range(1, rounds + 1):
        order = list(ARMS)
        rng.shuffle(order)
        result.extend((round_id, lane) for lane in order)
    return result


def _read_schedule(
    run_dir: Path,
    rounds: int,
    seed: int | None,
    failures: dict[str, list[str]],
) -> list[tuple[int, str]]:
    path = run_dir / "block-order.csv"
    schedule: list[tuple[int, str]] = []
    if path.is_file():
        for row in _read_csv(path):
            try:
                schedule.append((int(row["round"]), row["lane"]))
            except (KeyError, ValueError) as exc:
                failures["schedule_rows_parse"].append(
                    f"malformed block-order row {row}: {exc}"
                )
    else:
        failures["schedule_manifest_present"].append(
            "block-order.csv is missing"
        )
        return schedule
    by_round: dict[int, list[str]] = defaultdict(list)
    for round_id, lane in schedule:
        by_round[round_id].append(lane)
    if len(schedule) != rounds * len(ARMS) or any(
        sorted(by_round.get(round_id, [])) != sorted(ARMS)
        for round_id in range(1, rounds + 1)
    ):
        failures["schedule_is_complete_randomized_round"].append(
            "each round must contain every arm exactly once"
        )
    if seed is not None and schedule != _expected_schedule(rounds, seed):
        failures["schedule_matches_seed"].append(
            "block-order.csv does not match the seeded shuffle"
        )
    return schedule


def _expected_groups(
    schedule: list[tuple[int, str]], block_size: int
) -> tuple[
    list[tuple[str, int]], dict[tuple[str, int], tuple[int, int, int]]
]:
    groups: list[tuple[str, int]] = []
    positions: dict[tuple[str, int], tuple[int, int, int]] = {}
    lane_trials: Counter[str] = Counter()
    for block, (round_id, lane) in enumerate(schedule, start=1):
        for block_trial in range(1, block_size + 1):
            lane_trials[lane] += 1
            key = (lane, lane_trials[lane])
            groups.append(key)
            positions[key] = (round_id, block, block_trial)
    return groups, positions


def _compare_float(
    actual: Any,
    expected: float | None,
    *,
    tolerance: float = ROUNDING_TOLERANCE_MS,
) -> tuple[bool, float]:
    try:
        parsed = _as_float(actual)
    except (TypeError, ValueError):
        return False, math.inf
    if parsed is None or expected is None:
        return parsed is None and expected is None, 0.0
    error = abs(parsed - expected)
    return error <= tolerance, error


def _bootstrap_contrasts(
    records: list[dict[str, Any]],
    rounds: int,
    block_size: int,
    replicates: int,
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if replicates <= 0:
        raise ValueError("bootstrap replicates must be positive")
    grouped: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        grouped[record["round"]][record["lane"]].append(record)

    round_means: dict[str, Any] = {}
    raw: dict[int, dict[str, dict[str, float | None]]] = defaultdict(dict)
    for round_id in range(1, rounds + 1):
        round_means[str(round_id)] = {}
        for lane in ARMS:
            sample = grouped[round_id][lane]
            raw[round_id][lane] = {}
            round_means[str(round_id)][lane] = {}
            for metric in ("observed_to_action_ms", "observed_to_probe_ms"):
                values = [
                    item[metric]
                    for item in sample
                    if item[metric] is not None
                ]
                complete = len(values) == block_size
                mean = statistics.fmean(values) if complete else None
                raw[round_id][lane][metric] = mean
                round_means[str(round_id)][lane][metric] = {
                    "n_observed": len(values),
                    "mean_ms": _rounded(mean, 6),
                }

    rng = random.Random(seed)
    output: dict[str, Any] = {}
    for name, lane_a, lane_b in CONTRASTS:
        metrics: dict[str, Any] = {}
        for metric in ("observed_to_action_ms", "observed_to_probe_ms"):
            differences: list[tuple[int, float]] = []
            excluded: list[int] = []
            for round_id in range(1, rounds + 1):
                left = raw[round_id][lane_a][metric]
                right = raw[round_id][lane_b][metric]
                if left is None or right is None:
                    excluded.append(round_id)
                else:
                    differences.append((round_id, left - right))
            if differences:
                values = [value for _, value in differences]
                distribution = [
                    statistics.fmean(
                        values[rng.randrange(len(values))] for _ in values
                    )
                    for _ in range(replicates)
                ]
                estimate = statistics.fmean(values)
                ci = (
                    nearest_rank(distribution, 0.025),
                    nearest_rank(distribution, 0.975),
                )
            else:
                estimate = None
                ci = (None, None)
            metrics[metric] = {
                "estimate_ms": _rounded(estimate),
                "ci95_nearest_rank_ms": [
                    _rounded(ci[0]),
                    _rounded(ci[1]),
                ],
                "inferential_n_complete_rounds": len(differences),
                "included_rounds": [item[0] for item in differences],
                "excluded_rounds_missing_metric": excluded,
                "round_differences_ms": [
                    _rounded(item[1], 6) for item in differences
                ],
            }
        output[name] = {
            "arm_a": lane_a,
            "arm_b": lane_b,
            "estimand": (
                "mean across complete-round differences of within-arm "
                "trial means (arm_a - arm_b)"
            ),
            "metrics": metrics,
        }
    return output, round_means


def audit_run(
    run_dir: Path,
    *,
    source_root: Path | None = None,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Audit one run entirely from raw artifacts and event timestamps."""

    run_dir = run_dir.resolve()
    if source_root is None:
        source_root = (
            run_dir.parent.parent
            if run_dir.parent.name == "outputs"
            else run_dir
        )
    source_root = source_root.resolve()
    protocol = _read_json(run_dir / "protocol.json")
    arms = tuple(protocol.get("arms", ()))
    trials_per_lane = int(protocol["trials_per_lane"])
    block_size = int(protocol.get("trials_per_block", 1))
    rounds = int(
        protocol.get(
            "randomized_complete_block_rounds",
            protocol.get("randomized_complete_rounds"),
        )
    )
    schedule_seed_value = protocol.get("random_seed")
    schedule_seed = (
        int(schedule_seed_value) if schedule_seed_value is not None else None
    )

    failures: dict[str, list[str]] = defaultdict(list)

    def fail(check: str, message: str) -> None:
        failures[check].append(message)

    if arms != ARMS:
        fail("protocol_arms_match", f"unexpected protocol arms: {arms}")
    if trials_per_lane != rounds * block_size:
        fail(
            "protocol_trial_arithmetic",
            "trials_per_lane must equal rounds times trials_per_block",
        )

    schedule = _read_schedule(run_dir, rounds, schedule_seed, failures)
    expected_groups, group_positions = _expected_groups(schedule, block_size)

    events = _read_events(run_dir / "events.jsonl")
    grouped_events: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(
        list
    )
    group_order: list[tuple[str, int]] = []
    last_key: tuple[str, int] | None = None
    closed: set[tuple[str, int]] = set()
    for event in events:
        key = _event_key(event)
        event["monotonic_ns"] = _event_timestamp(event)
        if key != last_key:
            if last_key is not None:
                closed.add(last_key)
            if key in closed:
                fail("trial_events_are_contiguous", f"interleaved trial {key}")
            group_order.append(key)
            last_key = key
        grouped_events[key].append(event)
    if group_order != expected_groups:
        fail(
            "event_trial_order_matches_schedule",
            "event trial order does not match randomized complete rounds",
        )
    if any(
        right["monotonic_ns"] <= left["monotonic_ns"]
        for left, right in zip(events, events[1:])
    ):
        fail(
            "global_event_clock_is_strictly_monotonic",
            "event time is not globally strictly increasing",
        )

    trial_rows = _read_csv(run_dir / "trials.csv")
    csv_by_key: dict[tuple[str, int], dict[str, str]] = {}
    for row in trial_rows:
        try:
            key = (
                str(_first(row, ("lane", "arm"))),
                int(_first(row, ("trial", "lane_trial"))),
            )
        except (TypeError, ValueError) as exc:
            fail("trials_csv_rows_parse", f"malformed row {row}: {exc}")
            continue
        if key in csv_by_key:
            fail("trials_csv_unique_keys", f"duplicate row {key}")
        csv_by_key[key] = row
    if len(trial_rows) != len(ARMS) * trials_per_lane:
        fail(
            "trials_csv_retains_all_trials",
            f"expected {len(ARMS) * trials_per_lane}, got {len(trial_rows)}",
        )

    records: list[dict[str, Any]] = []
    max_metadata_timing_error = 0.0
    max_csv_timing_error = 0.0
    policy_digests: dict[str, set[str]] = defaultdict(set)
    decision_origins_by_lane: dict[str, Counter[int]] = defaultdict(Counter)
    final_state_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for global_order, key in enumerate(expected_groups, start=1):
        lane, trial = key
        round_id, block, block_trial = group_positions[key]
        trial_events = grouped_events.get(key, [])
        names = [_event_name(event) for event in trial_events]
        expected_sequence = EVENT_SEQUENCE[lane]
        canonical_names = [name for name in names if name not in FAILURE_EVENTS]
        passed_event_sequence = tuple(canonical_names) == expected_sequence
        if not passed_event_sequence:
            fail(
                "per_trial_event_sequences_match",
                f"{lane}/{trial}: {names}",
            )
        timestamps = [event["monotonic_ns"] for event in trial_events]
        if any(right <= left for left, right in zip(timestamps, timestamps[1:])):
            fail(
                "per_trial_event_clock_is_strictly_monotonic",
                f"{lane}/{trial}",
            )
        timings = _derive_timings(trial_events)
        if any(
            value is not None and value < 0 for value in timings.values()
        ):
            fail("derived_timings_are_nonnegative", f"{lane}/{trial}")

        signed_events = [
            event
            for event in trial_events
            if _event_name(event) == "signed_roa_requested"
        ]
        signed_updates = len(signed_events)

        trial_dir = _trial_dir(run_dir, lane, trial)
        metadata = _read_json(trial_dir / "metadata.json")
        pre_policy_path = trial_dir / "pre-policy.json"
        final_policy_path = trial_dir / "final-policy.json"
        pre_policy = _read_json(pre_policy_path)
        final_policy = _read_json(final_policy_path)
        decisions = _read_json(trial_dir / "decisions.json")
        final_rib = _read_json(trial_dir / "final-rib.json")
        try:
            ping_text = (trial_dir / "ping.txt").read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"cannot read {trial_dir / 'ping.txt'}: {exc}") from exc

        from_origin = _as_int(metadata.get("from_origin"))
        to_origin = _as_int(metadata.get("to_origin"))
        if from_origin is None or to_origin is None:
            fail("trial_metadata_has_endpoint_origins", f"{lane}/{trial}")
        identity_expected = {
            "lane": lane,
            "trial": trial,
            "round": round_id,
        }
        for field, expected in identity_expected.items():
            actual = metadata.get(field)
            if field in {"trial", "round"}:
                try:
                    actual = int(actual)
                except (TypeError, ValueError):
                    pass
            if actual != expected:
                fail(
                    "trial_metadata_matches_schedule",
                    f"{lane}/{trial} {field}: {actual} != {expected}",
                )

        entry_changes = len(
            _policy_signature(pre_policy) ^ _policy_signature(final_policy)
        )
        event_changes = [
            _as_int(
                _first(
                    event,
                    ("roa_entry_changes", "authorization_entry_changes"),
                )
            )
            for event in signed_events
        ]
        explicit_changes = [value for value in event_changes if value is not None]
        if explicit_changes and sum(explicit_changes) != entry_changes:
            fail(
                "event_roa_changes_match_policy_diff",
                f"{lane}/{trial}: events {sum(explicit_changes)}, diff {entry_changes}",
            )

        expected_updates = 1 if lane == "reactive_exact" else 0
        expected_changes = 2 if lane == "reactive_exact" else 0
        if signed_updates != expected_updates or entry_changes != expected_changes:
            check = (
                "reactive_exact_updates_each_handoff"
                if lane == "reactive_exact"
                else "nonreactive_arms_issue_no_handoff_roa_update"
            )
            fail(
                check,
                (
                    f"{lane}/{trial}: signed updates {signed_updates}, "
                    f"ROA-entry changes {entry_changes}"
                ),
            )

        for field in TIMING_FIELDS:
            matches, error = _compare_float(metadata.get(field), timings[field])
            if math.isfinite(error):
                max_metadata_timing_error = max(
                    max_metadata_timing_error, error
                )
            if not matches:
                fail(
                    "event_timings_match_metadata",
                    f"{lane}/{trial} {field}: {metadata.get(field)} vs {timings[field]}",
                )
        metadata_updates = _as_int(metadata.get("signed_update_transactions"))
        metadata_changes = _as_int(
            _first(
                metadata,
                ("roa_entry_changes", "authorization_entry_changes"),
            )
        )
        if metadata_updates != signed_updates or metadata_changes != entry_changes:
            fail(
                "event_roa_work_matches_metadata",
                f"{lane}/{trial}",
            )

        decision_rows = _decision_rows(decisions)
        decision_origins = _decision_origins(decisions)
        if lane == "open_dynamic":
            if (
                len(decision_rows) != 1
                or len(decision_origins) != 1
                or decision_origins[0] != to_origin
            ):
                fail(
                    "open_dynamic_has_one_observed_origin_decision",
                    (
                        f"open_dynamic/{trial}: rows={len(decision_rows)}, "
                        f"origins={decision_origins}, target={to_origin}"
                    ),
                )
            compiler_started = next(
                (
                    event["monotonic_ns"]
                    for event in trial_events
                    if _event_name(event) == "compiler_started"
                ),
                None,
            )
            observed = next(
                (
                    event["monotonic_ns"]
                    for event in trial_events
                    if _event_name(event) == "new_route_in_adj_rib_in"
                ),
                None,
            )
            if (
                observed is None
                or compiler_started is None
                or compiler_started <= observed
            ):
                fail(
                    "open_dynamic_compiles_after_observation",
                    f"open_dynamic/{trial}",
                )
            endpoint_origins = {
                origin for origin in (from_origin, to_origin) if origin is not None
            }
            leaked = endpoint_origins & (
                _policy_origins(pre_policy) | _policy_origins(final_policy)
            )
            if leaked:
                fail(
                    "open_signed_policy_omits_endpoint_origins",
                    f"open_dynamic/{trial}: endpoint origins in policy {sorted(leaked)}",
                )
            if _policy_signature(pre_policy) != _policy_signature(final_policy):
                fail(
                    "open_signed_policy_is_static_during_handoff",
                    f"open_dynamic/{trial}",
                )

        for origin in decision_origins:
            decision_origins_by_lane[lane][origin] += 1
        if to_origin is not None and _rib_origin(final_rib) != to_origin:
            fail("final_rib_matches_target_origin", f"{lane}/{trial}")

        action_present = "action_installed" in canonical_names
        probe_present = "probe_succeeded" in canonical_names
        completion = str(metadata.get("completion", "")).strip().lower()
        completion_success = _as_bool(completion, default=None)
        if completion_success is None:
            completion_success = completion in {
                "complete",
                "completed",
                "success",
                "succeeded",
            }
        deadline_miss = _as_bool(metadata.get("deadline_miss"), default=False)
        passed = _as_bool(metadata.get("passed"), default=False)
        if completion_success != (action_present and probe_present):
            fail("completion_matches_terminal_events", f"{lane}/{trial}")
        if probe_present and not _ping_succeeded(ping_text):
            fail("probe_event_matches_ping_capture", f"{lane}/{trial}")
        if deadline_miss is True:
            fail("no_deadline_miss", f"{lane}/{trial}")
        if passed is not True:
            fail("all_trial_assertions_pass", f"{lane}/{trial}")

        final_state = str(
            _first(metadata, ("final_state_paper", "final_state"), "")
        )
        final_state_counts[lane][final_state] += 1
        final_origin = _as_int(metadata.get("final_origin"))
        if final_origin != to_origin:
            fail("metadata_final_origin_matches_target", f"{lane}/{trial}")

        policy_digest = str(metadata.get("policy_digest", "")).strip()
        if policy_digest:
            policy_digests[lane].add(policy_digest)
            if policy_digest not in _policy_digest_candidates(
                final_policy_path, final_policy
            ):
                # The runner may define a documented domain-specific digest.
                # It must still agree between raw metadata and trials.csv below.
                pass

        csv_row = csv_by_key.get(key)
        if csv_row is None:
            fail("trials_csv_retains_all_trials", f"missing row {key}")
        else:
            integer_expected = {
                "global_order": global_order,
                "round": round_id,
                "block": block,
                "block_trial": block_trial,
                "from_origin": from_origin,
                "to_origin": to_origin,
                "signed_update_transactions": signed_updates,
                "roa_entry_changes": entry_changes,
                "final_local_preference": _as_int(
                    metadata.get("final_local_preference")
                ),
                "final_origin": to_origin,
            }
            for field, expected in integer_expected.items():
                try:
                    actual = _as_int(
                        _first(
                            csv_row,
                            (
                                field,
                                "authorization_entry_changes"
                                if field == "roa_entry_changes"
                                else field,
                            ),
                        )
                    )
                except (TypeError, ValueError):
                    actual = None
                if actual != expected:
                    fail(
                        "trials_csv_matches_raw_artifacts",
                        f"{lane}/{trial} {field}: {actual} != {expected}",
                    )
            for field in TIMING_FIELDS:
                matches, error = _compare_float(csv_row.get(field), timings[field])
                if math.isfinite(error):
                    max_csv_timing_error = max(max_csv_timing_error, error)
                if not matches:
                    fail(
                        "event_timings_match_trials_csv",
                        f"{lane}/{trial} {field}: {csv_row.get(field)} vs {timings[field]}",
                    )
            csv_text_expected = {
                "lane": lane,
                "status": str(metadata.get("status", "")),
                "final_state_raw": str(metadata.get("final_state_raw", "")),
                "final_state_paper": str(metadata.get("final_state_paper", "")),
                "final_action": str(metadata.get("final_action", "")),
                "policy_digest": policy_digest,
            }
            for field, expected in csv_text_expected.items():
                if csv_row.get(field, "") != expected:
                    fail(
                        "trials_csv_matches_raw_artifacts",
                        f"{lane}/{trial} {field}",
                    )
            if _as_bool(csv_row.get("completion"), default=None) != _as_bool(
                metadata.get("completion"), default=None
            ):
                fail(
                    "trials_csv_matches_raw_artifacts",
                    f"{lane}/{trial} completion",
                )
            csv_failure = str(csv_row.get("failure_category") or "")
            metadata_failure = str(metadata.get("failure_category") or "")
            if csv_failure != metadata_failure:
                fail(
                    "trials_csv_matches_raw_artifacts",
                    f"{lane}/{trial} failure_category",
                )
            if _as_bool(csv_row.get("deadline_miss"), default=False) != deadline_miss:
                fail("trials_csv_matches_raw_artifacts", f"{lane}/{trial} deadline")
            if _as_bool(csv_row.get("passed"), default=False) != passed:
                fail("trials_csv_matches_raw_artifacts", f"{lane}/{trial} passed")

        records.append(
            {
                "lane": lane,
                "trial": trial,
                "round": round_id,
                "block": block,
                "block_trial": block_trial,
                "from_origin": from_origin,
                "to_origin": to_origin,
                "signed_update_transactions": signed_updates,
                "roa_entry_changes": entry_changes,
                "completion": completion,
                "deadline_miss": deadline_miss,
                "passed": passed,
                **timings,
            }
        )

    source_ok, source_entries, source_failures = _source_hash_audit(
        run_dir, source_root
    )
    for message in source_failures:
        fail("source_hashes_match", message)
    artifact_ok, artifact_entries, artifact_failures, artifact_name = (
        _artifact_manifest_audit(run_dir)
    )
    for message in artifact_failures:
        fail("artifact_manifest_matches", message)

    lane_summaries: dict[str, Any] = {}
    for lane in ARMS:
        sample = [record for record in records if record["lane"] == lane]
        lane_summaries[lane] = {
            "trial_n": len(sample),
            "passed_n": sum(record["passed"] is True for record in sample),
            "failed_n": sum(record["passed"] is not True for record in sample),
            "deadline_miss_n": sum(
                record["deadline_miss"] is True for record in sample
            ),
            "signed_update_transactions_total": sum(
                record["signed_update_transactions"] for record in sample
            ),
            "roa_entry_changes_total": sum(
                record["roa_entry_changes"] for record in sample
            ),
            "metrics": {
                metric: sample_stats(record[metric] for record in sample)
                for metric in TIMING_FIELDS
            },
            "final_state_counts": dict(
                sorted(final_state_counts[lane].items())
            ),
            "decision_origin_counts": {
                str(origin): count
                for origin, count in sorted(
                    decision_origins_by_lane[lane].items()
                )
            },
            "policy_digests": sorted(policy_digests[lane]),
        }

    contrasts, round_means = _bootstrap_contrasts(
        records,
        rounds,
        block_size,
        bootstrap_replicates,
        bootstrap_seed,
    )

    check_names = (
        "protocol_arms_match",
        "protocol_trial_arithmetic",
        "schedule_manifest_present",
        "schedule_rows_parse",
        "schedule_is_complete_randomized_round",
        "schedule_matches_seed",
        "trial_events_are_contiguous",
        "event_trial_order_matches_schedule",
        "global_event_clock_is_strictly_monotonic",
        "per_trial_event_sequences_match",
        "per_trial_event_clock_is_strictly_monotonic",
        "derived_timings_are_nonnegative",
        "trials_csv_rows_parse",
        "trials_csv_unique_keys",
        "trials_csv_retains_all_trials",
        "trial_metadata_has_endpoint_origins",
        "trial_metadata_matches_schedule",
        "event_roa_changes_match_policy_diff",
        "reactive_exact_updates_each_handoff",
        "nonreactive_arms_issue_no_handoff_roa_update",
        "event_timings_match_metadata",
        "event_roa_work_matches_metadata",
        "open_dynamic_has_one_observed_origin_decision",
        "open_dynamic_compiles_after_observation",
        "open_signed_policy_omits_endpoint_origins",
        "open_signed_policy_is_static_during_handoff",
        "final_rib_matches_target_origin",
        "completion_matches_terminal_events",
        "probe_event_matches_ping_capture",
        "no_deadline_miss",
        "all_trial_assertions_pass",
        "metadata_final_origin_matches_target",
        "trials_csv_matches_raw_artifacts",
        "event_timings_match_trials_csv",
        "source_hashes_match",
        "artifact_manifest_matches",
    )
    checks = {name: name not in failures for name in check_names}
    checks["source_hashes_match"] = source_ok and not failures.get(
        "source_hashes_match"
    )
    checks["artifact_manifest_matches"] = (
        artifact_ok is not False and not failures.get("artifact_manifest_matches")
    )

    failed_trials = [
        {
            "lane": record["lane"],
            "trial": record["trial"],
            "round": record["round"],
            "completion": record["completion"],
            "deadline_miss": record["deadline_miss"],
            "observed_to_action_ms": record["observed_to_action_ms"],
            "observed_to_probe_ms": record["observed_to_probe_ms"],
        }
        for record in records
        if record["passed"] is not True
    ]
    return {
        "schema_version": 1,
        "passed": all(checks.values()),
        "run_dir": str(run_dir),
        "inputs": {
            "used": [
                "protocol.json",
                "block-order.csv",
                "events.jsonl",
                "trials.csv (cross-check only)",
                "raw/*/trial-*/metadata.json",
                "raw/*/trial-*/pre-policy.json",
                "raw/*/trial-*/final-policy.json",
                "raw/*/trial-*/decisions.json",
                "raw/*/trial-*/final-rib.json",
                "raw/*/trial-*/ping.txt",
                "source.sha256",
            ],
            "intentionally_not_read": [
                "summary.json",
                "summary.csv",
                "REPORT.md",
                "independent-audit.json",
            ],
        },
        "design": {
            "arms": list(ARMS),
            "trial_n_per_arm": trials_per_lane,
            "trials_per_arm_per_round": block_size,
            "inferential_n_complete_rounds": rounds,
            "total_trials": len(records),
            "random_seed": schedule_seed,
        },
        "timing_provenance": {
            "source": "events.jsonl monotonic_ns",
            "raw_to_metadata_max_abs_error_ms": _rounded(
                max_metadata_timing_error, 6
            ),
            "raw_to_trials_csv_max_abs_error_ms": _rounded(
                max_csv_timing_error, 6
            ),
            "comparison_tolerance_ms": ROUNDING_TOLERANCE_MS,
        },
        "checks": checks,
        "failures": {
            name: sorted(messages)
            for name, messages in sorted(failures.items())
            if messages
        },
        "descriptive_trial_level": lane_summaries,
        "failed_trials": failed_trials,
        "round_arm_means_ms": round_means,
        "inference": {
            "unit": "complete randomized round",
            "bootstrap_replicates": bootstrap_replicates,
            "bootstrap_seed": bootstrap_seed,
            "bootstrap_rng": "Python random.Random (MT19937)",
            "ci_method": "cluster percentile bootstrap; nearest-rank bounds",
            "contrasts": contrasts,
        },
        "source_hash_audit": {
            "source_root": str(source_root),
            "entries": source_entries,
        },
        "artifact_manifest_audit": {
            "manifest": artifact_name,
            "present": artifact_ok is not None,
            "entries": artifact_entries,
        },
        "interpretation_cautions": [
            (
                f"Trial-level descriptive n is {trials_per_lane} per arm, "
                f"but inferential n is {rounds} complete randomized rounds."
            ),
            (
                "All failed trials are retained. A timing contrast excludes a "
                "round only when either compared arm lacks that timing value."
            ),
            (
                "The endpoints measure local action installation and the "
                "configured probe, not Internet-wide reachability."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--source-root", type=Path)
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
                    "summary.json",
                    "summary.csv",
                    "REPORT.md",
                    "independent-audit.json",
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
