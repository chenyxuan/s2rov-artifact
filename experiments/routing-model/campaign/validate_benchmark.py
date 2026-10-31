"""Validate deterministic paper-campaign benchmark slices.

A benchmark result must contain complete results for a non-empty prefix of the
manifest's frozen units.  The validator compares only deterministic outcome
content across worker counts; elapsed time, RSS, process IDs, worker sequence,
and other scheduling metadata never enter the fingerprint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


B1_DELEGATE = "B1_delegate_only"
B1_COMPETITION = "B1_competition"
D1_OPEN_DELEGATE = "D1_open_delegate_only"
A1_OPEN_COMPETITION = "A1_open_competition"
ATTACKER_CLASSES = ("uniform", "edge", "high_degree")


class BenchmarkValidationError(ValueError):
    """Raised when a benchmark slice is incomplete or non-deterministic."""


def load_manifest(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise BenchmarkValidationError("manifest root must be a JSON object")
    if not isinstance(document.get("selected_units"), list) or not isinstance(
        document.get("trial_plan"), list
    ):
        raise BenchmarkValidationError("manifest needs selected_units and trial_plan")
    return document


def load_results(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BenchmarkValidationError(
                    f"{path}:{line_number}: invalid JSON"
                ) from exc
            if not isinstance(item, dict):
                raise BenchmarkValidationError(
                    f"{path}:{line_number}: result row must be an object"
                )
            rows.append(item)
    if not rows:
        raise BenchmarkValidationError(f"{path}: benchmark result is empty")
    return rows


def _attacker_class(item: Mapping[str, Any]) -> str | None:
    value = item.get("attacker_class")
    return None if value in (None, "", "none", "na", "not_applicable") else str(value)


def _canonical_outcome_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping):
        raise BenchmarkValidationError(
            f"{row.get('scenario_id')}: missing outcomes object"
        )
    return {"scenario_id": str(row["scenario_id"]), "outcomes": outcomes}


def scenario_outcome_fingerprint(row: Mapping[str, Any]) -> str:
    """Fingerprint one scenario's ID and outcomes, excluding runtime metadata."""

    encoded = json.dumps(
        _canonical_outcome_payload(row),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def deterministic_outcome_fingerprint(rows: Sequence[Mapping[str, Any]]) -> str:
    """Fingerprint order-independent scenario outcomes for worker comparisons."""

    payload = sorted(
        (_canonical_outcome_payload(row) for row in rows),
        key=lambda item: item["scenario_id"],
    )
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _outcome_fingerprint(row: Mapping[str, Any]) -> str:
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping):
        raise BenchmarkValidationError(
            f"{row.get('scenario_id')}: missing outcomes object"
        )
    encoded = json.dumps(
        outcomes, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _row_key(row: Mapping[str, Any]) -> tuple[str, str | None, int]:
    try:
        percent = int(row["deployment_percent_target"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BenchmarkValidationError(
            f"{row.get('scenario_id')}: invalid deployment percentage"
        ) from exc
    return str(row.get("lane", "")), _attacker_class(row), percent


def _one_row(
    index: Mapping[tuple[str, str | None, int], Sequence[Mapping[str, Any]]],
    key: tuple[str, str | None, int],
    *,
    unit_id: str,
) -> Mapping[str, Any]:
    matches = index.get(key, ())
    if len(matches) != 1:
        raise BenchmarkValidationError(
            f"{unit_id}: expected exactly one row for {key}, found {len(matches)}"
        )
    return matches[0]


def validate_zero_equivalence(
    rows: Sequence[Mapping[str, Any]], unit_ids: Sequence[str]
) -> int:
    """Check exact B1/D1 and class-matched B1/A1 0% outcome equality."""

    by_unit: dict[str, list[Mapping[str, Any]]] = {unit_id: [] for unit_id in unit_ids}
    for row in rows:
        unit_id = str(row["unit_id"])
        if unit_id in by_unit:
            by_unit[unit_id].append(row)

    checks = 0
    for unit_id in unit_ids:
        index: dict[tuple[str, str | None, int], list[Mapping[str, Any]]] = {}
        for row in by_unit[unit_id]:
            index.setdefault(_row_key(row), []).append(row)
        b1_delegate = _one_row(index, (B1_DELEGATE, None, 0), unit_id=unit_id)
        d1_zero = _one_row(index, (D1_OPEN_DELEGATE, None, 0), unit_id=unit_id)
        if _outcome_fingerprint(b1_delegate) != _outcome_fingerprint(d1_zero):
            raise BenchmarkValidationError(
                f"{unit_id}: B1 delegate and D1@0 outcomes differ"
            )
        checks += 1
        for attacker_class in ATTACKER_CLASSES:
            b1 = _one_row(
                index,
                (B1_COMPETITION, attacker_class, 0),
                unit_id=unit_id,
            )
            a1 = _one_row(
                index,
                (A1_OPEN_COMPETITION, attacker_class, 0),
                unit_id=unit_id,
            )
            if _outcome_fingerprint(b1) != _outcome_fingerprint(a1):
                raise BenchmarkValidationError(
                    f"{unit_id}/{attacker_class}: B1 and A1@0 outcomes differ"
                )
            checks += 1
    return checks


def validate_benchmark(
    manifest: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Validate one complete prefix-unit benchmark result."""

    units = manifest.get("selected_units")
    plan = manifest.get("trial_plan")
    if not isinstance(units, list) or not isinstance(plan, list):
        raise BenchmarkValidationError("manifest needs selected_units and trial_plan")
    manifest_digest = manifest.get("manifest_sha256")
    manifest_schema = manifest.get("schema_version")
    ordered_units = [str(unit["unit_id"]) for unit in units]
    if len(ordered_units) != len(set(ordered_units)):
        raise BenchmarkValidationError("manifest has duplicate unit IDs")
    plan_by_id: dict[str, Mapping[str, Any]] = {}
    planned_ids_by_unit: dict[str, set[str]] = {
        unit_id: set() for unit_id in ordered_units
    }
    for item in plan:
        if not isinstance(item, Mapping):
            raise BenchmarkValidationError("trial plan entry must be an object")
        scenario_id = str(item["scenario_id"])
        unit_id = str(item["unit_id"])
        if scenario_id in plan_by_id or unit_id not in planned_ids_by_unit:
            raise BenchmarkValidationError(
                "manifest trial plan has duplicate/unknown ID"
            )
        plan_by_id[scenario_id] = item
        planned_ids_by_unit[unit_id].add(scenario_id)

    actual_ids: list[str] = []
    actual_units: set[str] = set()
    for row in rows:
        scenario_id = row.get("scenario_id")
        unit_id = row.get("unit_id")
        if not isinstance(scenario_id, str) or not isinstance(unit_id, str):
            raise BenchmarkValidationError(
                "result row needs string scenario_id/unit_id"
            )
        if row.get("status") != "success":
            raise BenchmarkValidationError(f"{scenario_id}: result is not successful")
        if row.get("schema_version") != manifest_schema:
            raise BenchmarkValidationError(f"{scenario_id}: schema version mismatch")
        if row.get("manifest_sha256") != manifest_digest:
            raise BenchmarkValidationError(f"{scenario_id}: manifest SHA256 mismatch")
        planned = plan_by_id.get(scenario_id)
        if planned is None or str(planned["unit_id"]) != unit_id:
            raise BenchmarkValidationError(
                f"{scenario_id}: unknown ID or unit differs from trial plan"
            )
        actual_ids.append(scenario_id)
        actual_units.add(unit_id)
        _canonical_outcome_payload(row)

    duplicates = [value for value, count in Counter(actual_ids).items() if count > 1]
    if duplicates:
        raise BenchmarkValidationError(
            f"benchmark has duplicate scenario IDs: {duplicates[:3]}"
        )
    if not actual_units:
        raise BenchmarkValidationError("benchmark contains no complete unit")
    prefix_units = ordered_units[: len(actual_units)]
    if actual_units != set(prefix_units):
        raise BenchmarkValidationError(
            "benchmark units must be a contiguous prefix of selected_units"
        )
    expected_ids = set().union(*(planned_ids_by_unit[unit] for unit in prefix_units))
    actual_id_set = set(actual_ids)
    missing = sorted(expected_ids - actual_id_set)
    unexpected = sorted(actual_id_set - expected_ids)
    if missing or unexpected or len(actual_ids) != len(expected_ids):
        raise BenchmarkValidationError(
            "benchmark row/ID set is incomplete: "
            f"missing={missing[:3]} ({len(missing)}), "
            f"unexpected={unexpected[:3]} ({len(unexpected)})"
        )

    zero_checks = validate_zero_equivalence(rows, prefix_units)
    per_scenario = {
        str(row["scenario_id"]): scenario_outcome_fingerprint(row) for row in rows
    }
    return {
        "status": "VERIFIED",
        "complete_prefix_units": len(prefix_units),
        "first_unit_id": prefix_units[0],
        "last_unit_id": prefix_units[-1],
        "scenario_rows": len(rows),
        "expected_scenario_rows": len(expected_ids),
        "zero_percent_exact_equalities": zero_checks,
        "outcome_fingerprint_sha256": deterministic_outcome_fingerprint(rows),
        "per_scenario_outcome_sha256": dict(sorted(per_scenario.items())),
        "fingerprint_scope": "scenario_id + outcomes only",
        "ignored_for_fingerprint": [
            "elapsed_seconds",
            "rss_before_bytes",
            "rss_after_bytes",
            "peak_rss_bytes",
            "worker_pid",
            "worker_trial_sequence",
            "worker_graph_build_seconds",
            "worker_graph_build_peak_rss_bytes",
        ],
    }


def compare_benchmarks(results: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Fail unless all worker-count runs cover and reproduce the same outcomes."""

    if not results:
        raise BenchmarkValidationError("no benchmark summaries supplied")
    unit_counts = {int(item["complete_prefix_units"]) for item in results.values()}
    row_counts = {int(item["scenario_rows"]) for item in results.values()}
    fingerprints = {
        str(item["outcome_fingerprint_sha256"]) for item in results.values()
    }
    if len(unit_counts) != 1 or len(row_counts) != 1:
        raise BenchmarkValidationError(
            "worker benchmarks cover different unit/scenario sets"
        )
    if len(fingerprints) != 1:
        raise BenchmarkValidationError(
            "worker benchmarks produced different deterministic outcomes"
        )
    return {
        "status": "VERIFIED",
        "labels": sorted(results),
        "complete_prefix_units": next(iter(unit_counts)),
        "scenario_rows": next(iter(row_counts)),
        "outcome_fingerprint_sha256": next(iter(fingerprints)),
        "cross_worker_outcomes_equal": True,
    }


def _parse_result_argument(value: str) -> tuple[str, Path]:
    if "=" in value:
        label, raw_path = value.split("=", 1)
        if not label or not raw_path:
            raise argparse.ArgumentTypeError("result must be LABEL=PATH or PATH")
        return label, Path(raw_path)
    path = Path(value)
    return path.stem, path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--result",
        action="append",
        type=_parse_result_argument,
        required=True,
        help="repeat LABEL=PATH for worker-count comparisons",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = load_manifest(args.manifest)
    summaries: dict[str, dict[str, Any]] = {}
    for label, path in args.result:
        if label in summaries:
            raise BenchmarkValidationError(f"duplicate result label {label!r}")
        summary = validate_benchmark(manifest, load_results(path))
        summary["path"] = str(path)
        summaries[label] = summary
    comparison = compare_benchmarks(summaries)
    output = {"runs": summaries, "comparison": comparison}
    rendered = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
