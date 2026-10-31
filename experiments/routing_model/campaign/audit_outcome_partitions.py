"""Independent routing-model all-AS destination-partition integrity audit.

This deliberately consumes only the frozen campaign manifest and append-only
raw scenario rows.  It does not import the paper analysis or consume any
derived report/summary artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from decimal import Decimal, getcontext
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence


getcontext().prec = 50

AUDIT_VERSION = "routing_model-outcome-partition-audit-v1"
EXPECTED_HOLDERS = 200
EXPECTED_WEIGHT_SUM = Decimal("691")
DESTINATIONS = (
    "delegate",
    "attacker",
    "holder_fallback",
    "disconnected",
    "loop",
)

CELL_SELECTORS: dict[str, dict[str, Any]] = {
    "b2_exact_delegate_only": {
        "lane": "B2_exact_delegate_only",
        "attacker_class": None,
        "deployment_percent_target": 0,
        "deployment_strategy": "reference",
    },
    "d1_open_delegate_only_100": {
        "lane": "D1_open_delegate_only",
        "attacker_class": None,
        "deployment_percent_target": 100,
        "deployment_strategy": "shared",
    },
    "b1_uniform_competition": {
        "lane": "B1_competition",
        "attacker_class": "uniform",
        "deployment_percent_target": 0,
        "deployment_strategy": "reference",
    },
    "b2_exact_uniform_competition": {
        "lane": "B2_exact_competition",
        "attacker_class": "uniform",
        "deployment_percent_target": 0,
        "deployment_strategy": "reference",
    },
    "a1_open_uniform_competition_100": {
        "lane": "A1_open_competition",
        "attacker_class": "uniform",
        "deployment_percent_target": 100,
        "deployment_strategy": "shared",
    },
}

PLAN_FIELDS = (
    "unit_id",
    "lane",
    "attacker_class",
    "deployment_percent_target",
    "deployment_strategy",
    "deployment_seed",
    "order_id",
)


class PartitionAuditError(ValueError):
    """Raised when a frozen artifact violates the audit contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    core = dict(manifest)
    core.pop("manifest_sha256", None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _scenario_ids_sha256(scenario_ids: Sequence[str]) -> str:
    payload = "".join(f"{scenario_id}\n" for scenario_id in sorted(scenario_ids))
    return hashlib.sha256(payload.encode()).hexdigest()


def _decimal(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise PartitionAuditError(f"{label}: expected a finite decimal number")
    try:
        result = Decimal(str(value))
    except Exception as exc:
        raise PartitionAuditError(f"{label}: invalid decimal number") from exc
    if not result.is_finite():
        raise PartitionAuditError(f"{label}: expected a finite decimal number")
    return result


def _normalized_attacker(value: Any) -> str | None:
    return None if value in (None, "", "none", "na", "not_applicable") else str(value)


def _selector_matches(row: Mapping[str, Any], selector: Mapping[str, Any]) -> bool:
    return all(
        (
            _normalized_attacker(row.get(key))
            if key == "attacker_class"
            else row.get(key)
        )
        == value
        for key, value in selector.items()
    )


def _load_manifest(
    path: Path,
    *,
    expected_holders: int,
    expected_weight_sum: Decimal,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Decimal]]:
    try:
        with path.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PartitionAuditError(f"cannot load manifest {path}") from exc
    if not isinstance(manifest, dict):
        raise PartitionAuditError("manifest must be a JSON object")

    declared_sha = manifest.get("manifest_sha256")
    actual_sha = canonical_manifest_sha256(manifest)
    if declared_sha != actual_sha:
        raise PartitionAuditError("manifest canonical SHA-256 mismatch")

    units = manifest.get("selected_units")
    if not isinstance(units, list) or len(units) != expected_holders:
        raise PartitionAuditError(
            f"expected {expected_holders} selected units, found "
            f"{len(units) if isinstance(units, list) else 'no list'}"
        )
    units_by_id: dict[str, dict[str, Any]] = {}
    holders: set[int] = set()
    weights: dict[str, Decimal] = {}
    strata: Counter[str] = Counter()
    for item in units:
        if not isinstance(item, dict):
            raise PartitionAuditError("selected unit must be a JSON object")
        unit_id = item.get("unit_id")
        holder = item.get("holder_asn")
        if not isinstance(unit_id, str) or not unit_id:
            raise PartitionAuditError("selected unit has invalid unit_id")
        if unit_id in units_by_id:
            raise PartitionAuditError(f"duplicate selected unit {unit_id}")
        if isinstance(holder, bool) or not isinstance(holder, int) or holder in holders:
            raise PartitionAuditError(f"{unit_id}: invalid or duplicate holder_asn")
        frame_size = item.get("N_h", item.get("stratum_population_N_h"))
        sample_size = item.get("n_h", item.get("stratum_sample_n_h"))
        if (
            isinstance(frame_size, bool)
            or not isinstance(frame_size, int)
            or isinstance(sample_size, bool)
            or not isinstance(sample_size, int)
            or frame_size <= 0
            or sample_size <= 0
        ):
            raise PartitionAuditError(f"{unit_id}: invalid N_h/n_h")
        weight = _decimal(item.get("design_weight"), f"{unit_id}/design_weight")
        if weight != Decimal(frame_size) / Decimal(sample_size):
            raise PartitionAuditError(f"{unit_id}: design weight is not N_h/n_h")
        units_by_id[unit_id] = item
        holders.add(holder)
        weights[unit_id] = weight
        strata[str(item.get("holder_stratum"))] += 1

    for unit_id, item in units_by_id.items():
        stratum = str(item.get("holder_stratum"))
        sample_size = int(item.get("n_h", item.get("stratum_sample_n_h")))
        if strata[stratum] != sample_size:
            raise PartitionAuditError(
                f"{stratum}: observed {strata[stratum]} units but n_h={sample_size}"
            )
    weight_sum = sum(weights.values(), Decimal(0))
    if weight_sum != expected_weight_sum:
        raise PartitionAuditError(
            f"design-weight sum {weight_sum} != expected {expected_weight_sum}"
        )

    plan = manifest.get("trial_plan")
    if not isinstance(plan, list) or not plan:
        raise PartitionAuditError("manifest must contain a nonempty trial_plan")
    plan_by_id: dict[str, dict[str, Any]] = {}
    for item in plan:
        if not isinstance(item, dict):
            raise PartitionAuditError("trial_plan entry must be a JSON object")
        scenario_id = item.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise PartitionAuditError("trial_plan entry has invalid scenario_id")
        if scenario_id in plan_by_id:
            raise PartitionAuditError(f"duplicate planned scenario {scenario_id}")
        if item.get("unit_id") not in units_by_id:
            raise PartitionAuditError(f"{scenario_id}: unknown planned unit")
        plan_by_id[scenario_id] = item

    expected = manifest.get("expected_scenario_ids")
    if not isinstance(expected, dict):
        raise PartitionAuditError("manifest lacks expected_scenario_ids metadata")
    if expected.get("count") != len(plan_by_id):
        raise PartitionAuditError("expected scenario count does not match trial_plan")
    if expected.get("sorted_newline_sha256") != _scenario_ids_sha256(tuple(plan_by_id)):
        raise PartitionAuditError("expected scenario-ID SHA-256 mismatch")
    return manifest, plan_by_id, weights


def _destination_fraction(
    row: Mapping[str, Any], scenario_id: str
) -> dict[str, Fraction]:
    outcomes = row.get("outcomes")
    all_as = outcomes.get("all") if isinstance(outcomes, Mapping) else None
    if not isinstance(all_as, Mapping):
        raise PartitionAuditError(f"{scenario_id}: missing outcomes/all")
    denominator = all_as.get("denominator_asns")
    destination = all_as.get("destination")
    counts = destination.get("counts") if isinstance(destination, Mapping) else None
    if (
        isinstance(denominator, bool)
        or not isinstance(denominator, int)
        or denominator <= 0
        or not isinstance(counts, Mapping)
        or set(counts) != set(DESTINATIONS)
    ):
        raise PartitionAuditError(f"{scenario_id}: malformed all-AS destination")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in counts.values()
    ):
        raise PartitionAuditError(f"{scenario_id}: invalid destination count")
    if sum(counts.values()) != denominator:
        raise PartitionAuditError(
            f"{scenario_id}: destination counts do not sum to denominator"
        )
    fractions = {
        outcome: Fraction(int(counts[outcome]), denominator) for outcome in DESTINATIONS
    }
    if sum(fractions.values(), Fraction(0)) != Fraction(1):
        raise PartitionAuditError(
            f"{scenario_id}: recomputed partition does not sum to 1"
        )

    stored = destination.get("fractions")
    if not isinstance(stored, Mapping) or set(stored) != set(DESTINATIONS):
        raise PartitionAuditError(f"{scenario_id}: malformed stored fractions")
    for outcome, fraction in fractions.items():
        value = _decimal(stored[outcome], f"{scenario_id}/{outcome}/fraction")
        exact_decimal = Decimal(fraction.numerator) / Decimal(fraction.denominator)
        if abs(value - exact_decimal) > Decimal("1e-12"):
            raise PartitionAuditError(
                f"{scenario_id}/{outcome}: stored fraction disagrees with counts"
            )
    return fractions


def _json_number(value: Decimal | Fraction) -> int | float:
    if isinstance(value, Fraction):
        return value.numerator if value.denominator == 1 else float(value)
    integral = value.to_integral_value()
    return int(integral) if value == integral else float(value)


def audit(
    manifest_path: Path,
    results_path: Path,
    *,
    expected_holders: int = EXPECTED_HOLDERS,
    expected_weight_sum: Decimal = EXPECTED_WEIGHT_SUM,
) -> dict[str, Any]:
    """Run the audit and return a deterministic JSON-compatible object."""

    manifest, plan_by_id, weights = _load_manifest(
        manifest_path,
        expected_holders=expected_holders,
        expected_weight_sum=expected_weight_sum,
    )
    manifest_sha = str(manifest["manifest_sha256"])
    units = {str(item["unit_id"]): item for item in manifest["selected_units"]}
    selected: dict[str, dict[str, dict[str, Fraction]]] = {
        cell: {} for cell in CELL_SELECTORS
    }
    seen_ids: set[str] = set()
    row_count = 0

    try:
        handle = results_path.open(encoding="utf-8")
    except OSError as exc:
        raise PartitionAuditError(f"cannot open results {results_path}") from exc
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row_count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PartitionAuditError(
                    f"{results_path}:{line_number}: invalid JSON"
                ) from exc
            if not isinstance(row, dict):
                raise PartitionAuditError(f"line {line_number}: row is not an object")
            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or scenario_id not in plan_by_id:
                raise PartitionAuditError(f"line {line_number}: unknown scenario_id")
            if scenario_id in seen_ids:
                raise PartitionAuditError(f"duplicate result scenario {scenario_id}")
            seen_ids.add(scenario_id)
            if row.get("status") != "success" or row.get("attempt") != 1:
                raise PartitionAuditError(f"{scenario_id}: not attempt-1 success")
            if row.get("manifest_sha256") != manifest_sha:
                raise PartitionAuditError(f"{scenario_id}: manifest SHA-256 mismatch")

            planned = plan_by_id[scenario_id]
            for field in PLAN_FIELDS:
                actual = (
                    _normalized_attacker(row.get(field))
                    if field == "attacker_class"
                    else row.get(field)
                )
                expected = (
                    _normalized_attacker(planned.get(field))
                    if field == "attacker_class"
                    else planned.get(field)
                )
                if actual != expected:
                    raise PartitionAuditError(
                        f"{scenario_id}: {field} differs from plan"
                    )

            unit_id = str(row.get("unit_id"))
            unit = units[unit_id]
            if row.get("holder_asn") != unit.get("holder_asn"):
                raise PartitionAuditError(
                    f"{scenario_id}: holder differs from manifest"
                )
            if (
                _decimal(row.get("design_weight"), f"{scenario_id}/design_weight")
                != weights[unit_id]
            ):
                raise PartitionAuditError(
                    f"{scenario_id}: weight differs from manifest"
                )
            fractions = _destination_fraction(row, scenario_id)

            for cell, selector in CELL_SELECTORS.items():
                if _selector_matches(row, selector):
                    if unit_id in selected[cell]:
                        raise PartitionAuditError(f"{cell}: duplicate unit {unit_id}")
                    selected[cell][unit_id] = fractions

    missing = set(plan_by_id) - seen_ids
    if missing or len(seen_ids) != len(plan_by_id):
        raise PartitionAuditError(
            f"result scenario set mismatch: missing={len(missing)}, "
            f"actual={len(seen_ids)}, planned={len(plan_by_id)}"
        )

    aggregates: dict[str, dict[str, Fraction]] = {}
    cell_output: dict[str, Any] = {}
    for cell, selector in CELL_SELECTORS.items():
        by_unit = selected[cell]
        if set(by_unit) != set(units):
            raise PartitionAuditError(
                f"{cell}: expected every selected unit once; got {len(by_unit)}"
            )
        weighted = {
            outcome: sum(
                (
                    Fraction(weights[unit_id]) * by_unit[unit_id][outcome]
                    for unit_id in units
                ),
                Fraction(0),
            )
            / Fraction(expected_weight_sum)
            for outcome in DESTINATIONS
        }
        aggregate_sum = sum(weighted.values(), Fraction(0))
        if aggregate_sum != Fraction(1):
            raise PartitionAuditError(f"{cell}: weighted partition does not sum to 1")
        aggregates[cell] = weighted
        cell_output[cell] = {
            "design_weight_sum": _json_number(expected_weight_sum),
            "holders": len(by_unit),
            "partition": {
                outcome: _json_number(weighted[outcome]) for outcome in DESTINATIONS
            },
            "partition_sum": _json_number(aggregate_sum),
            "selector": selector,
        }

    a1 = aggregates["a1_open_uniform_competition_100"]["attacker"]
    b1 = aggregates["b1_uniform_competition"]["attacker"]
    b2 = aggregates["b2_exact_uniform_competition"]["attacker"]
    return {
        "audit_version": AUDIT_VERSION,
        "cells": cell_output,
        "contrasts_percentage_points": {
            "a1_100_minus_b1_uniform_attacker_exposure": _json_number((a1 - b1) * 100),
            "a1_100_minus_b2_exact_uniform_attacker": _json_number((a1 - b2) * 100),
        },
        "inputs_sha256": {
            "manifest_file": sha256_file(manifest_path),
            "manifest_frozen_canonical": manifest_sha,
            "raw_scenarios": sha256_file(results_path),
        },
        "validation": {
            "all_rows_attempt_1_success": True,
            "all_rows_destination_partition_sum_1": True,
            "all_weighted_aggregate_partition_sum_1": True,
            "design_weight_sum": _json_number(expected_weight_sum),
            "holders_unique": len(units),
            "raw_rows": row_count,
            "scenario_ids_exactly_match_frozen_plan": True,
            "selected_cell_rows": sum(len(value) for value in selected.values()),
            "stored_fractions_match_recomputed_counts": True,
        },
    }


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(rendered, encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = audit(args.manifest, args.results)
    write_json(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
