"""Tests for deterministic worker-count benchmark validation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from experiments.routing_model.campaign.validate_benchmark import (
    A1_OPEN_COMPETITION,
    ATTACKER_CLASSES,
    B1_COMPETITION,
    B1_DELEGATE,
    D1_OPEN_DELEGATE,
    BenchmarkValidationError,
    compare_benchmarks,
    deterministic_outcome_fingerprint,
    validate_benchmark,
)


def _outcomes(delegate: int, attacker: int) -> dict[str, Any]:
    denominator = 10
    return {
        "all": {
            "denominator_asns": denominator,
            "child": {
                "counts": {
                    "delegate": delegate,
                    "attacker": attacker,
                    "absent": denominator - delegate - attacker,
                }
            },
            "destination": {
                "counts": {
                    "delegate": delegate,
                    "attacker": attacker,
                    "holder_fallback": denominator - delegate - attacker,
                    "disconnected": 0,
                    "loop": 0,
                }
            },
        }
    }


def _fixture(unit_count: int = 2) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_hash = "a" * 64
    units = [{"unit_id": f"unit{index:04d}"} for index in range(1, unit_count + 1)]
    plan: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []

    def add(
        unit_id: str,
        lane: str,
        outcomes: dict[str, Any],
        attacker_class: str | None = None,
    ) -> None:
        scenario_id = f"{unit_id}__{lane}__{attacker_class or 'none'}"
        plan.append(
            {
                "scenario_id": scenario_id,
                "unit_id": unit_id,
                "lane": lane,
                "attacker_class": attacker_class,
                "deployment_percent_target": 0,
            }
        )
        rows.append(
            {
                "schema_version": 1,
                "status": "success",
                "manifest_sha256": manifest_hash,
                "scenario_id": scenario_id,
                "unit_id": unit_id,
                "lane": lane,
                "attacker_class": attacker_class,
                "deployment_percent_target": 0,
                "outcomes": deepcopy(outcomes),
                "elapsed_seconds": 1.0,
                "worker_pid": 10,
            }
        )

    for unit in units:
        unit_id = unit["unit_id"]
        delegate = _outcomes(7, 0)
        add(unit_id, B1_DELEGATE, delegate)
        add(unit_id, D1_OPEN_DELEGATE, delegate)
        for offset, attacker_class in enumerate(ATTACKER_CLASSES, start=1):
            competition = _outcomes(5, offset)
            add(unit_id, B1_COMPETITION, competition, attacker_class)
            add(unit_id, A1_OPEN_COMPETITION, competition, attacker_class)

    manifest = {
        "schema_version": 1,
        "manifest_sha256": manifest_hash,
        "selected_units": units,
        "trial_plan": plan,
    }
    return manifest, rows


def test_complete_prefix_and_zero_equalities_are_verified() -> None:
    manifest, rows = _fixture()
    summary = validate_benchmark(manifest, rows)

    assert summary["status"] == "VERIFIED"
    assert summary["complete_prefix_units"] == 2
    assert summary["scenario_rows"] == 16
    assert summary["zero_percent_exact_equalities"] == 8


def test_fingerprint_ignores_order_timing_rss_and_worker_metadata() -> None:
    manifest, rows = _fixture()
    changed = deepcopy(list(reversed(rows)))
    for index, row in enumerate(changed):
        row["elapsed_seconds"] = 100 + index
        row["worker_pid"] = 999
        row["peak_rss_bytes"] = index
        row["worker_trial_sequence"] = 1000 - index

    assert deterministic_outcome_fingerprint(rows) == deterministic_outcome_fingerprint(
        changed
    )
    first = validate_benchmark(manifest, rows)
    second = validate_benchmark(manifest, changed)
    assert compare_benchmarks({"1": first, "16": second})["cross_worker_outcomes_equal"]


def test_incomplete_or_nonprefix_units_fail_closed() -> None:
    manifest, rows = _fixture()
    with pytest.raises(BenchmarkValidationError, match="incomplete"):
        validate_benchmark(manifest, rows[:-1])

    second_unit_only = [row for row in rows if row["unit_id"] == "unit0002"]
    with pytest.raises(BenchmarkValidationError, match="contiguous prefix"):
        validate_benchmark(manifest, second_unit_only)


def test_zero_equivalence_mismatch_fails_closed() -> None:
    manifest, rows = _fixture()
    target = next(
        row
        for row in rows
        if row["unit_id"] == "unit0001" and row["lane"] == D1_OPEN_DELEGATE
    )
    target["outcomes"] = _outcomes(6, 0)

    with pytest.raises(BenchmarkValidationError, match="B1 delegate and D1@0"):
        validate_benchmark(manifest, rows)


def test_cross_worker_comparison_rejects_different_outcomes() -> None:
    manifest, rows = _fixture()
    first = validate_benchmark(manifest, rows)
    second = deepcopy(first)
    second["outcome_fingerprint_sha256"] = "0" * 64

    with pytest.raises(BenchmarkValidationError, match="different deterministic"):
        compare_benchmarks({"1": first, "4": second})
