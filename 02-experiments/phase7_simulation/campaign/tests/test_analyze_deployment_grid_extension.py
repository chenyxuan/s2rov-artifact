from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

from phase7_simulation.campaign import analyze_paper_campaign as base
from phase7_simulation.campaign.analyze_deployment_grid_extension import (
    A1,
    B1_COMPETITION,
    B1_DELEGATE,
    D1,
    EXTENSION_PERCENTAGES,
    FROZEN_PERCENTAGES,
    RANDOM_ORDERS,
    STRATUM_BOOTSTRAP_ORDER,
    GridExtensionAnalysisError,
    average_orders_within_unit,
    build_order_level_contrasts,
    summarize_curves,
    validate_and_anchor_frozen_intersections,
)


ROOT = Path(__file__).resolve().parents[3]


def _partition(denominator: int, outcome: str, count: int) -> dict[str, Any]:
    other = denominator - count
    child_counts = {"delegate": 0, "attacker": 0, "absent": denominator}
    destination_counts = {
        "delegate": 0,
        "attacker": 0,
        "holder_fallback": other,
        "disconnected": 0,
        "loop": 0,
    }
    destination_counts[outcome] = count
    return {
        "denominator_asns": denominator,
        "child": {
            "counts": child_counts,
            "fractions": {
                key: value / denominator for key, value in child_counts.items()
            },
        },
        "destination": {
            "counts": destination_counts,
            "fractions": {
                key: value / denominator for key, value in destination_counts.items()
            },
        },
    }


def _row(
    unit_id: str,
    lane: str,
    attacker: str | None,
    percent: int,
    order: str,
    outcome: str,
    count: int,
) -> dict[str, Any]:
    rov_count = count * 2 // 5
    non_rov_count = count - rov_count
    strategy = order if order in {"shared", "reference"} else "random"
    seed = (
        int(order.removeprefix("random_")) if order.startswith("random_") else None
    )
    return {
        "unit_id": unit_id,
        "lane": lane,
        "attacker_class": attacker,
        "deployment_percent_target": percent,
        "deployment_strategy": strategy,
        "deployment_seed": seed,
        "order_id": order if order.startswith("random_") else None,
        "deployment_count": percent,
        "scenario_id": f"{unit_id}:{lane}:{attacker}:{order}:{percent}",
        "outcomes": {
            "all": _partition(1_000, outcome, count),
            "rov": _partition(400, outcome, rov_count),
            "non_rov": _partition(600, outcome, non_rov_count),
        },
    }


def _fixture() -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[int, base.HolderDesign],
    dict[str, int],
]:
    holder_design: dict[int, base.HolderDesign] = {}
    unit_to_holder: dict[str, int] = {}
    for index, stratum in enumerate(("S1", "S1", "S2", "S2", "S3", "S3", "S4", "S4"), 1):
        holder_design[index] = base.HolderDesign(
            holder_asn=index,
            stratum=stratum,
            frame_size=4,
            sample_size=2,
            design_weight=2.0,
        )
        unit_to_holder[f"unit{index:04d}"] = index

    frozen: list[dict[str, Any]] = []
    extension: list[dict[str, Any]] = []
    for unit_id in unit_to_holder:
        frozen.extend(
            (
                _row(unit_id, B1_DELEGATE, None, 0, "reference", "delegate", 200),
                _row(
                    unit_id,
                    B1_COMPETITION,
                    "uniform",
                    0,
                    "reference",
                    "attacker",
                    100,
                ),
            )
        )
        for lane, attacker, outcome, baseline, slope in (
            (D1, None, "delegate", 200, 2),
            (A1, "uniform", "attacker", 100, 1),
        ):
            for percent in FROZEN_PERCENTAGES:
                orders = ("shared",) if percent in {0, 100} else RANDOM_ORDERS
                for order in orders:
                    offset = (
                        0 if order == "shared" else int(order.removeprefix("random_")) - 1
                    )
                    frozen.append(
                        _row(
                            unit_id,
                            lane,
                            attacker,
                            percent,
                            order,
                            outcome,
                            baseline + slope * percent + offset,
                        )
                    )
            for percent in EXTENSION_PERCENTAGES:
                for order in RANDOM_ORDERS:
                    offset = int(order.removeprefix("random_")) - 1
                    extension.append(
                        _row(
                            unit_id,
                            lane,
                            attacker,
                            percent,
                            order,
                            outcome,
                            baseline + slope * percent + offset,
                        )
                    )
    return frozen, extension, holder_design, unit_to_holder


def test_synthetic_fixture_preserves_orders_before_unit_average() -> None:
    frozen, extension, holder_design, unit_to_holder = _fixture()
    order_level = build_order_level_contrasts(
        frozen, extension, holder_design, unit_to_holder
    )
    unit_contrasts = average_orders_within_unit(order_level)
    summary, trajectories = summarize_curves(
        unit_contrasts,
        order_level,
        holder_design,
        bootstrap_replicates=50,
        bootstrap_seed=7,
    )

    assert len(order_level) == 8 * 2 * 11 * 5
    assert len(unit_contrasts) == 8 * 2 * 11
    assert len(summary) == 22
    assert len(trajectories) == 110

    d1_20 = next(
        row
        for row in summary
        if row["estimand"] == "Delta_R"
        and row["deployment_percent_target"] == 20
    )
    assert d1_20["paired_delta_design_weighted_mean"] == pytest.approx(0.042)
    assert d1_20["random_order_delta_min"] == pytest.approx(0.040)
    assert d1_20["random_order_delta_max"] == pytest.approx(0.044)
    assert d1_20["n_random_orders_as_independent_units"] == 0
    assert d1_20["finite_population_correction"] is True

    a1_20 = next(
        row
        for row in summary
        if row["estimand"] == "Delta_E_rov"
        and row["deployment_percent_target"] == 20
    )
    assert a1_20["paired_delta_design_weighted_mean"] == pytest.approx(0.022)
    assert a1_20["finite_population_correction"] is False
    assert "selected_unit_stability" in a1_20["interval_type"]

    d1_zero = next(
        row
        for row in summary
        if row["estimand"] == "Delta_R"
        and row["deployment_percent_target"] == 0
    )
    assert d1_zero["random_order_delta_min"] == d1_zero["random_order_delta_max"]


def test_missing_order_fails_before_unit_average() -> None:
    frozen, extension, holder_design, unit_to_holder = _fixture()
    order_level = build_order_level_contrasts(
        frozen, extension, holder_design, unit_to_holder
    )
    incomplete = [
        row
        for row in order_level
        if not (
            row["unit_id"] == "unit0001"
            and row["estimand"] == "Delta_R"
            and row["deployment_percent_target"] == 20
            and row["deployment_order"] == "random_05"
        )
    ]
    with pytest.raises(GridExtensionAnalysisError, match="exactly five orders"):
        average_orders_within_unit(incomplete)


def test_frozen_intersection_tables_are_hash_bound_and_exactly_anchored() -> None:
    phase7_path = (
        ROOT
        / "phase7_simulation/results/paper_campaign/analysis/raw_cell_summary.csv"
    )
    phase9_path = ROOT / "phase9_selected_unit_reanalysis/results/competition_cells.csv"
    with phase7_path.open(newline="", encoding="utf-8") as handle:
        phase7 = [
            row
            for row in csv.DictReader(handle)
            if row["estimand"] == "Delta_R"
            and row["metric_level"] == "destination"
            and row["population"] == "all"
            and row["attacker_class"] == ""
            and row["deployment_strategy"] == "random"
            and int(row["deployment_percent_target"]) in FROZEN_PERCENTAGES
        ]
    with phase9_path.open(newline="", encoding="utf-8") as handle:
        phase9 = [
            row
            for row in csv.DictReader(handle)
            if row["estimand"] == "Delta_E_rov"
            and row["metric_level"] == "destination"
            and row["population"] == "all"
            and row["attacker_class"] == "uniform"
            and row["deployment_strategy"] == "random"
            and int(row["deployment_percent_target"]) in FROZEN_PERCENTAGES
        ]

    summary: list[dict[str, Any]] = []
    for row in phase7:
        summary.append(
            {
                "estimand": "Delta_R",
                "deployment_percent_target": int(row["deployment_percent_target"]),
                "paired_delta_design_weighted_mean": float(
                    row["paired_delta_design_weighted_mean"]
                )
                + 1e-16,
                "paired_delta_pp": 0.0,
                "treatment_design_weighted_mean": float(
                    row["raw_treatment_design_weighted_mean"]
                ),
                "reference_design_weighted_mean": float(
                    row["raw_reference_design_weighted_mean"]
                ),
                "pointwise_interval95_lower": float(row["pointwise_ci95_lower"]),
                "pointwise_interval95_upper": float(row["pointwise_ci95_upper"]),
                "pointwise_interval95_lower_pp": 0.0,
                "pointwise_interval95_upper_pp": 0.0,
            }
        )
    for row in phase9:
        summary.append(
            {
                "estimand": "Delta_E_rov",
                "deployment_percent_target": int(row["deployment_percent_target"]),
                "paired_delta_design_weighted_mean": float(
                    row["stratum_standardized_selected_unit_mean"]
                ),
                "paired_delta_pp": 0.0,
                "treatment_design_weighted_mean": float(
                    row["raw_treatment_stratum_standardized_mean"]
                ),
                "reference_design_weighted_mean": float(
                    row["raw_reference_stratum_standardized_mean"]
                ),
                "pointwise_interval95_lower": float(
                    row["resampling_interval95_lower"]
                ),
                "pointwise_interval95_upper": float(
                    row["resampling_interval95_upper"]
                ),
                "pointwise_interval95_lower_pp": 0.0,
                "pointwise_interval95_upper_pp": 0.0,
            }
        )

    audit = validate_and_anchor_frozen_intersections(
        summary,
        frozen_cell_summary_path=phase7_path,
        frozen_competition_cells_path=phase9_path,
    )
    assert audit["point_and_interval_values_exact_after_anchor"] is True
    assert audit["stratum_bootstrap_order"] == ["S1", "S2", "S3", "S4"]
    assert STRATUM_BOOTSTRAP_ORDER == ("S1", "S2", "S3", "S4")
    assert all(row["frozen_intersection_anchored"] is True for row in summary)
