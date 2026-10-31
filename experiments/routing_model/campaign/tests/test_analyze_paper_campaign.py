"""Tests for holder-level routing-model campaign analysis."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from experiments.routing_model.campaign.analyze_paper_campaign import (
    A1_OPEN_COMPETITION,
    ATTACKER_CLASSES,
    B1_COMPETITION,
    B1_DELEGATE,
    B2_COMPETITION,
    B2_DELEGATE,
    D1_OPEN_DELEGATE,
    DEPLOYMENT_PERCENTAGES,
    AnalysisDesign,
    CampaignAnalysisError,
    analyze_campaign,
    canonical_manifest_sha256,
    expected_scenario_ids,
    validate_expected_scenario_ids,
    validate_execution_contract,
    validate_partitions,
    validate_rows_against_trial_plan,
    validate_zero_equivalence,
    weighted_quantile,
    write_outputs,
)


def _population_outcomes(
    delegate_fraction: float, attacker_fraction: float
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for population, denominator in (("all", 1000), ("rov", 400), ("non_rov", 600)):
        delegate = round(delegate_fraction * denominator)
        attacker = round(attacker_fraction * denominator)
        child = {
            "delegate": delegate,
            "attacker": attacker,
            "absent": denominator - delegate - attacker,
        }
        destination = {
            "delegate": delegate,
            "attacker": attacker,
            "holder_fallback": denominator - delegate - attacker,
            "disconnected": 0,
            "loop": 0,
        }
        result[population] = {
            "denominator_asns": denominator,
            "child": {
                "counts": child,
                "fractions": {key: value / denominator for key, value in child.items()},
            },
            "destination": {
                "counts": destination,
                "fractions": {
                    key: value / denominator for key, value in destination.items()
                },
            },
        }
    return result


def _fixture() -> tuple[list[dict[str, Any]], dict[str, Any], AnalysisDesign]:
    frame_sizes = {"S1": 4, "S2": 6, "S3": 8, "S4": 10}
    units: list[dict[str, Any]] = []
    for stratum_index, stratum in enumerate(frame_sizes, start=1):
        for within in range(2):
            holder = stratum_index * 100 + within
            pair_index = len(units) + 1
            units.append(
                {
                    "unit_id": f"unit{pair_index:04d}",
                    "pair_index": pair_index,
                    "holder_asn": holder,
                    "root_prefix": f"10.{pair_index}.0.0/16",
                    "leaf_prefix": f"10.{pair_index}.1.0/24",
                    "delegate_asn": 10_000 + pair_index,
                    "holder_stratum": stratum,
                    "N_h": frame_sizes[stratum],
                    "n_h": 2,
                    "design_weight": frame_sizes[stratum] / 2,
                    "uniform_attacker_asn": 20_000 + pair_index,
                    "edge_attacker_asn": 30_000 + pair_index,
                    "high_degree_attacker_asn": 40_000 + pair_index,
                }
            )

    topology_asns = 1000
    fixed_rov = tuple(range(1, 401))
    order_sequences = {
        "degree": fixed_rov,
        "customer_cone": tuple(reversed(fixed_rov)),
        **{
            f"random_{seed:02d}": fixed_rov[seed:] + fixed_rov[:seed]
            for seed in range(1, 6)
        },
    }
    deployment_orders = []
    for order_id, asns in order_sequences.items():
        strategy = "random" if order_id.startswith("random_") else order_id
        seed = int(order_id[-2:]) if strategy == "random" else None
        deployment_orders.append(
            {
                "order_id": order_id,
                "strategy": strategy,
                "seed": seed,
                "asns": list(asns),
                "order_sha256": hashlib.sha256(
                    "\n".join(str(asn) for asn in asns).encode()
                ).hexdigest(),
                "deployment_counts": {
                    str(percent): (
                        len(fixed_rov)
                        if percent == 100
                        else int(len(fixed_rov) * percent / 100)
                    )
                    for percent in DEPLOYMENT_PERCENTAGES
                },
            }
        )
    orders_by_id = {order["order_id"]: order for order in deployment_orders}

    def set_hash(asns: Any) -> str:
        return hashlib.sha256(
            ("\n".join(str(asn) for asn in sorted(asns)) + "\n").encode()
        ).hexdigest()

    rows: list[dict[str, Any]] = []
    counter = 0

    def add(
        unit: dict[str, Any],
        lane: str,
        outcomes: dict[str, dict[str, Any]],
        *,
        attacker_class: str = "not_applicable",
        percent: int = 0,
        strategy: str = "reference",
        seed: int | None = None,
    ) -> None:
        nonlocal counter
        counter += 1
        normalized_class = (
            None if attacker_class == "not_applicable" else attacker_class
        )
        if strategy == "random":
            order_id = f"random_{int(seed):02d}"
        elif strategy == "cone":
            order_id = "customer_cone"
        elif strategy == "degree":
            order_id = "degree"
        else:
            order_id = None
        if lane in {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}:
            deployment_count = (
                len(fixed_rov)
                if percent == 100
                else int(len(fixed_rov) * percent / 100)
            )
        else:
            deployment_count = 0
        if deployment_count == 0:
            deployed_asns: Any = ()
        elif percent == 100:
            deployed_asns = fixed_rov
        else:
            deployed_asns = orders_by_id[str(order_id)]["asns"][:deployment_count]
        rows.append(
            {
                "schema_version": 1,
                "status": "success",
                "scenario_id": f"scenario-{counter:05d}",
                "manifest_sha256": None,
                "unit_id": unit["unit_id"],
                "pair_index": unit["pair_index"],
                "holder_asn": unit["holder_asn"],
                "root_prefix": unit["root_prefix"],
                "leaf_prefix": unit["leaf_prefix"],
                "delegate_asn": unit["delegate_asn"],
                "attacker_asn": (
                    None
                    if normalized_class is None
                    else unit[f"{normalized_class}_attacker_asn"]
                ),
                "holder_stratum": unit["holder_stratum"],
                "N_h": unit["N_h"],
                "n_h": unit["n_h"],
                "design_weight": unit["design_weight"],
                "lane": lane,
                "attacker_class": attacker_class,
                "deployment_strategy": strategy,
                "deployment_seed": seed,
                "deployment_percent_target": percent,
                "deployment_count": deployment_count,
                "deployment_fraction_actual": deployment_count / len(fixed_rov),
                "order_id": order_id,
                "order_sha256": (
                    None if order_id is None else orders_by_id[order_id]["order_sha256"]
                ),
                "deployment_set_sha256": set_hash(deployed_asns),
                "fixed_rov_count": len(fixed_rov),
                "policy_assignment_counts": {
                    "bgp": topology_asns - len(fixed_rov),
                    "rov": len(fixed_rov) - deployment_count,
                    "s2rov": deployment_count,
                },
                "outcomes": deepcopy(outcomes),
            }
        )

    random_offsets = {1: -0.02, 2: -0.01, 3: 0.0, 4: 0.01, 5: 0.02}
    for unit in units:
        stratum_index = int(unit["holder_stratum"][1:])
        b1_delegate = _population_outcomes(0.20, 0.0)
        b2_delegate = _population_outcomes(0.40, 0.0)
        add(unit, B1_DELEGATE, b1_delegate)
        add(unit, B2_DELEGATE, b2_delegate)
        for attacker_index, attacker_class in enumerate(ATTACKER_CLASSES):
            b1_attacker = 0.10 + 0.01 * attacker_index
            add(
                unit,
                B1_COMPETITION,
                _population_outcomes(0.20, b1_attacker),
                attacker_class=attacker_class,
            )
            add(
                unit,
                B2_COMPETITION,
                _population_outcomes(0.20, 0.02),
                attacker_class=attacker_class,
            )

        for percent in DEPLOYMENT_PERCENTAGES:
            if percent in {0, 100}:
                staged_orders = (("shared", None),)
            else:
                staged_orders = (
                    ("degree", None),
                    ("cone", None),
                    *(("random", seed) for seed in range(1, 6)),
                )
            for strategy, seed in staged_orders:
                if percent == 0:
                    d1_outcomes = b1_delegate
                elif percent == 100:
                    d1_outcomes = _population_outcomes(0.40, 0.0)
                else:
                    effect = 0.02 * stratum_index + 0.001 * percent
                    if strategy == "random":
                        effect += random_offsets[int(seed)]
                    elif strategy == "cone":
                        effect += 0.01
                    d1_outcomes = _population_outcomes(0.20 + effect, 0.0)
                add(
                    unit,
                    D1_OPEN_DELEGATE,
                    d1_outcomes,
                    percent=percent,
                    strategy=strategy,
                    seed=seed,
                )

                for attacker_index, attacker_class in enumerate(ATTACKER_CLASSES):
                    b1_attacker = 0.10 + 0.01 * attacker_index
                    if percent == 0:
                        a1_outcomes = _population_outcomes(0.20, b1_attacker)
                    elif percent == 100:
                        a1_outcomes = _population_outcomes(0.20, 0.30)
                    else:
                        effect = 0.01 * stratum_index + 0.001 * percent
                        if strategy == "random":
                            effect += random_offsets[int(seed)]
                        elif strategy == "cone":
                            effect += 0.01
                        a1_outcomes = _population_outcomes(0.20, b1_attacker + effect)
                    add(
                        unit,
                        A1_OPEN_COMPETITION,
                        a1_outcomes,
                        attacker_class=attacker_class,
                        percent=percent,
                        strategy=strategy,
                        seed=seed,
                    )

    plan_fields = (
        "scenario_id",
        "unit_id",
        "pair_index",
        "holder_asn",
        "lane",
        "attacker_class",
        "deployment_strategy",
        "deployment_seed",
        "deployment_percent_target",
        "order_id",
    )
    trial_plan = [{key: row[key] for key in plan_fields} for row in rows]
    scenario_ids = sorted(row["scenario_id"] for row in rows)
    manifest = {
        "schema_version": 1,
        "status": "planned_not_executed",
        "selected_units": units,
        "deployment_orders": deployment_orders,
        "topology": {
            "asns": topology_asns,
            "fixed_rov_asns": list(fixed_rov),
            "fixed_rov_count": len(fixed_rov),
        },
        "trial_plan": trial_plan,
        "expected_scenario_ids": {
            "count": len(scenario_ids),
            "sorted_newline_sha256": hashlib.sha256(
                ("\n".join(scenario_ids) + "\n").encode()
            ).hexdigest(),
        },
    }
    manifest["manifest_sha256"] = canonical_manifest_sha256(manifest)
    for row in rows:
        row["manifest_sha256"] = manifest["manifest_sha256"]
    return rows, manifest, AnalysisDesign()


def test_analysis_averages_random_orders_before_holder_bootstrap() -> None:
    rows, manifest, design = _fixture()
    contrasts, summary, validation = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=200,
        bootstrap_seed=9,
        expected_holders=8,
        strict_production_strata=False,
        design=design,
    )

    target = next(
        item
        for item in summary
        if item["estimand"] == "Delta_R"
        and item["metric_level"] == "destination"
        and item["population"] == "all"
        and item["deployment_strategy"] == "random"
        and item["deployment_percent_target"] == 5
    )
    target_contrasts = [
        item
        for item in contrasts
        if item["estimand"] == "Delta_R"
        and item["metric_level"] == "destination"
        and item["population"] == "all"
        and item["deployment_strategy"] == "random"
        and item["deployment_percent_target"] == 5
    ]

    assert len(target_contrasts) == 8
    assert {item["random_orders_averaged"] for item in target_contrasts} == {5}
    assert target["n_holders"] == 8
    assert target["n_ases_as_independent_units"] == 0
    assert target["n_random_orders_as_independent_units"] == 0
    assert target["random_seed_count"] == 5
    assert target["random_seed_delta_min"] < target["random_seed_delta_max"]
    assert target["raw_treatment_design_weighted_mean"] - target[
        "raw_reference_design_weighted_mean"
    ] == pytest.approx(target["paired_delta_design_weighted_mean"])
    assert validation["n_independent_holders"] == 8
    assert validation["checks"]["random_orders_averaged_within_holder_first"]
    assert validation["checks"]["srswor_finite_population_rescaling"]
    assert validation["bootstrap"]["rescaled_count_formula"].startswith(
        "c_hi=1+a_h*(m_hi-1)"
    )
    assert validation["bootstrap"]["interval"] == (
        "pointwise rescaled-bootstrap percentile 95%"
    )
    assert validation["expected_summary_cells"] == 1152
    assert len(summary) == 1152
    assert {item["metric_level"] for item in summary} == {"destination", "child"}


def test_bootstrap_is_deterministic_and_stratified() -> None:
    rows, manifest, design = _fixture()
    first = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=80,
        bootstrap_seed=123,
        expected_holders=8,
        strict_production_strata=False,
        design=design,
    )[1]
    second = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=80,
        bootstrap_seed=123,
        expected_holders=8,
        strict_production_strata=False,
        design=design,
    )[1]

    assert first == second
    assert all(
        item["ci_type"] == "pointwise_stratified_paired_rescaled_percentile_srswor_fpc"
        for item in first
    )


def test_expected_id_validator_rejects_duplicate_missing_and_unexpected() -> None:
    rows, manifest, _ = _fixture()
    expected_ids = expected_scenario_ids(manifest)
    with pytest.raises(CampaignAnalysisError, match="duplicate result"):
        validate_expected_scenario_ids([*rows, rows[0]], expected_ids)
    with pytest.raises(CampaignAnalysisError, match="scenario-ID mismatch"):
        validate_expected_scenario_ids(rows[:-1], expected_ids)
    unexpected = deepcopy(rows)
    unexpected[-1]["scenario_id"] = "unexpected"
    with pytest.raises(CampaignAnalysisError, match="scenario-ID mismatch"):
        validate_expected_scenario_ids(unexpected, expected_ids)


def test_partition_validator_rejects_nonadditive_population() -> None:
    rows, _, _ = _fixture()
    broken = deepcopy(rows[0])
    broken["outcomes"]["all"]["destination"]["counts"]["delegate"] += 1
    broken["outcomes"]["all"]["destination"]["counts"]["holder_fallback"] -= 1
    broken["outcomes"]["all"]["destination"]["fractions"]["delegate"] += 0.001
    broken["outcomes"]["all"]["destination"]["fractions"]["holder_fallback"] -= 0.001

    with pytest.raises(CampaignAnalysisError, match=r"all != rov \+ non_rov"):
        validate_partitions([broken])


def test_zero_equivalence_validator_rejects_mismatched_announcements() -> None:
    rows, _, _ = _fixture()
    staged_zero = next(
        row
        for row in rows
        if row["lane"] == D1_OPEN_DELEGATE and row["deployment_percent_target"] == 0
    )
    staged_zero["outcomes"] = _population_outcomes(0.21, 0.0)

    with pytest.raises(CampaignAnalysisError, match="zero cell differs"):
        validate_zero_equivalence(rows)


def test_analysis_rejects_unknown_lane_even_when_ids_and_row_count_match() -> None:
    rows, manifest, design = _fixture()
    for row in rows:
        if (
            row["lane"] == D1_OPEN_DELEGATE
            and row["deployment_strategy"] == "degree"
            and row["deployment_percent_target"] == 1
        ):
            row["lane"] = "UNKNOWN_LANE"

    with pytest.raises(CampaignAnalysisError, match="unknown campaign lane"):
        analyze_campaign(
            rows,
            manifest,
            bootstrap_replicates=10,
            expected_holders=8,
            strict_production_strata=False,
            design=design,
        )


def test_analysis_binds_row_metadata_to_scenario_id_plan() -> None:
    rows, manifest, design = _fixture()
    target = next(
        row
        for row in rows
        if row["lane"] == A1_OPEN_COMPETITION
        and row["attacker_class"] == "edge"
        and row["deployment_strategy"] == "random"
        and row["deployment_seed"] == 3
        and row["deployment_percent_target"] == 5
    )
    target["deployment_seed"] = 4

    with pytest.raises(CampaignAnalysisError, match="differs from frozen plan"):
        analyze_campaign(
            rows,
            manifest,
            bootstrap_replicates=10,
            expected_holders=8,
            strict_production_strata=False,
            design=design,
        )


def test_plan_binding_rejects_unit_identity_and_attacker_drift() -> None:
    rows, manifest, _ = _fixture()
    target = next(
        row
        for row in rows
        if row["lane"] == B1_COMPETITION and row["attacker_class"] == "uniform"
    )
    mutations = {
        "unit_id": "unit9999",
        "pair_index": int(target["pair_index"]) + 1,
        "root_prefix": "192.0.2.0/24",
        "leaf_prefix": "192.0.2.0/25",
        "holder_asn": int(target["holder_asn"]) + 1,
        "delegate_asn": int(target["delegate_asn"]) + 1,
        "attacker_asn": int(target["attacker_asn"]) + 1,
    }
    for field, bad_value in mutations.items():
        changed = deepcopy(target)
        changed[field] = bad_value
        with pytest.raises(CampaignAnalysisError):
            validate_rows_against_trial_plan([changed], manifest)


def test_execution_contract_rejects_set_hash_and_policy_count_drift() -> None:
    rows, manifest, design = _fixture()
    target = next(
        row
        for row in rows
        if row["lane"] == D1_OPEN_DELEGATE
        and row["deployment_strategy"] == "degree"
        and row["deployment_percent_target"] == 5
    )

    bad_hash = deepcopy(target)
    bad_hash["deployment_set_sha256"] = "0" * 64
    with pytest.raises(CampaignAnalysisError, match="manifest order prefix"):
        validate_execution_contract([bad_hash], manifest, design=design)

    bad_assignments = deepcopy(target)
    bad_assignments["policy_assignment_counts"]["s2rov"] += 1
    with pytest.raises(CampaignAnalysisError, match="policy assignments"):
        validate_execution_contract([bad_assignments], manifest, design=design)


def test_weighted_quantile_and_output_contract(tmp_path: Path) -> None:
    assert weighted_quantile([0.0, 1.0, 2.0], [1.0, 3.0, 1.0], 0.5) == 1.0
    rows, manifest, design = _fixture()
    contrasts, summary, validation = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=20,
        expected_holders=8,
        strict_production_strata=False,
        design=design,
    )
    write_outputs(tmp_path, contrasts, summary, validation)

    assert (tmp_path / "holder_contrasts.jsonl").is_file()
    assert (tmp_path / "raw_cell_summary.json").is_file()
    assert (tmp_path / "raw_cell_summary.csv").is_file()
    assert (tmp_path / "analysis_manifest.json").is_file()
