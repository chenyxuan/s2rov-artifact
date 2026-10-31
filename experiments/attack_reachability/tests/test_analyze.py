from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pytest

from attack_reachability import analyze, runner


@pytest.fixture(scope="module")
def units() -> tuple[runner.SiblingUnit, ...]:
    return runner.units_from_routing_model(runner.load_routing_model_manifest())


def test_weighted_quantile_is_left_continuous() -> None:
    assert analyze.weighted_quantile([3, 1, 2], [1, 1, 2], 0.5) == 2
    assert analyze.weighted_quantile([3, 1, 2], [1, 1, 2], 0.25) == 1
    with pytest.raises(ValueError):
        analyze.weighted_quantile([1], [0], 0.5)


def test_rescaled_bootstrap_preserves_each_stratum_total(
    units: tuple[runner.SiblingUnit, ...],
) -> None:
    holders = sorted(unit.holder_asn for unit in units)
    by_holder = {unit.holder_asn: unit for unit in units}
    weights = analyze.bootstrap_weight_matrix(
        holders, by_holder, replicates=128, seed=runner.BOOTSTRAP_SEED
    )
    assert np.all(weights > 0)
    for stratum in ("S1", "S2", "S3", "S4"):
        positions = [
            index
            for index, holder in enumerate(holders)
            if by_holder[holder].holder_stratum == stratum
        ]
        frame_size = by_holder[holders[positions[0]]].N_h
        assert np.allclose(weights[:, positions].sum(axis=1), frame_size)


def _analysis_outcomes(attacker_fraction: int) -> dict:
    outcomes = {}
    for population in runner.POPULATIONS:
        denominator = 10
        outcomes[population] = {
            "denominator_asns": denominator,
            "sibling_route": {
                "counts": {
                    "attacker": attacker_fraction * denominator,
                    "absent": (1 - attacker_fraction) * denominator,
                }
            },
            "sibling_destination": {
                "counts": {
                    "attacker": attacker_fraction * denominator,
                    "holder_fallback": (1 - attacker_fraction) * denominator,
                    "disconnected": 0,
                    "loop": 0,
                }
            },
            "leaf_route": {"counts": {"delegate": denominator, "absent": 0}},
            "leaf_destination": {
                "counts": {
                    "delegate": denominator,
                    "holder_fallback": 0,
                    "disconnected": 0,
                    "loop": 0,
                }
            },
        }
    return outcomes


def test_holder_paired_design_weighted_pipeline(
    units: tuple[runner.SiblingUnit, ...],
) -> None:
    rows = []
    for unit in units:
        for lane, percent in runner.LANE_PERCENTAGES:
            rows.append(
                {
                    "holder_asn": unit.holder_asn,
                    "lane": lane,
                    "deployment_percent_target": percent,
                    "outcomes": _analysis_outcomes(
                        int(lane == runner.A1_SIBLING and percent == 100)
                    ),
                }
            )
    contrasts = analyze.build_holder_contrasts(rows, units)
    assert len(contrasts) == 200 * 2 * 3 * 4
    summary = analyze.summarize(contrasts, units)
    primary = analyze.primary_cell(summary, "route")
    assert primary["independent_unit"] == "holder_asn"
    assert primary["n_holders"] == 200
    assert primary["design_weight_sum"] == pytest.approx(691)
    assert primary["paired_delta_design_weighted_mean"] == pytest.approx(1)
    assert primary["pointwise_ci95_lower"] == pytest.approx(1)
    assert primary["pointwise_ci95_upper"] == pytest.approx(1)


def test_scientific_digest_ignores_order_and_resource_metadata(
    units: tuple[runner.SiblingUnit, ...],
) -> None:
    base = {
        "scenario_id": "a",
        "manifest_sha256": "m",
        "unit_id": units[0].unit_id,
        "pair_index": units[0].pair_index,
        "holder_asn": units[0].holder_asn,
        "delegate_asn": units[0].delegate_asn,
        "attacker_asn": units[0].uniform_attacker_asn,
        "holder_stratum": units[0].holder_stratum,
        "design_weight": units[0].design_weight,
        "lane": runner.B1_SIBLING,
        "deployment_percent_target": 0,
        "deployment_count": 0,
        "deployment_set_sha256": runner.asn_set_sha256(()),
        "root_prefix": units[0].root_prefix,
        "leaf_prefix": units[0].leaf_prefix,
        "sibling_prefix": units[0].sibling_prefix,
        "policy_max_length": 24,
        "policy_assignment_counts": {"bgp": 1, "rov": 1, "s2rov": 0},
        "outcomes": {},
        "partition_checks": {},
        "elapsed_seconds": 1,
    }
    other = {**base, "scenario_id": "b", "elapsed_seconds": 99}
    digest = analyze.scientific_digest([base, other])
    assert digest == analyze.scientific_digest(
        [{**other, "elapsed_seconds": 0}, {**base, "elapsed_seconds": 2}]
    )
    assert digest != analyze.scientific_digest(
        [base, {**other, "deployment_set_sha256": "different"}]
    )


def test_leaf_mismatch_count_is_not_capped(
    monkeypatch, units: tuple[runner.SiblingUnit, ...]
) -> None:
    routing_model = {}
    rows = []
    role_cells = (
        (runner.B1_SIBLING, 0, "B1"),
        (runner.A1_SIBLING, 0, "A0"),
        (runner.A1_SIBLING, 100, "A100"),
    )
    for unit in units:
        for lane, percent, role in role_cells:
            reference_outcomes = {
                population: {
                    "child": {"counts": {"delegate": 1, "absent": 0, "attacker": 0}},
                    "destination": {
                        "counts": {
                            "delegate": 1,
                            "holder_fallback": 0,
                            "disconnected": 0,
                            "loop": 0,
                            "attacker": 0,
                        }
                    },
                }
                for population in runner.POPULATIONS
            }
            routing_model[(unit.holder_asn, role)] = {"outcomes": reference_outcomes}
            rows.append(
                {
                    "holder_asn": unit.holder_asn,
                    "lane": lane,
                    "deployment_percent_target": percent,
                    "outcomes": {
                        population: {
                            "leaf_route": {"counts": {"delegate": 0, "absent": 1}},
                            "leaf_destination": {
                                "counts": {
                                    "delegate": 0,
                                    "holder_fallback": 1,
                                    "disconnected": 0,
                                    "loop": 0,
                                }
                            },
                        }
                        for population in runner.POPULATIONS
                    },
                }
            )
    monkeypatch.setattr(analyze, "load_routing_model_leaf_references", lambda: routing_model)
    audit = analyze.leaf_invariance_audit(rows, units)
    assert audit["status"] == "failed"
    assert audit["mismatch_count"] == 600 * 3 * 2
    assert len(audit["mismatches_shown"]) == 20


def test_reproduction_requires_exact_independent_hash_match() -> None:
    with (
        TemporaryDirectory(dir=runner.ATTACK_REACHABILITY_ROOT) as first,
        TemporaryDirectory(dir=runner.ATTACK_REACHABILITY_ROOT) as second,
    ):
        reference = Path(first)
        candidate = Path(second)
        inputs = {
            "manifest_file_sha256": "manifest",
            "raw_results_file_sha256": "raw",
            "raw_results_scientific_sha256": "science",
            "routing_model_leaf_reference_sha256": "routing_model",
        }
        for directory in (reference, candidate):
            runner.atomic_write_json(
                directory / "analysis_manifest.json", {"inputs": inputs}
            )
            for name in analyze.REPRODUCTION_FILES:
                (directory / name).write_text(f"identical-{name}\n", encoding="utf-8")
        audit = analyze.verify_reproduction(reference, candidate)
        assert audit["status"] == "VERIFIED"
        persisted = json.loads(
            (reference / "reproduction_audit.json").read_text(encoding="utf-8")
        )
        assert persisted["reproduction_audit_sha256"] == runner.canonical_sha256(
            persisted, "reproduction_audit_sha256"
        )
        (candidate / "summary.csv").write_text("different\n", encoding="utf-8")
        with pytest.raises(analyze.AttackReachabilityAnalysisError, match="did not reproduce"):
            analyze.verify_reproduction(reference, candidate)
        failed = json.loads(
            (reference / "reproduction_audit.json").read_text(encoding="utf-8")
        )
        assert failed["status"] == "FAILED"
