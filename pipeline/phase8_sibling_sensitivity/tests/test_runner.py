from __future__ import annotations

import copy
import json
import os
from dataclasses import asdict
from ipaddress import ip_network
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from phase8_sibling_sensitivity import runner


@pytest.fixture(scope="module")
def parent() -> dict:
    return runner.load_phase7_manifest()


@pytest.fixture(scope="module")
def units(parent: dict) -> tuple[runner.SiblingUnit, ...]:
    return runner.units_from_phase7(parent)


@pytest.fixture(scope="module")
def manifest() -> dict:
    return runner.build_manifest()


def test_phase7_projection_and_sibling_geometry(
    parent: dict, units: tuple[runner.SiblingUnit, ...]
) -> None:
    assert len(units) == runner.EXPECTED_HOLDERS
    assert {unit.holder_stratum for unit in units} == {"S1", "S2", "S3", "S4"}
    assert all(
        sum(unit.holder_stratum == stratum for unit in units) == 50
        for stratum in ("S1", "S2", "S3", "S4")
    )
    for source, unit in zip(parent["selected_units"], units, strict=True):
        assert unit.unit_id == source["unit_id"]
        assert unit.holder_asn == source["holder_asn"]
        assert unit.uniform_attacker_asn == source["uniform_attacker_asn"]
        assert unit.design_weight == source["design_weight"]
        root = ip_network(unit.root_prefix)
        leaf = ip_network(unit.leaf_prefix)
        sibling = ip_network(unit.sibling_prefix)
        assert sibling.prefixlen == leaf.prefixlen
        assert sibling.supernet(prefixlen_diff=1) == leaf.supernet(prefixlen_diff=1)
        assert sibling.subnet_of(root)
        assert not sibling.overlaps(leaf)


def test_exact_600_plan_and_frozen_32_benchmark(
    units: tuple[runner.SiblingUnit, ...],
) -> None:
    trials, benchmark_ids = runner.build_trial_plan(units)
    assert len(trials) == 600
    assert len({trial.scenario_id for trial in trials}) == 600
    assert tuple(trial.scenario_id for trial in trials[:32]) == benchmark_ids
    cells_by_unit: dict[str, set[tuple[str, int]]] = {}
    for trial in trials:
        cells_by_unit.setdefault(trial.unit_id, set()).add(
            (trial.lane, trial.deployment_percent_target)
        )
    assert all(
        cells == set(runner.LANE_PERCENTAGES) for cells in cells_by_unit.values()
    )
    benchmark = trials[:32]
    unit_by_id = {unit.unit_id: unit for unit in units}
    assert {unit_by_id[trial.unit_id].holder_stratum for trial in benchmark} == {
        "S1",
        "S2",
        "S3",
        "S4",
    }
    assert {trial.lane for trial in benchmark} == {
        runner.B1_SIBLING,
        runner.A1_SIBLING,
    }
    assert {trial.deployment_percent_target for trial in benchmark} == {0, 100}


def test_manifest_binds_phase7_units_and_endpoint_sets(manifest: dict) -> None:
    runner.validate_manifest(manifest, verify_environment=False, verify_artifacts=True)
    assert manifest["topology"]["fixed_rov_set_sha256"] == runner.asn_set_sha256(
        manifest["topology"]["fixed_rov_asns"]
    )
    assert manifest["design"]["deployment_sets"] == {
        "0": {"count": 0, "asn_set_sha256": runner.asn_set_sha256(())},
        "100": {
            "count": 589,
            "asn_set_sha256": runner.asn_set_sha256(
                manifest["topology"]["fixed_rov_asns"]
            ),
        },
    }
    assert manifest["selected_units_canonical_sha256"] == (
        runner.canonical_records_sha256(manifest["selected_units"], key="unit_id")
    )


def test_rehashed_manifest_cannot_change_a_phase7_holder(manifest: dict) -> None:
    mutated = copy.deepcopy(manifest)
    mutated["selected_units"][0]["uniform_attacker_asn"] += 1
    mutated["selected_units_canonical_sha256"] = runner.canonical_records_sha256(
        mutated["selected_units"], key="unit_id"
    )
    mutated["manifest_sha256"] = runner.manifest_sha256(mutated)
    with pytest.raises(runner.Phase8ContractError, match="frozen Phase-7 selection"):
        runner.validate_manifest(
            mutated, verify_environment=False, verify_artifacts=False
        )


def _partition(outcomes: tuple[str, ...], denominator: int) -> dict:
    counts = {outcome: 0 for outcome in outcomes}
    counts[outcomes[0]] = denominator
    return {
        "counts": counts,
        "fractions": {
            outcome: count / denominator for outcome, count in counts.items()
        },
    }


def _valid_row(manifest: dict) -> tuple[dict, runner.SiblingTrial, runner.SiblingUnit]:
    trial = runner.SiblingTrial(**manifest["trial_plan"][0])
    unit = runner.SiblingUnit(
        **next(
            item
            for item in manifest["selected_units"]
            if item["unit_id"] == trial.unit_id
        )
    )
    deployment_count = 589 if trial.deployment_percent_target == 100 else 0
    denominators = {"all": 77429, "rov": 589, "non_rov": 76840}
    outcomes = {
        population: {
            "denominator_asns": denominator,
            **{
                partition: _partition(names, denominator)
                for partition, names in runner.PARTITION_OUTCOMES.items()
            },
        }
        for population, denominator in denominators.items()
    }
    checks = {
        f"{population}_{partition}_complete": True
        for population in runner.POPULATIONS
        for partition in runner.PARTITION_OUTCOMES
    }
    checks.update(
        {
            f"{partition}_{outcome}_all_equals_subgroups": True
            for partition, names in runner.PARTITION_OUTCOMES.items()
            for outcome in names
        }
    )
    checks["all_equals_rov_plus_non_rov"] = True
    row = {
        "schema_version": 1,
        "status": "success",
        "scenario_id": trial.scenario_id,
        "manifest_sha256": manifest["manifest_sha256"],
        **asdict(unit),
        "attacker_asn": unit.uniform_attacker_asn,
        "attacker_class": "uniform",
        "attacker_degree": unit.uniform_attacker_degree,
        "lane": trial.lane,
        "deployment_percent_target": trial.deployment_percent_target,
        "deployment_count": deployment_count,
        "deployment_fraction_actual": deployment_count / 589,
        "deployment_set_sha256": manifest["design"]["deployment_sets"][
            str(trial.deployment_percent_target)
        ]["asn_set_sha256"],
        "fixed_rov_count": 589,
        "sibling_relation": "other_child_of_leaf_immediate_parent",
        "policy_max_length": ip_network(unit.leaf_prefix).prefixlen,
        "leaf_da_state": "Delegated",
        "sibling_da_state": "Delegated",
        "policy_assignment_counts": {
            "bgp": 76840,
            "rov": 589 - deployment_count,
            "darov": deployment_count,
        },
        "outcomes": outcomes,
        "partition_checks": checks,
        "elapsed_seconds": 1.0,
        "peak_rss_bytes": 1,
        "worker_graph_build_peak_rss_bytes": 1,
        "worker_pid": 1,
        "worker_trial_sequence": 1,
        "worker_graph_build_seconds": 1.0,
        "rss_before_bytes": 1,
        "rss_after_bytes": 1,
        "attempt": 1,
        "prior_failure_count": 0,
        "retry_authorized": False,
    }
    return row, trial, unit


def test_result_validator_rejects_incomplete_partition(manifest: dict) -> None:
    row, trial, unit = _valid_row(manifest)
    runner.validate_result_row(row, trial, unit, manifest)
    bad = copy.deepcopy(row)
    bad["outcomes"]["rov"]["sibling_route"]["counts"]["attacker"] -= 1
    with pytest.raises(runner.Phase8ContractError, match="incomplete"):
        runner.validate_result_row(bad, trial, unit, manifest)


@pytest.mark.parametrize("invalid", [-1, 0.5, True, "0"])
def test_result_validator_rejects_non_count_values(
    manifest: dict, invalid: object
) -> None:
    row, trial, unit = _valid_row(manifest)
    counts = row["outcomes"]["rov"]["sibling_route"]["counts"]
    counts["attacker"] = invalid
    counts["absent"] = 589
    with pytest.raises(runner.Phase8ContractError, match="invalid count"):
        runner.validate_result_row(row, trial, unit, manifest)


def test_result_validator_rejects_endpoint_set_drift(manifest: dict) -> None:
    row, trial, unit = _valid_row(manifest)
    row["deployment_set_sha256"] = "0" * 64
    with pytest.raises(runner.Phase8ContractError, match="deployment_set_sha256"):
        runner.validate_result_row(row, trial, unit, manifest)


def test_resource_monitor_sampling_failure_is_fail_closed(monkeypatch) -> None:
    signals: list[tuple[int, int]] = []

    def fail_pid_provider() -> list[int]:
        raise OSError("synthetic /proc failure")

    monkeypatch.setattr(runner.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monitor = runner.ParentResourceMonitor(fail_pid_provider, interval_seconds=0)
    monitor._sample()
    assert monitor.breach_reason == (
        "resource monitor failed closed: OSError: synthetic /proc failure"
    )
    assert signals == [(os.getpid(), runner.signal.SIGUSR1)]


def test_initializer_failure_returns_one_failed_task(monkeypatch) -> None:
    def fail_manifest(*_args, **_kwargs):
        raise RuntimeError("synthetic initializer failure")

    monkeypatch.setattr(runner, "load_manifest", fail_manifest)
    runner.worker_initializer("unused")
    raw = {
        "scenario_id": "synthetic",
        "unit_id": "unit",
        "pair_index": 0,
        "lane": runner.B1_SIBLING,
        "deployment_percent_target": 0,
        "_attempt": 1,
    }
    result = runner.worker_execute(raw)
    assert result["status"] == "failed"
    assert result["initializer_exception"]["type"] == "RuntimeError"
    runner._WORKER_CONTEXT = None
    runner._WORKER_INIT_FAILURE = None


def test_run_requires_16_workers_and_phase8_paths(manifest: dict) -> None:
    with pytest.raises(runner.Phase8ContractError, match="must be below"):
        runner.write_plan(runner.PHASE7_ROOT / "forbidden-phase8-output")
    with TemporaryDirectory(dir=runner.PHASE8_ROOT) as temporary:
        output_dir = Path(temporary)
        runner.atomic_write_json(output_dir / "manifest.json", manifest)
        with pytest.raises(runner.Phase8ContractError, match="exactly 16"):
            runner.run_campaign(
                output_dir,
                workers=15,
                max_new_trials=32,
                benchmark_report=output_dir / "benchmark_32.json",
            )
        assert not (output_dir / "failures.jsonl").exists()


def test_parent_failure_is_written_to_fail_closed_ledger(monkeypatch) -> None:
    with TemporaryDirectory(dir=runner.PHASE8_ROOT) as temporary:
        output_dir = Path(temporary)

        def fail_after_preflight(*_args, **_kwargs):
            runner.atomic_write_json(
                output_dir / "active_invocation.json",
                {
                    "status": "running",
                    "invocation_id": "test",
                    "manifest_sha256": "manifest",
                },
            )
            raise RuntimeError("synthetic parent failure")

        monkeypatch.setattr(runner, "_run_campaign_impl", fail_after_preflight)
        with pytest.raises(RuntimeError, match="synthetic parent failure"):
            runner.run_campaign(
                output_dir,
                workers=16,
                max_new_trials=32,
                benchmark_report=output_dir / "benchmark_32.json",
            )
        failures = [
            json.loads(line)
            for line in (output_dir / "failures.jsonl").read_text().splitlines()
        ]
        assert len(failures) == 1
        assert failures[0]["failure_scope"] == "parent_invocation"
        assert failures[0]["retry_authorized"] is False
