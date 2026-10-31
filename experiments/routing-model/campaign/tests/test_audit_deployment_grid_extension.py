"""Lightweight synthetic tests for the independent grid-extension auditor."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from phase7_simulation.campaign import audit_deployment_grid_extension as audit


@dataclass(frozen=True)
class FixturePaths:
    manifest: Path
    raw: Path
    checkpoint: Path
    failures: Path
    source_manifest: Path
    source_raw: Path


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _manifest_self_sha256(value: dict[str, Any]) -> str:
    core = dict(value)
    core.pop("manifest_sha256", None)
    return _canonical_sha256(core)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _order_sha256(asns: list[int]) -> str:
    return hashlib.sha256("\n".join(map(str, asns)).encode()).hexdigest()


def _set_sha256(asns: list[int]) -> str:
    payload = "\n".join(map(str, sorted(asns))) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def _trial(unit_id: str, pair_index: int, order: str, percent: int, lane: str) -> dict[str, Any]:
    seed = int(order.removeprefix("random_"))
    attacker = None if lane == audit.D1 else "uniform"
    attacker_label = "none" if attacker is None else attacker
    return {
        "scenario_id": (
            f"{unit_id}__{lane}__atk-{attacker_label}__random__"
            f"seed-{seed:02d}__pct-{percent:03d}"
        ),
        "unit_id": unit_id,
        "pair_index": pair_index,
        "lane": lane,
        "announcement_set": "delegate_only" if lane == audit.D1 else "competition",
        "policy_reference": "open_staged",
        "attacker_class": attacker,
        "deployment_strategy": "random",
        "deployment_seed": seed,
        "deployment_percent_target": percent,
        "order_id": order,
        "shared_for_order_ids": [],
    }


def _partition(denominator: int, keys: tuple[str, ...]) -> dict[str, Any]:
    counts = {key: 0 for key in keys}
    counts["delegate"] = denominator
    return {
        "counts": counts,
        "fractions": {key: value / denominator for key, value in counts.items()},
    }


def _outcomes(topology_asns: int, rov_count: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for population, denominator in (
        ("all", topology_asns),
        ("rov", rov_count),
        ("non_rov", topology_asns - rov_count),
    ):
        result[population] = {
            "denominator_asns": denominator,
            "child": _partition(denominator, audit.CHILD_OUTCOMES),
            "destination": _partition(denominator, audit.DESTINATION_OUTCOMES),
        }
    return result


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _make_fixture(tmp_path: Path) -> tuple[FixturePaths, audit.AuditContract]:
    result_dir = tmp_path / "extension"
    source_dir = tmp_path / "source"
    result_dir.mkdir()
    source_dir.mkdir()
    paths = FixturePaths(
        manifest=result_dir / "manifest.json",
        raw=result_dir / "raw_scenarios.jsonl",
        checkpoint=result_dir / "checkpoint.json",
        failures=result_dir / "failures.jsonl",
        source_manifest=source_dir / "manifest.json",
        source_raw=source_dir / "raw_scenarios.jsonl",
    )

    unit = {
        "unit_id": "unit0001",
        "pair_index": 1,
        "source_row": 7,
        "root_prefix": "10.0.0.0/16",
        "leaf_prefix": "10.0.1.0/24",
        "holder_asn": 100,
        "delegate_asn": 200,
        "holder_degree": 1,
        "delegate_degree": 2,
        "cluster_id": "holder:100",
        "holder_stratum": "S1",
        "holder_stratum_degree_range": "1-2",
        "N_h": 1,
        "n_h": 1,
        "stratum_population_N_h": 1,
        "stratum_sample_n_h": 1,
        "design_weight": 1.0,
        "uniform_attacker_asn": 300,
        "uniform_attacker_degree": 3,
    }
    fixed_rov = [1, 2, 3, 4]
    order_id = "random_01"
    source_order = {
        "order_id": order_id,
        "strategy": "random",
        "seed": 1,
        "asns": fixed_rov,
        "order_sha256": _order_sha256(fixed_rov),
        "deployment_counts": {"0": 0, "50": 2, "100": 4},
    }
    topology = {
        "asns": 10,
        "fixed_rov_count": 4,
        "fixed_rov_asns": fixed_rov,
    }
    source_manifest: dict[str, Any] = {
        "schema_version": 1,
        "selected_units": [unit],
        "deployment_orders": [source_order],
        "topology": topology,
    }
    source_manifest["manifest_sha256"] = _manifest_self_sha256(source_manifest)
    _write_json(paths.source_manifest, source_manifest)
    paths.source_raw.write_text('{"accepted":true}\n', encoding="utf-8")

    percentages = (20, 60)
    order = {
        **{key: value for key, value in source_order.items() if key != "deployment_counts"},
        "deployment_counts": {"20": 0, "60": 2},
    }
    trial_plan = [
        _trial(unit["unit_id"], unit["pair_index"], order_id, percent, lane)
        for percent in percentages
        for lane in (audit.D1, audit.A1)
    ]
    source_record = {
        "path": "fixture/source/manifest.json",
        "manifest_sha256": source_manifest["manifest_sha256"],
        "file_sha256": _file_sha256(paths.source_manifest),
        "expected_selected_units": 1,
        "selected_units_copied": 1,
        "expected_random_orders": 1,
        "random_orders_copied": 1,
        "selected_units_sha256": _canonical_sha256([unit]),
        "deployment_orders_sha256": _canonical_sha256([order]),
        "source_trials_reused": 0,
        "source_raw_results_modified": False,
    }
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "experiment_id": audit.EXPERIMENT_ID,
        "mode": "formal",
        "source_campaign": source_record,
        "topology": topology,
        "artifact_hashes_sha256": {
            "files": {},
            "bundle_sha256": hashlib.sha256(b"").hexdigest(),
        },
        "design": {
            "selected_units": 1,
            "deployment_percentages": list(percentages),
            "deployment_counts": {"20": 0, "60": 2},
            "deployment_orders": [order_id],
            "lanes": [audit.D1, audit.A1],
            "competition_attacker_class": "uniform",
            "physical_trials": 4,
            "source_units_resampled": False,
            "source_orders_changed": False,
        },
        "execution_contract": {
            "silent_retries": 0,
            "accepted_campaign_output_mutation": False,
            "single_trial_limit_seconds": 60.0,
            "per_worker_peak_rss_limit_bytes": 1_610_612_736,
            "aggregate_rss_limit_bytes": 1_000_000,
            "minimum_mem_available_bytes": 100,
        },
        "selected_units": [unit],
        "deployment_orders": [order],
        "trial_plan": trial_plan,
        "expected_scenario_ids": {
            "count": 4,
            "sorted_newline_sha256": hashlib.sha256(
                ("\n".join(sorted(row["scenario_id"] for row in trial_plan)) + "\n").encode()
            ).hexdigest(),
        },
    }
    manifest["manifest_sha256"] = _manifest_self_sha256(manifest)
    _write_json(paths.manifest, manifest)

    flags = {
        f"{population}_{partition}_complete": True
        for population in ("all", "rov", "non_rov")
        for partition in ("child", "destination")
    }
    flags["all_equals_rov_plus_non_rov"] = True
    rows = []
    for trial in trial_plan:
        count = int(4 * trial["deployment_percent_target"] / 100)
        selected = fixed_rov[:count]
        row = {
            **trial,
            **{field: unit[field] for field in audit.UNIT_FIELDS},
            "schema_version": 1,
            "status": "success",
            "manifest_sha256": manifest["manifest_sha256"],
            "attacker_asn": (
                None if trial["lane"] == audit.D1 else unit["uniform_attacker_asn"]
            ),
            "attacker_degree": (
                None
                if trial["lane"] == audit.D1
                else unit["uniform_attacker_degree"]
            ),
            "deployment_count": count,
            "deployment_fraction_actual": count / 4,
            "fixed_rov_count": 4,
            "order_sha256": order["order_sha256"],
            "deployment_set_sha256": _set_sha256(selected),
            "policy_assignment_counts": {"bgp": 6, "rov": 4 - count, "s2rov": count},
            "outcomes": _outcomes(10, 4),
            "partition_checks": flags,
            "attempt": 1,
            "prior_failure_count": 0,
            "retry_authorized": False,
            "worker_pid": 123,
            "worker_trial_sequence": 1,
            "worker_graph_build_peak_rss_bytes": 100,
            "rss_before_bytes": 100,
            "rss_after_bytes": 100,
            "peak_rss_bytes": 100,
            "worker_graph_build_seconds": 0.1,
            "elapsed_seconds": 0.2,
        }
        rows.append(row)
    paths.raw.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    paths.failures.write_text("", encoding="utf-8")
    checkpoint = {
        "schema_version": 1,
        "experiment_id": audit.EXPERIMENT_ID,
        "mode": "formal",
        "manifest_sha256": manifest["manifest_sha256"],
        "status": "complete",
        "planned_trials": 4,
        "completed_trials": 4,
        "remaining_trials": 0,
        "retry_failures_authorized": False,
        "run_wall_seconds": 1.0,
        "peak_aggregate_rss_bytes": 100,
        "minimum_mem_available_bytes": 1_000,
    }
    _write_json(paths.checkpoint, checkpoint)
    contract = audit.AuditContract(
        units=1,
        percentages=percentages,
        order_ids=(order_id,),
        lanes=(audit.D1, audit.A1),
        topology_asns=10,
        fixed_rov_count=4,
        aggregate_rss_limit_bytes=1_000_000,
        minimum_mem_available_bytes=100,
        source_manifest_self_sha256=source_manifest["manifest_sha256"],
        source_manifest_file_sha256=_file_sha256(paths.source_manifest),
        source_raw_sha256=_file_sha256(paths.source_raw),
        source_manifest_relative_path="fixture/source/manifest.json",
        verify_artifact_files=False,
    )
    return paths, contract


def _run(paths: FixturePaths, contract: audit.AuditContract) -> dict[str, Any]:
    return audit.audit_files(
        manifest_path=paths.manifest,
        raw_path=paths.raw,
        checkpoint_path=paths.checkpoint,
        failures_path=paths.failures,
        source_manifest_path=paths.source_manifest,
        source_raw_path=paths.source_raw,
        contract=contract,
        artifact_paths={},
    )


def _mutate_raw(paths: FixturePaths, change: Callable[[list[dict[str, Any]]], None]) -> None:
    rows = [json.loads(line) for line in paths.raw.read_text().splitlines()]
    change(rows)
    paths.raw.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_synthetic_fixture_passes_and_has_verifiable_output_hash(tmp_path: Path) -> None:
    paths, contract = _make_fixture(tmp_path)
    result = _run(paths, contract)

    assert result["passed"] is True
    assert all(result["checks"].values())
    core = dict(result)
    output_hashes = core.pop("output_hashes")
    assert output_hashes["canonical_audit_core_sha256"] == _canonical_sha256(core)


@pytest.mark.parametrize(
    ("mutation", "failed_check"),
    [
        (
            lambda rows: rows[-1].__setitem__("scenario_id", rows[0]["scenario_id"]),
            "raw_scenario_ids_unique",
        ),
        (
            lambda rows: rows[-1].__setitem__("deployment_set_sha256", "0" * 64),
            "deployment_count_fraction_and_order_prefix",
        ),
        (
            lambda rows: rows[-1]["outcomes"]["all"]["child"]["fractions"].__setitem__(
                "delegate", 0.5
            ),
            "outcome_fractions_exact",
        ),
        (
            lambda rows: (
                rows[-1].__setitem__("attempt", 2),
                rows[-1].__setitem__("prior_failure_count", 1),
                rows[-1].__setitem__("retry_authorized", True),
            ),
            "attempt_one_and_no_retries",
        ),
    ],
)
def test_synthetic_corruption_is_detected(
    tmp_path: Path,
    mutation: Callable[[list[dict[str, Any]]], None],
    failed_check: str,
) -> None:
    paths, contract = _make_fixture(tmp_path)
    _mutate_raw(paths, mutation)

    result = _run(paths, contract)

    assert result["passed"] is False
    assert result["checks"][failed_check] is False


def test_frozen_source_mutation_is_detected(tmp_path: Path) -> None:
    paths, contract = _make_fixture(tmp_path)
    paths.source_raw.write_text('{"accepted":false}\n', encoding="utf-8")

    result = _run(paths, contract)

    assert result["passed"] is False
    assert result["checks"]["source_raw_file_sha256"] is False


def test_incomplete_checkpoint_refuses_before_raw_open(tmp_path: Path) -> None:
    paths, contract = _make_fixture(tmp_path)
    checkpoint = json.loads(paths.checkpoint.read_text())
    checkpoint.update({"status": "in_progress", "completed_trials": 2, "remaining_trials": 2})
    _write_json(paths.checkpoint, checkpoint)
    paths.raw.unlink()

    # Restore a path entry that exists but cannot be opened; the completion
    # gate must fire first.  A directory satisfies existence but not is_file,
    # so use a no-read file and assert the explicit refusal message.
    paths.raw.write_text("do not read", encoding="utf-8")
    with pytest.raises(audit.AuditRefusal, match="was not opened"):
        _run(paths, contract)
