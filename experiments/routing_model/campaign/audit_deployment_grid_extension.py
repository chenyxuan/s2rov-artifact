#!/usr/bin/env python3
"""Independent, read-only audit of the routing-model deployment-grid extension.

This module intentionally does not import the extension runner or either
campaign analyzer.  It reconstructs the formal factorial design and validates
the emitted JSONL directly from the frozen manifest.  The raw result file is
opened only after the sibling checkpoint declares a complete, no-retry run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
AUDIT_ID = "routing_model-deployment-grid-extension-independent-audit-v1"
EXPERIMENT_ID = "routing_model-deployment-grid-extension-v1"

PERCENTAGES = (20, 30, 40, 60, 70, 80, 90)
ORDER_IDS = tuple(f"random_{seed:02d}" for seed in range(1, 6))
D1 = "D1_open_delegate_only"
A1 = "A1_open_competition"
LANES = (D1, A1)
CHILD_OUTCOMES = ("delegate", "attacker", "absent")
DESTINATION_OUTCOMES = (
    "delegate",
    "attacker",
    "holder_fallback",
    "disconnected",
    "loop",
)

EXPECTED_SOURCE_MANIFEST_SELF_SHA256 = (
    "1394b5aab7020cd0ae7a8cc9d8866ecc86eb06d1bb49e5e2ec85127bb1c3f277"
)
EXPECTED_SOURCE_MANIFEST_FILE_SHA256 = (
    "a674b87afd90716521f19673c4ddbd1153c1b911ec5021a99e0eabe579bcbeae"
)
EXPECTED_SOURCE_RAW_SHA256 = (
    "fb9ec8fa80d41b5a98b4bc956d82ebfec0514eaab27fd183f86683dfed6925b7"
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_DIR = (
    REPOSITORY_ROOT
    / "experiments" / "routing_model"
    / "results"
    / "deployment_grid_extension"
)
DEFAULT_SOURCE_DIR = (
    REPOSITORY_ROOT / "experiments" / "routing_model" / "results" / "paper_campaign"
)
DEFAULT_OUTPUT_PATH = DEFAULT_RESULT_DIR / "independent_audit.json"

ARTIFACT_PATHS = {
    "as_rel_fixed": REPOSITORY_ROOT
    / "experiments/routing_model/data/inputs/as-rel-fixed.txt",
    "campaign_runner": REPOSITORY_ROOT
    / "experiments/routing_model/campaign/full_graph_gate.py",
    "s2rov_policy": REPOSITORY_ROOT / "experiments/routing_model/s2rov/policy.py",
    "dependency_lock": REPOSITORY_ROOT
    / "experiments/routing_model/requirements-bgpy.lock.txt",
    "deployment_grid_extension_contract": REPOSITORY_ROOT
    / "experiments/routing_model/evaluation/deployment_grid_extension_contract.md",
    "deployment_grid_extension_runner": REPOSITORY_ROOT
    / "experiments/routing_model/campaign/deployment_grid_extension.py",
    "holder_delegate_pairs": REPOSITORY_ROOT
    / "experiments/routing_model/data/inputs/holder_delegate_pairs.csv",
    "origin_divergence_candidates": REPOSITORY_ROOT
    / "experiments/routing_model/data/inputs/origin_divergence_candidates.csv",
    "paper_campaign_runner": REPOSITORY_ROOT
    / "experiments/routing_model/campaign/paper_campaign.py",
    "daroa_codec_oracle": REPOSITORY_ROOT
    / "implementation/daroa_codec/scripts/utils/daroa.py",
    "rov_ases_json": REPOSITORY_ROOT
    / "experiments/routing_model/data/inputs/rov_ases.json",
    "rov_ases_text": REPOSITORY_ROOT
    / "experiments/routing_model/data/inputs/rov_ases.txt",
    "source_paper_campaign_manifest": DEFAULT_SOURCE_DIR / "manifest.json",
    "third_party_lock": REPOSITORY_ROOT / "experiments/routing_model/third_party.lock.json",
}


class AuditError(ValueError):
    """Raised when an audit input cannot be interpreted safely."""


class AuditRefusal(AuditError):
    """Raised before opening a raw file whose run is not complete."""


@dataclass(frozen=True)
class AuditContract:
    """Expected design and frozen-source identity.

    Tests use a deliberately small contract.  The command-line interface has
    no switch for changing the formal contract.
    """

    units: int = 200
    percentages: tuple[int, ...] = PERCENTAGES
    order_ids: tuple[str, ...] = ORDER_IDS
    lanes: tuple[str, ...] = LANES
    topology_asns: int = 77_429
    fixed_rov_count: int = 589
    single_trial_limit_seconds: float = 60.0
    per_worker_peak_rss_limit_bytes: int = 1_610_612_736
    aggregate_rss_limit_bytes: int = 25_769_803_776
    minimum_mem_available_bytes: int = 17_179_869_184
    source_manifest_self_sha256: str = EXPECTED_SOURCE_MANIFEST_SELF_SHA256
    source_manifest_file_sha256: str = EXPECTED_SOURCE_MANIFEST_FILE_SHA256
    source_raw_sha256: str = EXPECTED_SOURCE_RAW_SHA256
    source_manifest_relative_path: str | None = (
        "experiments/routing_model/results/paper_campaign/manifest.json"
    )
    verify_artifact_files: bool = True

    @property
    def expected_rows(self) -> int:
        return (
            self.units
            * len(self.percentages)
            * len(self.order_ids)
            * len(self.lanes)
        )


FORMAL_CONTRACT = AuditContract()


CHECK_NAMES = (
    "checkpoint_complete_before_raw_read",
    "checkpoint_contract",
    "manifest_self_sha256",
    "manifest_formal_contract",
    "artifact_bundle_sha256",
    "artifact_files_sha256",
    "source_manifest_file_sha256",
    "source_manifest_self_sha256",
    "source_raw_file_sha256",
    "source_binding",
    "source_material_copied_exactly",
    "manifest_trial_plan_exact",
    "manifest_scenario_id_contract",
    "raw_jsonl_well_formed",
    "raw_row_count_exact",
    "raw_scenario_ids_unique",
    "raw_scenario_ids_exact",
    "raw_trial_metadata_exact",
    "factorial_cells_200x7x5x2",
    "deployment_orders_are_fixed_rov_permutations",
    "deployment_count_fraction_and_order_prefix",
    "policy_assignments_exact",
    "outcome_schema_exact",
    "outcome_partitions_complete",
    "outcome_fractions_exact",
    "outcome_population_additivity",
    "partition_check_flags_true",
    "attempt_one_and_no_retries",
    "runtime_fields_valid",
    "runtime_limits_respected",
    "failure_log_empty",
    "input_files_unchanged_during_audit",
)


class CheckBook:
    """Accumulate named booleans and bounded diagnostic examples."""

    def __init__(self) -> None:
        self.checks = {name: True for name in CHECK_NAMES}
        self._examples: dict[str, list[str]] = defaultdict(list)

    def test(self, name: str, condition: bool, message: str) -> bool:
        if name not in self.checks:
            raise KeyError(name)
        if not condition:
            self.checks[name] = False
            if len(self._examples[name]) < 5:
                self._examples[name].append(message)
        return condition

    def fail(self, name: str, message: str) -> None:
        self.test(name, False, message)

    @property
    def issues(self) -> list[dict[str, Any]]:
        return [
            {"check": name, "examples": self._examples[name]}
            for name in CHECK_NAMES
            if not self.checks[name]
        ]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def manifest_self_sha256(document: Mapping[str, Any]) -> str:
    core = dict(document)
    core.pop("manifest_sha256", None)
    return canonical_sha256(core)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bundle_sha256(files: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def order_sha256(asns: Iterable[int]) -> str:
    return hashlib.sha256(
        "\n".join(str(asn) for asn in asns).encode("utf-8")
    ).hexdigest()


def asn_set_sha256(asns: Iterable[int]) -> str:
    return hashlib.sha256(
        ("\n".join(str(asn) for asn in sorted(asns)) + "\n").encode("utf-8")
    ).hexdigest()


def scenario_ids_sha256(values: Iterable[str]) -> str:
    return hashlib.sha256(
        ("\n".join(sorted(values)) + "\n").encode("utf-8")
    ).hexdigest()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot load JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{path}: expected a JSON object")
    return value


def _stat_identity(path: Path) -> tuple[int, int, int]:
    value = path.stat()
    return value.st_ino, value.st_size, value.st_mtime_ns


def _is_int(value: Any, *, minimum: int | None = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return minimum is None or value >= minimum


def _is_number(value: Any, *, minimum: float | None = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    if not math.isfinite(numeric):
        return False
    return minimum is None or numeric >= minimum


def _same_float(value: Any, expected: float) -> bool:
    return _is_number(value) and math.isclose(
        float(value), expected, rel_tol=0.0, abs_tol=1e-15
    )


def _expected_trial(
    unit: Mapping[str, Any], order_id: str, percent: int, lane: str
) -> dict[str, Any]:
    unit_id = str(unit["unit_id"])
    seed = int(order_id.removeprefix("random_"))
    attacker = None if lane == D1 else "uniform"
    attacker_label = "none" if attacker is None else attacker
    return {
        "scenario_id": (
            f"{unit_id}__{lane}__atk-{attacker_label}__random__"
            f"seed-{seed:02d}__pct-{percent:03d}"
        ),
        "unit_id": unit_id,
        "pair_index": unit["pair_index"],
        "lane": lane,
        "announcement_set": "delegate_only" if lane == D1 else "competition",
        "policy_reference": "open_staged",
        "attacker_class": attacker,
        "deployment_strategy": "random",
        "deployment_seed": seed,
        "deployment_percent_target": percent,
        "order_id": order_id,
        "shared_for_order_ids": [],
    }


def _build_expected_plan(
    units: Sequence[Mapping[str, Any]], contract: AuditContract
) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    for unit in units:
        for order_id in contract.order_ids:
            for percent in contract.percentages:
                for lane in contract.lanes:
                    trial = _expected_trial(unit, order_id, percent, lane)
                    scenario_id = trial["scenario_id"]
                    if scenario_id in expected:
                        raise AuditError(f"reconstructed duplicate ID {scenario_id}")
                    expected[scenario_id] = trial
    return expected


def _source_order_map(source: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw = source.get("deployment_orders")
    if not isinstance(raw, list):
        return {}
    return {
        str(item.get("order_id")): item
        for item in raw
        if isinstance(item, Mapping)
        and str(item.get("order_id", "")).startswith("random_")
    }


def _validate_checkpoint_before_raw(
    checkpoint: Mapping[str, Any],
    manifest: Mapping[str, Any],
    contract: AuditContract,
) -> None:
    """Refuse before opening raw unless the producer declared completion."""

    conditions = (
        checkpoint.get("status") == "complete",
        checkpoint.get("completed_trials") == contract.expected_rows,
        checkpoint.get("planned_trials") == contract.expected_rows,
        checkpoint.get("remaining_trials") == 0,
        checkpoint.get("manifest_sha256") == manifest.get("manifest_sha256"),
        checkpoint.get("retry_failures_authorized") is False,
    )
    if not all(conditions):
        raise AuditRefusal(
            "checkpoint is not a complete, 14,000-row, no-retry run; "
            "raw_scenarios.jsonl was not opened"
        )


def _audit_manifest_and_source(
    manifest: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    manifest_file_sha256: str,
    source_manifest_file_sha256: str,
    source_raw_file_sha256: str,
    contract: AuditContract,
    checks: CheckBook,
    artifact_paths: Mapping[str, Path],
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
    dict[str, dict[str, Any]],
]:
    del manifest_file_sha256  # recorded as an input; self-binding is below.
    checks.test(
        "manifest_self_sha256",
        manifest.get("manifest_sha256") == manifest_self_sha256(manifest),
        "extension manifest canonical self-SHA256 differs",
    )

    design = manifest.get("design")
    topology = manifest.get("topology")
    execution = manifest.get("execution_contract")
    formal_ok = (
        manifest.get("schema_version") == SCHEMA_VERSION
        and manifest.get("experiment_id") == EXPERIMENT_ID
        and manifest.get("mode") == "formal"
        and isinstance(design, Mapping)
        and design.get("selected_units") == contract.units
        and design.get("deployment_percentages") == list(contract.percentages)
        and design.get("deployment_orders") == list(contract.order_ids)
        and design.get("lanes") == list(contract.lanes)
        and design.get("competition_attacker_class") == "uniform"
        and design.get("physical_trials") == contract.expected_rows
        and design.get("source_units_resampled") is False
        and design.get("source_orders_changed") is False
        and isinstance(topology, Mapping)
        and topology.get("asns") == contract.topology_asns
        and topology.get("fixed_rov_count") == contract.fixed_rov_count
        and isinstance(execution, Mapping)
        and execution.get("silent_retries") == 0
        and execution.get("accepted_campaign_output_mutation") is False
        and execution.get("single_trial_limit_seconds")
        == contract.single_trial_limit_seconds
        and execution.get("per_worker_peak_rss_limit_bytes")
        == contract.per_worker_peak_rss_limit_bytes
        and execution.get("aggregate_rss_limit_bytes")
        == contract.aggregate_rss_limit_bytes
        and execution.get("minimum_mem_available_bytes")
        == contract.minimum_mem_available_bytes
    )
    checks.test(
        "manifest_formal_contract",
        formal_ok,
        "extension manifest does not encode the frozen formal design",
    )

    artifacts = manifest.get("artifact_hashes_sha256")
    artifact_files = artifacts.get("files") if isinstance(artifacts, Mapping) else None
    internal_bundle_ok = (
        isinstance(artifact_files, Mapping)
        and all(
            isinstance(name, str)
            and isinstance(value, str)
            and len(value) == 64
            for name, value in artifact_files.items()
        )
        and artifacts.get("bundle_sha256") == bundle_sha256(artifact_files)
    )
    checks.test(
        "artifact_bundle_sha256",
        bool(internal_bundle_ok),
        "artifact-hash bundle is malformed or does not self-verify",
    )
    if contract.verify_artifact_files:
        actual_artifacts: dict[str, str] = {}
        artifact_error: str | None = None
        try:
            actual_artifacts = {
                name: sha256_file(path) for name, path in artifact_paths.items()
            }
        except OSError as exc:
            artifact_error = str(exc)
        checks.test(
            "artifact_files_sha256",
            artifact_error is None
            and isinstance(artifact_files, Mapping)
            and dict(artifact_files) == actual_artifacts,
            artifact_error or "declared artifact hashes differ from current files",
        )
    else:
        checks.test(
            "artifact_files_sha256",
            True,
            "fixture disables repository artifact-file binding",
        )

    checks.test(
        "source_manifest_file_sha256",
        source_manifest_file_sha256 == contract.source_manifest_file_sha256,
        "accepted source manifest bytes changed",
    )
    source_self = manifest_self_sha256(source)
    checks.test(
        "source_manifest_self_sha256",
        source.get("manifest_sha256") == source_self
        and source_self == contract.source_manifest_self_sha256,
        "accepted source manifest identity changed or does not self-verify",
    )
    checks.test(
        "source_raw_file_sha256",
        source_raw_file_sha256 == contract.source_raw_sha256,
        "accepted source raw-results bytes changed",
    )

    source_record = manifest.get("source_campaign")
    source_binding_ok = (
        isinstance(source_record, Mapping)
        and source_record.get("manifest_sha256")
        == contract.source_manifest_self_sha256
        and source_record.get("file_sha256")
        == contract.source_manifest_file_sha256
        and source_record.get("expected_selected_units") == contract.units
        and source_record.get("selected_units_copied") == contract.units
        and source_record.get("expected_random_orders") == len(contract.order_ids)
        and source_record.get("random_orders_copied") == len(contract.order_ids)
        and source_record.get("source_trials_reused") == 0
        and source_record.get("source_raw_results_modified") is False
    )
    if contract.source_manifest_relative_path is not None:
        source_binding_ok = source_binding_ok and (
            source_record.get("path") == contract.source_manifest_relative_path
            if isinstance(source_record, Mapping)
            else False
        )
    checks.test(
        "source_binding",
        source_binding_ok,
        "extension source_campaign record differs from the accepted source",
    )

    raw_units = manifest.get("selected_units")
    source_units = source.get("selected_units")
    units_valid = (
        isinstance(raw_units, list)
        and len(raw_units) == contract.units
        and all(isinstance(item, Mapping) for item in raw_units)
        and len({item.get("unit_id") for item in raw_units}) == contract.units
    )
    unit_by_id: dict[str, Mapping[str, Any]] = (
        {str(item["unit_id"]): item for item in raw_units} if units_valid else {}
    )

    raw_orders = manifest.get("deployment_orders")
    orders_valid = (
        isinstance(raw_orders, list)
        and len(raw_orders) == len(contract.order_ids)
        and all(isinstance(item, Mapping) for item in raw_orders)
        and [str(item.get("order_id")) for item in raw_orders]
        == list(contract.order_ids)
    )
    order_by_id: dict[str, Mapping[str, Any]] = (
        {str(item["order_id"]): item for item in raw_orders} if orders_valid else {}
    )
    source_orders = _source_order_map(source)
    copied_order_ok = orders_valid and set(source_orders) == set(contract.order_ids)
    if copied_order_ok:
        for order_id in contract.order_ids:
            for field in ("order_id", "strategy", "seed", "asns", "order_sha256"):
                if order_by_id[order_id].get(field) != source_orders[order_id].get(field):
                    copied_order_ok = False
    copied_ok = (
        units_valid
        and raw_units == source_units
        and copied_order_ok
        and isinstance(source_record, Mapping)
        and source_record.get("selected_units_sha256") == canonical_sha256(raw_units)
        and source_record.get("deployment_orders_sha256")
        == canonical_sha256(raw_orders)
        and topology == source.get("topology")
    )
    checks.test(
        "source_material_copied_exactly",
        copied_ok,
        "selected units, topology, or random orders differ from frozen source",
    )

    expected_plan: dict[str, dict[str, Any]] = {}
    if units_valid:
        expected_plan = _build_expected_plan(raw_units, contract)
    raw_plan = manifest.get("trial_plan")
    plan_by_id: dict[str, Mapping[str, Any]] = {}
    plan_ok = (
        isinstance(raw_plan, list)
        and len(raw_plan) == contract.expected_rows
        and all(isinstance(item, Mapping) for item in raw_plan)
    )
    if plan_ok:
        for item in raw_plan:
            scenario_id = item.get("scenario_id")
            if not isinstance(scenario_id, str) or scenario_id in plan_by_id:
                plan_ok = False
                continue
            plan_by_id[scenario_id] = item
        plan_ok = plan_ok and set(plan_by_id) == set(expected_plan)
        if plan_ok:
            plan_ok = all(
                all(item.get(field) == value for field, value in expected.items())
                for scenario_id, expected in expected_plan.items()
                for item in (plan_by_id[scenario_id],)
            )
    checks.test(
        "manifest_trial_plan_exact",
        plan_ok,
        "trial_plan is not the exact reconstructed factorial plan",
    )
    ids_contract = manifest.get("expected_scenario_ids")
    ids_ok = (
        isinstance(ids_contract, Mapping)
        and ids_contract.get("count") == contract.expected_rows
        and ids_contract.get("sorted_newline_sha256")
        == scenario_ids_sha256(expected_plan)
    )
    checks.test(
        "manifest_scenario_id_contract",
        ids_ok,
        "manifest expected-scenario-ID digest differs from reconstruction",
    )
    return unit_by_id, order_by_id, expected_plan


def _audit_order_contract(
    manifest: Mapping[str, Any],
    order_by_id: Mapping[str, Mapping[str, Any]],
    contract: AuditContract,
    checks: CheckBook,
) -> tuple[frozenset[int], dict[tuple[str, int], tuple[int, frozenset[int], str]]]:
    topology = manifest.get("topology")
    fixed_raw = topology.get("fixed_rov_asns") if isinstance(topology, Mapping) else None
    fixed_rov: frozenset[int] = frozenset()
    fixed_ok = isinstance(fixed_raw, list) and all(_is_int(value) for value in fixed_raw)
    if fixed_ok:
        fixed_rov = frozenset(int(value) for value in fixed_raw)
        fixed_ok = len(fixed_raw) == len(fixed_rov) == contract.fixed_rov_count

    prefixes: dict[tuple[str, int], tuple[int, frozenset[int], str]] = {}
    orders_ok = fixed_ok and set(order_by_id) == set(contract.order_ids)
    for order_id in contract.order_ids:
        order = order_by_id.get(order_id)
        if not isinstance(order, Mapping):
            orders_ok = False
            continue
        raw_asns = order.get("asns")
        order_ok = (
            isinstance(raw_asns, list)
            and all(_is_int(asn) for asn in raw_asns)
            and len(raw_asns) == contract.fixed_rov_count
            and frozenset(raw_asns) == fixed_rov
            and order.get("strategy") == "random"
            and order.get("seed") == int(order_id.removeprefix("random_"))
            and order.get("order_sha256") == order_sha256(raw_asns)
        )
        orders_ok = orders_ok and order_ok
        if not isinstance(raw_asns, list):
            continue
        counts = order.get("deployment_counts")
        for percent in contract.percentages:
            count = int(contract.fixed_rov_count * percent / 100)
            if not isinstance(counts, Mapping) or counts.get(str(percent)) != count:
                orders_ok = False
            selected = frozenset(int(asn) for asn in raw_asns[:count])
            prefixes[(order_id, percent)] = (
                count,
                selected,
                asn_set_sha256(selected),
            )
    design = manifest.get("design")
    expected_counts = {
        str(percent): int(contract.fixed_rov_count * percent / 100)
        for percent in contract.percentages
    }
    if not isinstance(design, Mapping) or design.get("deployment_counts") != expected_counts:
        orders_ok = False
    checks.test(
        "deployment_orders_are_fixed_rov_permutations",
        orders_ok,
        "one or more order lists, order hashes, or floor counts are invalid",
    )
    return fixed_rov, prefixes


UNIT_FIELDS = (
    "pair_index",
    "source_row",
    "root_prefix",
    "leaf_prefix",
    "holder_asn",
    "delegate_asn",
    "holder_degree",
    "delegate_degree",
    "cluster_id",
    "holder_stratum",
    "holder_stratum_degree_range",
    "N_h",
    "n_h",
    "stratum_population_N_h",
    "stratum_sample_n_h",
    "design_weight",
)


def _validate_trial_metadata(
    row: Mapping[str, Any],
    expected: Mapping[str, Any],
    unit: Mapping[str, Any],
    manifest_digest: Any,
) -> bool:
    if (
        row.get("schema_version") != SCHEMA_VERSION
        or row.get("status") != "success"
        or row.get("manifest_sha256") != manifest_digest
    ):
        return False
    if any(row.get(field) != value for field, value in expected.items()):
        return False
    if any(row.get(field) != unit.get(field) for field in UNIT_FIELDS):
        return False
    if expected["lane"] == D1:
        attacker_asn = attacker_degree = None
    else:
        attacker_asn = unit.get("uniform_attacker_asn")
        attacker_degree = unit.get("uniform_attacker_degree")
    return (
        row.get("attacker_asn") == attacker_asn
        and row.get("attacker_degree") == attacker_degree
    )


def _audit_outcomes(
    row: Mapping[str, Any], contract: AuditContract, checks: CheckBook
) -> None:
    scenario_id = str(row.get("scenario_id", "<unknown>"))
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping) or set(outcomes) != {
        "all",
        "rov",
        "non_rov",
    }:
        checks.fail("outcome_schema_exact", f"{scenario_id}: population schema")
        checks.fail("outcome_partitions_complete", f"{scenario_id}: no partitions")
        checks.fail("outcome_fractions_exact", f"{scenario_id}: no fractions")
        checks.fail("outcome_population_additivity", f"{scenario_id}: no subgroups")
        checks.fail("partition_check_flags_true", f"{scenario_id}: no flags")
        return

    denominators = {
        "all": contract.topology_asns,
        "rov": contract.fixed_rov_count,
        "non_rov": contract.topology_asns - contract.fixed_rov_count,
    }
    schema_ok = True
    complete_ok = True
    fraction_ok = True
    for population, denominator in denominators.items():
        section = outcomes.get(population)
        if not isinstance(section, Mapping) or section.get("denominator_asns") != denominator:
            schema_ok = False
            complete_ok = False
            fraction_ok = False
            continue
        for partition, expected_keys in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            values = section.get(partition)
            if not isinstance(values, Mapping):
                schema_ok = complete_ok = fraction_ok = False
                continue
            counts = values.get("counts")
            fractions = values.get("fractions")
            if not isinstance(counts, Mapping) or set(counts) != set(expected_keys):
                schema_ok = complete_ok = fraction_ok = False
                continue
            if any(not _is_int(value, minimum=0) for value in counts.values()):
                complete_ok = False
            elif sum(int(value) for value in counts.values()) != denominator:
                complete_ok = False
            if not isinstance(fractions, Mapping) or set(fractions) != set(expected_keys):
                schema_ok = fraction_ok = False
                continue
            for key in expected_keys:
                count = counts[key]
                if not _is_int(count, minimum=0) or not _same_float(
                    fractions[key], int(count) / denominator
                ):
                    fraction_ok = False
    checks.test("outcome_schema_exact", schema_ok, f"{scenario_id}: outcome schema")
    checks.test(
        "outcome_partitions_complete", complete_ok, f"{scenario_id}: partition totals"
    )
    checks.test(
        "outcome_fractions_exact", fraction_ok, f"{scenario_id}: count fractions"
    )

    additive_ok = True
    try:
        for partition, keys in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            for key in keys:
                if outcomes["all"][partition]["counts"][key] != (
                    outcomes["rov"][partition]["counts"][key]
                    + outcomes["non_rov"][partition]["counts"][key]
                ):
                    additive_ok = False
    except (KeyError, TypeError):
        additive_ok = False
    checks.test(
        "outcome_population_additivity",
        additive_ok,
        f"{scenario_id}: all != ROV + non-ROV",
    )

    expected_flags = {
        f"{population}_{partition}_complete"
        for population in ("all", "rov", "non_rov")
        for partition in ("child", "destination")
    } | {"all_equals_rov_plus_non_rov"}
    flags = row.get("partition_checks")
    flags_ok = (
        isinstance(flags, Mapping)
        and set(flags) == expected_flags
        and all(value is True for value in flags.values())
    )
    checks.test(
        "partition_check_flags_true", flags_ok, f"{scenario_id}: producer flags"
    )


def _audit_row(
    row: Mapping[str, Any],
    *,
    expected_plan: Mapping[str, Mapping[str, Any]],
    unit_by_id: Mapping[str, Mapping[str, Any]],
    order_by_id: Mapping[str, Mapping[str, Any]],
    prefixes: Mapping[tuple[str, int], tuple[int, frozenset[int], str]],
    manifest_digest: Any,
    contract: AuditContract,
    checks: CheckBook,
) -> tuple[str | None, tuple[str, int, str, str] | None]:
    scenario_id = row.get("scenario_id")
    if not isinstance(scenario_id, str):
        checks.fail("raw_trial_metadata_exact", "row has no string scenario_id")
        return None, None
    expected = expected_plan.get(scenario_id)
    if expected is None:
        checks.fail("raw_trial_metadata_exact", f"{scenario_id}: unexpected ID")
        return scenario_id, None
    unit = unit_by_id.get(str(expected["unit_id"]))
    metadata_ok = isinstance(unit, Mapping) and _validate_trial_metadata(
        row, expected, unit, manifest_digest
    )
    checks.test(
        "raw_trial_metadata_exact",
        metadata_ok,
        f"{scenario_id}: trial or unit metadata differs",
    )

    order_id = str(expected["order_id"])
    percent = int(expected["deployment_percent_target"])
    prefix = prefixes.get((order_id, percent))
    order = order_by_id.get(order_id)
    prefix_ok = False
    if prefix is not None and isinstance(order, Mapping):
        count, _selected, set_digest = prefix
        prefix_ok = (
            row.get("deployment_count") == count
            and _same_float(
                row.get("deployment_fraction_actual"), count / contract.fixed_rov_count
            )
            and row.get("fixed_rov_count") == contract.fixed_rov_count
            and row.get("order_sha256") == order.get("order_sha256")
            and row.get("deployment_set_sha256") == set_digest
        )
    checks.test(
        "deployment_count_fraction_and_order_prefix",
        prefix_ok,
        f"{scenario_id}: deployment prefix metadata differs",
    )

    count = prefix[0] if prefix is not None else -1
    assignments_ok = row.get("policy_assignment_counts") == {
        "bgp": contract.topology_asns - contract.fixed_rov_count,
        "rov": contract.fixed_rov_count - count,
        "s2rov": count,
    }
    checks.test(
        "policy_assignments_exact",
        assignments_ok,
        f"{scenario_id}: policy counts differ",
    )

    attempt_ok = (
        row.get("attempt") == 1
        and not isinstance(row.get("attempt"), bool)
        and row.get("prior_failure_count") == 0
        and row.get("retry_authorized") is False
    )
    checks.test(
        "attempt_one_and_no_retries", attempt_ok, f"{scenario_id}: retry provenance"
    )

    integer_runtime_fields = (
        "worker_pid",
        "worker_trial_sequence",
        "worker_graph_build_peak_rss_bytes",
        "rss_before_bytes",
        "rss_after_bytes",
        "peak_rss_bytes",
    )
    runtime_fields_ok = all(
        _is_int(row.get(field), minimum=1 if field in {"worker_pid", "worker_trial_sequence"} else 0)
        for field in integer_runtime_fields
    ) and all(
        _is_number(row.get(field), minimum=0)
        for field in ("worker_graph_build_seconds", "elapsed_seconds")
    )
    checks.test(
        "runtime_fields_valid", runtime_fields_ok, f"{scenario_id}: runtime fields"
    )

    # The limits are read from the manifest but the formal values are checked
    # separately by manifest_formal_contract.
    runtime_limits_ok = (
        _is_number(row.get("elapsed_seconds"), minimum=0)
        and float(row["elapsed_seconds"])
        <= contract.single_trial_limit_seconds
        and _is_int(row.get("peak_rss_bytes"), minimum=0)
        and int(row["peak_rss_bytes"])
        <= contract.per_worker_peak_rss_limit_bytes
        and _is_int(row.get("worker_graph_build_peak_rss_bytes"), minimum=0)
        and int(row["worker_graph_build_peak_rss_bytes"])
        <= contract.per_worker_peak_rss_limit_bytes
    )
    checks.test(
        "runtime_limits_respected",
        runtime_limits_ok,
        f"{scenario_id}: per-trial time or worker RSS limit",
    )
    _audit_outcomes(row, contract, checks)
    return scenario_id, (
        str(expected["unit_id"]),
        percent,
        order_id,
        str(expected["lane"]),
    )


def _stream_raw_rows(
    raw_path: Path,
    *,
    expected_plan: Mapping[str, Mapping[str, Any]],
    unit_by_id: Mapping[str, Mapping[str, Any]],
    order_by_id: Mapping[str, Mapping[str, Any]],
    prefixes: Mapping[tuple[str, int], tuple[int, frozenset[int], str]],
    manifest_digest: Any,
    contract: AuditContract,
    checks: CheckBook,
) -> tuple[str, int, set[str], Counter[tuple[str, int, str, str]]]:
    digest = hashlib.sha256()
    row_count = 0
    ids: set[str] = set()
    cells: Counter[tuple[str, int, str, str]] = Counter()
    last_line_had_newline = False
    with raw_path.open("rb") as handle:
        for line_number, line in enumerate(handle, start=1):
            digest.update(line)
            last_line_had_newline = line.endswith(b"\n")
            if not line.strip():
                checks.fail("raw_jsonl_well_formed", f"blank line {line_number}")
                continue
            row_count += 1
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                checks.fail(
                    "raw_jsonl_well_formed", f"line {line_number}: {type(exc).__name__}"
                )
                continue
            if not isinstance(row, Mapping):
                checks.fail("raw_jsonl_well_formed", f"line {line_number}: non-object")
                continue
            scenario_id, cell = _audit_row(
                row,
                expected_plan=expected_plan,
                unit_by_id=unit_by_id,
                order_by_id=order_by_id,
                prefixes=prefixes,
                manifest_digest=manifest_digest,
                contract=contract,
                checks=checks,
            )
            if scenario_id is not None:
                if scenario_id in ids:
                    checks.fail(
                        "raw_scenario_ids_unique", f"duplicate {scenario_id}"
                    )
                ids.add(scenario_id)
            if cell is not None:
                cells[cell] += 1
    checks.test(
        "raw_jsonl_well_formed",
        row_count > 0 and last_line_had_newline,
        "raw JSONL is empty or lacks a final newline",
    )
    checks.test(
        "raw_row_count_exact",
        row_count == contract.expected_rows,
        f"observed {row_count:,}, expected {contract.expected_rows:,}",
    )
    checks.test(
        "raw_scenario_ids_unique",
        len(ids) == row_count,
        f"{row_count - len(ids):,} duplicate/non-string ID rows",
    )
    checks.test(
        "raw_scenario_ids_exact",
        ids == set(expected_plan),
        f"observed {len(ids):,} unique IDs, expected {len(expected_plan):,}",
    )
    expected_cells = {
        (unit_id, percent, order_id, lane)
        for unit_id in unit_by_id
        for percent in contract.percentages
        for order_id in contract.order_ids
        for lane in contract.lanes
    }
    cells_ok = (
        set(cells) == expected_cells
        and len(cells) == contract.expected_rows
        and all(count == 1 for count in cells.values())
    )
    checks.test(
        "factorial_cells_200x7x5x2",
        cells_ok,
        "unit x percentage x order x lane cells are not exactly singleton",
    )
    return digest.hexdigest(), row_count, ids, cells


def audit_files(
    *,
    manifest_path: Path,
    raw_path: Path,
    checkpoint_path: Path,
    source_manifest_path: Path,
    source_raw_path: Path,
    failures_path: Path | None = None,
    contract: AuditContract = FORMAL_CONTRACT,
    artifact_paths: Mapping[str, Path] = ARTIFACT_PATHS,
) -> dict[str, Any]:
    """Audit one completed result set without modifying any input."""

    input_paths = {
        "extension_manifest": manifest_path,
        "extension_raw": raw_path,
        "extension_checkpoint": checkpoint_path,
        "source_manifest": source_manifest_path,
        "source_raw": source_raw_path,
    }
    if failures_path is not None:
        input_paths["extension_failures"] = failures_path
    required = [
        manifest_path,
        raw_path,
        checkpoint_path,
        source_manifest_path,
        source_raw_path,
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise AuditError(f"missing audit inputs: {', '.join(missing)}")

    # The completion gate is intentionally evaluated before opening raw.
    manifest = _load_json_object(manifest_path)
    checkpoint = _load_json_object(checkpoint_path)
    _validate_checkpoint_before_raw(checkpoint, manifest, contract)

    stats_before = {
        name: _stat_identity(path) if path.exists() else None
        for name, path in input_paths.items()
    }
    checks = CheckBook()
    checks.test(
        "checkpoint_complete_before_raw_read",
        True,
        "completion gate passed before raw read",
    )

    source = _load_json_object(source_manifest_path)
    nonraw_hashes = {
        "extension_manifest": sha256_file(manifest_path),
        "extension_checkpoint": sha256_file(checkpoint_path),
        "source_manifest": sha256_file(source_manifest_path),
        "source_raw": sha256_file(source_raw_path),
    }
    if failures_path is not None and failures_path.exists():
        nonraw_hashes["extension_failures"] = sha256_file(failures_path)

    unit_by_id, order_by_id, expected_plan = _audit_manifest_and_source(
        manifest,
        source,
        manifest_file_sha256=nonraw_hashes["extension_manifest"],
        source_manifest_file_sha256=nonraw_hashes["source_manifest"],
        source_raw_file_sha256=nonraw_hashes["source_raw"],
        contract=contract,
        checks=checks,
        artifact_paths=artifact_paths,
    )
    _fixed_rov, prefixes = _audit_order_contract(
        manifest, order_by_id, contract, checks
    )
    raw_sha256, raw_row_count, raw_ids, cells = _stream_raw_rows(
        raw_path,
        expected_plan=expected_plan,
        unit_by_id=unit_by_id,
        order_by_id=order_by_id,
        prefixes=prefixes,
        manifest_digest=manifest.get("manifest_sha256"),
        contract=contract,
        checks=checks,
    )

    execution = manifest.get("execution_contract")
    checkpoint_contract_ok = (
        checkpoint.get("schema_version") == SCHEMA_VERSION
        and checkpoint.get("experiment_id") == EXPERIMENT_ID
        and checkpoint.get("mode") == "formal"
        and checkpoint.get("status") == "complete"
        and checkpoint.get("planned_trials") == contract.expected_rows
        and checkpoint.get("completed_trials") == contract.expected_rows
        and checkpoint.get("remaining_trials") == 0
        and checkpoint.get("manifest_sha256") == manifest.get("manifest_sha256")
        and checkpoint.get("retry_failures_authorized") is False
        and isinstance(execution, Mapping)
        and _is_number(checkpoint.get("run_wall_seconds"), minimum=0)
        and _is_int(checkpoint.get("peak_aggregate_rss_bytes"), minimum=0)
        and checkpoint.get("peak_aggregate_rss_bytes")
        <= execution.get("aggregate_rss_limit_bytes", -1)
        and _is_int(checkpoint.get("minimum_mem_available_bytes"), minimum=0)
        and checkpoint.get("minimum_mem_available_bytes")
        >= execution.get("minimum_mem_available_bytes", math.inf)
    )
    checks.test(
        "checkpoint_contract",
        checkpoint_contract_ok,
        "final checkpoint violates completion or resource contract",
    )
    no_failure_log = (
        failures_path is None
        or not failures_path.exists()
        or failures_path.stat().st_size == 0
    )
    checks.test(
        "failure_log_empty", no_failure_log, "failures.jsonl is nonempty"
    )
    checks.test(
        "attempt_one_and_no_retries",
        checkpoint.get("retry_failures_authorized") is False
        and isinstance(execution, Mapping)
        and execution.get("silent_retries") == 0
        and no_failure_log,
        "checkpoint, manifest, or failure log permits/records a retry",
    )

    stats_after = {
        name: _stat_identity(path) if path.exists() else None
        for name, path in input_paths.items()
    }
    checks.test(
        "input_files_unchanged_during_audit",
        stats_before == stats_after,
        "one or more inputs changed while being audited",
    )

    input_hashes: dict[str, dict[str, Any]] = {}
    for name, path in input_paths.items():
        if not path.exists():
            input_hashes[name] = {
                "path": str(path.resolve()),
                "exists": False,
                "bytes": None,
                "sha256": None,
            }
            continue
        digest = raw_sha256 if name == "extension_raw" else nonraw_hashes.get(name)
        input_hashes[name] = {
            "path": str(path.resolve()),
            "exists": True,
            "bytes": path.stat().st_size,
            "sha256": digest,
        }

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "audit_id": AUDIT_ID,
        "audited_at_utc": utc_now(),
        "implementation": {
            "independent_of": [
                "deployment_grid_extension.py",
                "analyze_deployment_grid_extension.py",
            ],
            "python": platform.python_version(),
            "read_only_inputs": True,
            "raw_opened_only_after_complete_checkpoint": True,
        },
        "contract": {
            "units": contract.units,
            "deployment_percentages": list(contract.percentages),
            "random_orders": list(contract.order_ids),
            "lanes": list(contract.lanes),
            "expected_rows": contract.expected_rows,
            "factorization": (
                f"{contract.units} x {len(contract.percentages)} x "
                f"{len(contract.order_ids)} x {len(contract.lanes)}"
            ),
            "topology_asns": contract.topology_asns,
            "fixed_rov_count": contract.fixed_rov_count,
            "single_trial_limit_seconds": contract.single_trial_limit_seconds,
            "per_worker_peak_rss_limit_bytes": (
                contract.per_worker_peak_rss_limit_bytes
            ),
            "aggregate_rss_limit_bytes": contract.aggregate_rss_limit_bytes,
            "minimum_mem_available_bytes": contract.minimum_mem_available_bytes,
        },
        "inputs": input_hashes,
        "observed": {
            "raw_rows": raw_row_count,
            "unique_scenario_ids": len(raw_ids),
            "unique_factorial_cells": len(cells),
            "scenario_ids_sorted_newline_sha256": scenario_ids_sha256(raw_ids),
            "manifest_file_sha256": nonraw_hashes["extension_manifest"],
            "manifest_self_sha256": manifest_self_sha256(manifest),
            "raw_file_sha256": raw_sha256,
            "source_manifest_file_sha256": nonraw_hashes["source_manifest"],
            "source_manifest_self_sha256": manifest_self_sha256(source),
            "source_raw_file_sha256": nonraw_hashes["source_raw"],
        },
        "checks": checks.checks,
        "issues": checks.issues,
        "passed": all(checks.checks.values()),
    }
    document["output_hashes"] = {
        "canonical_audit_core_sha256": canonical_sha256(document),
        "scope": "canonical JSON document with output_hashes omitted",
    }
    return document


def _failure_document(message: str) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "audit_id": AUDIT_ID,
        "audited_at_utc": utc_now(),
        "passed": False,
        "refused_before_raw_read": isinstance(message, str)
        and "was not opened" in message,
        "fatal_error": message,
        "checks": {name: False for name in CHECK_NAMES},
    }
    document["output_hashes"] = {
        "canonical_audit_core_sha256": canonical_sha256(document),
        "scope": "canonical JSON document with output_hashes omitted",
    }
    return document


def write_audit(path: Path, document: Mapping[str, Any]) -> str:
    """Atomically write the single audit artifact and return its file hash."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_RESULT_DIR / "manifest.json")
    parser.add_argument("--raw", type=Path, default=DEFAULT_RESULT_DIR / "raw_scenarios.jsonl")
    parser.add_argument(
        "--checkpoint", type=Path, default=DEFAULT_RESULT_DIR / "checkpoint.json"
    )
    parser.add_argument(
        "--failures", type=Path, default=DEFAULT_RESULT_DIR / "failures.jsonl"
    )
    parser.add_argument(
        "--source-manifest", type=Path, default=DEFAULT_SOURCE_DIR / "manifest.json"
    )
    parser.add_argument(
        "--source-raw", type=Path, default=DEFAULT_SOURCE_DIR / "raw_scenarios.jsonl"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inputs = {
        args.manifest.resolve(),
        args.raw.resolve(),
        args.checkpoint.resolve(),
        args.failures.resolve(),
        args.source_manifest.resolve(),
        args.source_raw.resolve(),
    }
    if args.output.resolve() in inputs:
        document = _failure_document("output path aliases an audit input")
    else:
        try:
            document = audit_files(
                manifest_path=args.manifest,
                raw_path=args.raw,
                checkpoint_path=args.checkpoint,
                failures_path=args.failures,
                source_manifest_path=args.source_manifest,
                source_raw_path=args.source_raw,
            )
        except (AuditError, OSError, TypeError, ValueError) as exc:
            document = _failure_document(str(exc))
    output_file_sha256 = write_audit(args.output, document)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "output_file_sha256": output_file_sha256,
                "passed": document.get("passed", False),
            },
            sort_keys=True,
        )
    )
    return 0 if document.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
