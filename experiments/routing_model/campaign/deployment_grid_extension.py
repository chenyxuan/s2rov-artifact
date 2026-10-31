"""Independent regular-grid extension for the accepted routing-model campaign.

The formal plan reuses the accepted campaign's 200 frozen units and five
random deployment orders, but writes a separate manifest and checkpoint.  It
adds seven deployment cells (20, 30, 40, 60, 70, 80, and 90 percent) for only
the D1 delegate-only and uniform-attacker A1 competition lanes.  No command in
this module writes to the accepted ``paper_campaign`` result directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import signal
import traceback
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable, Mapping, Sequence

from bgpy.simulation_engine import SimulationEngine

import experiments.routing_model.campaign.paper_campaign as paper
from experiments.routing_model.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    CHILD_OUTCOMES,
    DESTINATION_OUTCOMES,
    D1_OPEN_DELEGATE,
)


SCHEMA_VERSION = 1
EXPERIMENT_ID = "routing_model-deployment-grid-extension-v1"
FORMAL_PERCENTAGES = (20, 30, 40, 60, 70, 80, 90)
SMOKE_PERCENTAGES = (20, 90)
RANDOM_ORDER_IDS = (
    "random_01",
    "random_02",
    "random_03",
    "random_04",
    "random_05",
)
EXPECTED_FORMAL_UNITS = 200
EXPECTED_FORMAL_ORDERS = 5
EXPECTED_FORMAL_TRIALS = 14_000
EXPECTED_SMOKE_UNITS = 1
EXPECTED_SMOKE_ORDERS = 1
EXPECTED_SMOKE_TRIALS = 4

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = Path(__file__).resolve()
CONTRACT_PATH = (
    REPOSITORY_ROOT
    / "experiments" / "routing_model"
    / "evaluation"
    / "deployment_grid_extension_contract.md"
)
SOURCE_MANIFEST_PATH = (
    REPOSITORY_ROOT
    / "experiments" / "routing_model"
    / "results"
    / "paper_campaign"
    / "manifest.json"
)
DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT
    / "experiments" / "routing_model"
    / "results"
    / "deployment_grid_extension"
)
DEFAULT_SMOKE_DIR = (
    REPOSITORY_ROOT
    / "experiments" / "routing_model"
    / "results"
    / "deployment_grid_extension_smoke"
)


class GridExtensionError(ValueError):
    """Raised when the extension contract or a checkpoint fails closed."""


@dataclass
class WorkerContext:
    engine: SimulationEngine
    units: dict[str, paper.SampledUnit]
    orders: dict[str, paper.DeploymentOrder]
    rov_asns: frozenset[int]
    manifest_sha256: str
    graph_build_seconds: float
    graph_build_peak_rss_bytes: int
    sequence: int = 0


_WORKER_CONTEXT: WorkerContext | None = None


def utc_now() -> str:
    return paper.utc_now()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_path(path: Path) -> str:
    return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bundle_sha256(files: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def artifact_hashes() -> dict[str, Any]:
    """Bind the extension to current reused propagation code and inputs."""

    files = dict(paper.campaign_artifact_hashes()["files"])
    files.update(
        {
            "deployment_grid_extension_runner": _file_sha256(RUNNER_PATH),
            "deployment_grid_extension_contract": _file_sha256(CONTRACT_PATH),
            "source_paper_campaign_manifest": _file_sha256(
                SOURCE_MANIFEST_PATH
            ),
        }
    )
    return {"files": files, "bundle_sha256": _bundle_sha256(files)}


def manifest_sha256(document: Mapping[str, Any]) -> str:
    core = dict(document)
    core.pop("manifest_sha256", None)
    return _canonical_sha256(core)


def expected_ids_sha256(trials: Sequence[paper.CampaignTrial]) -> str:
    payload = "\n".join(sorted(trial.scenario_id for trial in trials)) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deployment_count(percent: int, rov_count: int = paper.ROV_COUNT) -> int:
    if percent not in FORMAL_PERCENTAGES:
        raise GridExtensionError(
            f"unsupported extension deployment percentage {percent}"
        )
    if rov_count < 1:
        raise GridExtensionError("fixed ROV count must be positive")
    return int(rov_count * percent / 100)


def _mode_contract(mode: str) -> tuple[int, tuple[str, ...], tuple[int, ...], int]:
    if mode == "formal":
        return (
            EXPECTED_FORMAL_UNITS,
            RANDOM_ORDER_IDS,
            FORMAL_PERCENTAGES,
            EXPECTED_FORMAL_TRIALS,
        )
    if mode == "smoke":
        return (
            EXPECTED_SMOKE_UNITS,
            RANDOM_ORDER_IDS[:1],
            SMOKE_PERCENTAGES,
            EXPECTED_SMOKE_TRIALS,
        )
    raise GridExtensionError(f"unsupported extension mode {mode!r}")


def _load_source_manifest() -> dict[str, Any]:
    return paper.load_manifest(SOURCE_MANIFEST_PATH, production=True)


def _selected_source_material(
    source: Mapping[str, Any], mode: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], tuple[int, ...]]:
    unit_count, order_ids, percentages, _trial_count = _mode_contract(mode)
    source_units = source.get("selected_units")
    source_orders = source.get("deployment_orders")
    if not isinstance(source_units, list) or not isinstance(source_orders, list):
        raise GridExtensionError("accepted manifest lacks units or deployment orders")
    if len(source_units) != EXPECTED_FORMAL_UNITS:
        raise GridExtensionError("accepted manifest no longer has 200 frozen units")
    by_order_id = {str(item.get("order_id")): item for item in source_orders}
    if len(by_order_id) != len(source_orders):
        raise GridExtensionError("accepted manifest repeats a deployment order")
    selected_orders: list[dict[str, Any]] = []
    for order_id in order_ids:
        raw = by_order_id.get(order_id)
        if raw is None or raw.get("strategy") != "random":
            raise GridExtensionError(
                f"accepted manifest lacks frozen random order {order_id}"
            )
        selected_orders.append(
            {
                "order_id": raw["order_id"],
                "strategy": raw["strategy"],
                "seed": raw["seed"],
                "asns": list(raw["asns"]),
                "order_sha256": raw["order_sha256"],
                "deployment_counts": {
                    str(percent): deployment_count(percent)
                    for percent in percentages
                },
            }
        )
    return (
        _json_copy(source_units[:unit_count]),
        _json_copy(selected_orders),
        percentages,
    )


def _units_from_documents(
    raw_units: Sequence[Mapping[str, Any]],
) -> tuple[paper.SampledUnit, ...]:
    fields = set(paper.SampledUnit.__dataclass_fields__)
    return tuple(
        paper.SampledUnit(
            **{key: value for key, value in raw.items() if key in fields}
        )
        for raw in raw_units
    )


def _orders_from_documents(
    raw_orders: Sequence[Mapping[str, Any]],
) -> tuple[paper.DeploymentOrder, ...]:
    return tuple(
        paper.DeploymentOrder(
            order_id=str(raw["order_id"]),
            strategy=str(raw["strategy"]),
            seed=None if raw["seed"] is None else int(raw["seed"]),
            asns=tuple(int(asn) for asn in raw["asns"]),
            order_sha256=str(raw["order_sha256"]),
        )
        for raw in raw_orders
    )


def build_trial_plan(
    units: Sequence[paper.SampledUnit],
    orders: Sequence[paper.DeploymentOrder],
    percentages: Sequence[int],
) -> tuple[paper.CampaignTrial, ...]:
    """Build only the new random-order D1 and uniform-A1 cells."""

    if not percentages or any(
        percent not in FORMAL_PERCENTAGES for percent in percentages
    ):
        raise GridExtensionError("trial plan contains a non-extension percentage")
    if len(set(percentages)) != len(percentages):
        raise GridExtensionError("trial plan repeats a deployment percentage")
    trials: list[paper.CampaignTrial] = []
    for unit in units:
        for order in orders:
            if order.order_id not in RANDOM_ORDER_IDS or order.strategy != "random":
                raise GridExtensionError("extension accepts only frozen random orders")
            for percent in percentages:
                trials.append(
                    paper.CampaignTrial(
                        scenario_id=paper._scenario_id(
                            unit,
                            D1_OPEN_DELEGATE,
                            None,
                            order.strategy,
                            order.seed,
                            percent,
                        ),
                        unit_id=unit.unit_id,
                        pair_index=unit.pair_index,
                        lane=D1_OPEN_DELEGATE,
                        announcement_set="delegate_only",
                        policy_reference="open_staged",
                        attacker_class=None,
                        deployment_strategy=order.strategy,
                        deployment_seed=order.seed,
                        deployment_percent_target=percent,
                        order_id=order.order_id,
                    )
                )
                trials.append(
                    paper.CampaignTrial(
                        scenario_id=paper._scenario_id(
                            unit,
                            A1_OPEN_COMPETITION,
                            "uniform",
                            order.strategy,
                            order.seed,
                            percent,
                        ),
                        unit_id=unit.unit_id,
                        pair_index=unit.pair_index,
                        lane=A1_OPEN_COMPETITION,
                        announcement_set="competition",
                        policy_reference="open_staged",
                        attacker_class="uniform",
                        deployment_strategy=order.strategy,
                        deployment_seed=order.seed,
                        deployment_percent_target=percent,
                        order_id=order.order_id,
                    )
                )
    scenario_ids = [trial.scenario_id for trial in trials]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise GridExtensionError("extension trial plan repeats a scenario ID")
    expected = len(units) * len(orders) * len(percentages) * 2
    if len(trials) != expected:
        raise GridExtensionError(
            f"extension trial plan has {len(trials)} rows, expected {expected}"
        )
    return tuple(trials)


def build_manifest_document(mode: str = "formal") -> dict[str, Any]:
    """Build a complete extension manifest without running propagation."""

    source = _load_source_manifest()
    raw_units, raw_orders, percentages = _selected_source_material(source, mode)
    units = _units_from_documents(raw_units)
    orders = _orders_from_documents(raw_orders)
    trials = build_trial_plan(units, orders, percentages)
    _unit_count, _order_ids, _percentages, expected_trials = _mode_contract(mode)
    if len(trials) != expected_trials:
        raise GridExtensionError(
            f"{mode} plan has {len(trials)} trials, expected {expected_trials}"
        )
    runtime = paper.runtime_environment_fingerprint()
    source_file_sha256 = _file_sha256(SOURCE_MANIFEST_PATH)
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": EXPERIMENT_ID,
        "mode": mode,
        "created_at_utc": utc_now(),
        "status": "planned_not_executed",
        "source_campaign": {
            "role": "frozen units and random deployment orders only",
            "path": _relative_path(SOURCE_MANIFEST_PATH),
            "manifest_sha256": source["manifest_sha256"],
            "file_sha256": source_file_sha256,
            "expected_selected_units": EXPECTED_FORMAL_UNITS,
            "selected_units_copied": len(raw_units),
            "expected_random_orders": EXPECTED_FORMAL_ORDERS,
            "random_orders_copied": len(raw_orders),
            "selected_units_sha256": _canonical_sha256(raw_units),
            "deployment_orders_sha256": _canonical_sha256(raw_orders),
            "source_trials_reused": 0,
            "source_raw_results_modified": False,
        },
        "engine": {
            "name": "BGPy",
            "version": runtime["bgpy"]["version"],
            "vendor_commit": runtime["bgpy"]["vendor_commit"],
            "vendor_dirty": runtime["bgpy"]["vendor_dirty"],
            "vendor_modified_by_extension": False,
        },
        "runtime_environment": runtime,
        "repository_commit": paper.git_value(
            ("rev-parse", "HEAD"), REPOSITORY_ROOT
        ),
        "repository_dirty_at_plan": bool(
            paper.git_value(("status", "--porcelain"), REPOSITORY_ROOT)
        ),
        "artifact_hashes_sha256": artifact_hashes(),
        "topology": _json_copy(source["topology"]),
        "design": {
            "purpose": "regular-grid extension for Section V.C primary curves",
            "mode": mode,
            "selected_units": len(units),
            "deployment_percentages": list(percentages),
            "deployment_counts": {
                str(percent): deployment_count(percent)
                for percent in percentages
            },
            "deployment_orders": [order.order_id for order in orders],
            "deployment_order_role": "repeated block, not sample unit",
            "lanes": [D1_OPEN_DELEGATE, A1_OPEN_COMPETITION],
            "competition_attacker_class": "uniform",
            "physical_trials": len(trials),
            "formula": "units * percentages * random_orders * two_lanes",
            "shares_denominator": "fixed measured 589-AS ROV set",
            "source_units_resampled": False,
            "source_orders_changed": False,
        },
        "selected_units": raw_units,
        "deployment_orders": raw_orders,
        "trial_plan": _json_copy([asdict(trial) for trial in trials]),
        "expected_scenario_ids": {
            "source": "trial_plan[].scenario_id",
            "count": len(trials),
            "sorted_newline_sha256": expected_ids_sha256(trials),
        },
        "execution_contract": {
            "default_workers": 16 if mode == "formal" else 1,
            "multiprocessing_start_method": "spawn",
            "graph_build_location": "worker initializer",
            "graph_reused_within_worker": True,
            "parent_single_jsonl_writer": True,
            "single_trial_limit_seconds": paper.SINGLE_TRIAL_LIMIT_SECONDS,
            "per_worker_peak_rss_limit_bytes": (
                paper.PER_WORKER_RSS_LIMIT_BYTES
            ),
            "aggregate_rss_limit_bytes": paper.AGGREGATE_RSS_LIMIT_BYTES,
            "minimum_mem_available_bytes": paper.MIN_MEM_AVAILABLE_BYTES,
            "silent_retries": 0,
            "failed_scenario_resume": "explicit_retry_failures_flag_only",
            "accepted_campaign_output_mutation": False,
        },
    }
    document["manifest_sha256"] = manifest_sha256(document)
    validate_manifest(document)
    return document


def _validate_internal_artifact_bundle(document: Mapping[str, Any]) -> None:
    artifacts = document.get("artifact_hashes_sha256")
    if not isinstance(artifacts, Mapping) or not isinstance(
        artifacts.get("files"), Mapping
    ):
        raise GridExtensionError("manifest has no artifact-hash bundle")
    files = artifacts["files"]
    if any(
        not isinstance(name, str)
        or not isinstance(value, str)
        or len(value) != 64
        for name, value in files.items()
    ):
        raise GridExtensionError("manifest artifact hashes are malformed")
    if artifacts.get("bundle_sha256") != _bundle_sha256(files):
        raise GridExtensionError("manifest artifact bundle SHA256 mismatch")


def validate_manifest(document: Mapping[str, Any]) -> None:
    """Validate the complete immutable extension plan against its source."""

    if document.get("schema_version") != SCHEMA_VERSION:
        raise GridExtensionError("unsupported extension manifest schema")
    if document.get("experiment_id") != EXPERIMENT_ID:
        raise GridExtensionError("unexpected extension experiment identifier")
    if document.get("manifest_sha256") != manifest_sha256(document):
        raise GridExtensionError("extension manifest SHA256 mismatch")
    mode = document.get("mode")
    if not isinstance(mode, str):
        raise GridExtensionError("extension manifest has no mode")
    unit_count, order_ids, percentages, trial_count = _mode_contract(mode)

    source_record = document.get("source_campaign")
    if not isinstance(source_record, Mapping):
        raise GridExtensionError("extension manifest has no source campaign")
    if source_record.get("path") != _relative_path(SOURCE_MANIFEST_PATH):
        raise GridExtensionError("extension source-manifest path changed")
    if source_record.get("file_sha256") != _file_sha256(SOURCE_MANIFEST_PATH):
        raise GridExtensionError("accepted source-manifest file SHA256 mismatch")
    source = _load_source_manifest()
    if source_record.get("manifest_sha256") != source.get("manifest_sha256"):
        raise GridExtensionError("accepted source-manifest digest mismatch")
    expected_units, expected_orders, expected_percentages = (
        _selected_source_material(source, mode)
    )
    if expected_percentages != percentages:
        raise AssertionError("mode percentage contract drift")
    if document.get("selected_units") != expected_units:
        raise GridExtensionError("copied selected units differ from accepted manifest")
    if document.get("deployment_orders") != expected_orders:
        raise GridExtensionError(
            "copied random deployment orders differ from accepted manifest"
        )
    if source_record.get("selected_units_sha256") != _canonical_sha256(
        expected_units
    ):
        raise GridExtensionError("selected-unit canonical SHA256 mismatch")
    if source_record.get("deployment_orders_sha256") != _canonical_sha256(
        expected_orders
    ):
        raise GridExtensionError("deployment-order canonical SHA256 mismatch")
    if source_record.get("source_trials_reused") != 0 or source_record.get(
        "source_raw_results_modified"
    ) is not False:
        raise GridExtensionError("source-campaign mutation boundary is missing")
    if source_record.get("expected_selected_units") != EXPECTED_FORMAL_UNITS or (
        source_record.get("selected_units_copied") != unit_count
    ):
        raise GridExtensionError("source selected-unit count contract changed")
    if source_record.get("expected_random_orders") != EXPECTED_FORMAL_ORDERS or (
        source_record.get("random_orders_copied") != len(order_ids)
    ):
        raise GridExtensionError("source random-order count contract changed")

    raw_units = document.get("selected_units")
    raw_orders = document.get("deployment_orders")
    raw_trials = document.get("trial_plan")
    if not all(isinstance(value, list) for value in (raw_units, raw_orders, raw_trials)):
        raise GridExtensionError("units, orders, and trial plan must be lists")
    assert isinstance(raw_units, list)
    assert isinstance(raw_orders, list)
    assert isinstance(raw_trials, list)
    if len(raw_units) != unit_count or len(raw_orders) != len(order_ids):
        raise GridExtensionError("extension unit/order count differs from mode")
    if [item.get("order_id") for item in raw_orders] != list(order_ids):
        raise GridExtensionError("extension random-order sequence changed")
    if len({item.get("unit_id") for item in raw_units}) != unit_count:
        raise GridExtensionError("extension selected-unit identifiers repeat")
    if len({item.get("holder_asn") for item in raw_units}) != unit_count:
        raise GridExtensionError("extension selected holders repeat")
    if len({item.get("root_prefix") for item in raw_units}) != unit_count:
        raise GridExtensionError("extension selected roots repeat")

    topology = document.get("topology")
    if topology != source.get("topology"):
        raise GridExtensionError("extension topology differs from accepted manifest")
    if not isinstance(topology, Mapping) or topology.get(
        "fixed_rov_count"
    ) != paper.ROV_COUNT:
        raise GridExtensionError("extension fixed ROV set has changed")
    fixed_rov = frozenset(int(asn) for asn in topology["fixed_rov_asns"])
    if len(fixed_rov) != paper.ROV_COUNT:
        raise GridExtensionError("extension fixed ROV ASNs repeat")
    for raw_order in raw_orders:
        asns = tuple(int(asn) for asn in raw_order["asns"])
        if len(asns) != paper.ROV_COUNT or frozenset(asns) != fixed_rov:
            raise GridExtensionError("extension order is not the fixed ROV permutation")
        if raw_order.get("order_sha256") != paper._order_hash(asns):
            raise GridExtensionError("extension deployment-order SHA256 mismatch")
        expected_counts = {
            str(percent): deployment_count(percent) for percent in percentages
        }
        if raw_order.get("deployment_counts") != expected_counts:
            raise GridExtensionError("extension deployment counts changed")

    units = _units_from_documents(raw_units)
    orders = _orders_from_documents(raw_orders)
    expected_trials = _json_copy(
        [asdict(trial) for trial in build_trial_plan(units, orders, percentages)]
    )
    if raw_trials != expected_trials or len(raw_trials) != trial_count:
        raise GridExtensionError("extension trial-plan enumeration changed")
    identifiers = [trial.get("scenario_id") for trial in raw_trials]
    if any(not isinstance(value, str) for value in identifiers) or len(
        set(identifiers)
    ) != len(identifiers):
        raise GridExtensionError("extension scenario identifiers are invalid")
    ids_contract = document.get("expected_scenario_ids")
    digest = hashlib.sha256(
        ("\n".join(sorted(identifiers)) + "\n").encode("utf-8")
    ).hexdigest()
    if not isinstance(ids_contract, Mapping) or ids_contract.get(
        "count"
    ) != trial_count or ids_contract.get("sorted_newline_sha256") != digest:
        raise GridExtensionError("extension scenario-ID digest mismatch")

    design = document.get("design")
    if not isinstance(design, Mapping):
        raise GridExtensionError("extension manifest has no design contract")
    expected_design_values = {
        "mode": mode,
        "selected_units": unit_count,
        "deployment_percentages": list(percentages),
        "deployment_orders": list(order_ids),
        "lanes": [D1_OPEN_DELEGATE, A1_OPEN_COMPETITION],
        "competition_attacker_class": "uniform",
        "physical_trials": trial_count,
        "source_units_resampled": False,
        "source_orders_changed": False,
    }
    for field, expected in expected_design_values.items():
        if design.get(field) != expected:
            raise GridExtensionError(f"extension design field {field} changed")

    runtime = document.get("runtime_environment")
    engine = document.get("engine")
    if not isinstance(runtime, Mapping) or not isinstance(
        runtime.get("bgpy"), Mapping
    ):
        raise GridExtensionError("extension runtime fingerprint is missing")
    if not isinstance(engine, Mapping) or any(
        engine.get(key) != runtime["bgpy"].get(key)
        for key in ("version", "vendor_commit", "vendor_dirty")
    ):
        raise GridExtensionError("extension engine and runtime fingerprints differ")
    if runtime["bgpy"].get("vendor_dirty") is not False:
        raise GridExtensionError("extension cannot bind a dirty BGPy tree")
    _validate_internal_artifact_bundle(document)


def _ensure_safe_output_dir(output_dir: Path) -> None:
    resolved = output_dir.resolve()
    accepted = SOURCE_MANIFEST_PATH.parent.resolve()
    if resolved == accepted or accepted in resolved.parents:
        raise GridExtensionError(
            "refusing to use the accepted paper_campaign directory as output"
        )


def _atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    paper._atomic_write_json(path, document)


def write_manifest(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists():
        existing = load_manifest(path)
        if existing["manifest_sha256"] == document["manifest_sha256"]:
            return
        raise GridExtensionError(
            f"refusing to overwrite different extension manifest {path}"
        )
    _atomic_write_json(path, document)


def load_manifest(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise GridExtensionError("extension manifest root must be an object")
    validate_manifest(document)
    return document


def verify_artifact_hashes(manifest: Mapping[str, Any]) -> None:
    if manifest.get("artifact_hashes_sha256") != artifact_hashes():
        raise GridExtensionError(
            "current code or input hashes differ from extension manifest"
        )


def verify_runtime_environment(manifest: Mapping[str, Any]) -> None:
    try:
        paper.verify_runtime_environment(manifest)
    except paper.CampaignContractError as exc:
        raise GridExtensionError(str(exc)) from exc


def _resolve_da_asns(
    trial: paper.CampaignTrial,
    rov_asns: frozenset[int],
    orders: Mapping[str, paper.DeploymentOrder],
) -> frozenset[int]:
    if trial.policy_reference != "open_staged":
        raise GridExtensionError("extension trial is not an open staged policy")
    if trial.deployment_percent_target not in FORMAL_PERCENTAGES:
        raise GridExtensionError("extension trial percentage is outside the grid")
    if trial.order_id is None or trial.order_id not in orders:
        raise GridExtensionError(f"trial {trial.scenario_id} has no frozen order")
    count = deployment_count(trial.deployment_percent_target, len(rov_asns))
    return frozenset(orders[trial.order_id].asns[:count])


def run_extension_trial(
    engine: SimulationEngine,
    trial: paper.CampaignTrial,
    unit: paper.SampledUnit,
    *,
    rov_asns: frozenset[int],
    orders: Mapping[str, paper.DeploymentOrder],
    manifest_digest: str,
    worker_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Run one cell using the accepted campaign's propagation helpers."""

    if trial.lane not in {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}:
        raise GridExtensionError("extension trial has an unsupported lane")
    if (trial.lane == D1_OPEN_DELEGATE) != (trial.attacker_class is None):
        raise GridExtensionError("extension lane and attacker class disagree")
    if trial.lane == A1_OPEN_COMPETITION and trial.attacker_class != "uniform":
        raise GridExtensionError("extension competition lane is not uniform")
    pair = paper._unit_pair(unit, trial.attacker_class)
    da_asns = _resolve_da_asns(trial, rov_asns, orders)
    paper.S2ROV.configure(paper.make_open_policy(pair))
    spec = paper.PaperExecutionSpec(
        pair=pair,
        lane=trial.lane,
        deployment_percent=trial.deployment_percent_target,
        deployment_strategy=trial.deployment_strategy,
        scenario_id=trial.scenario_id,
    )
    started = perf_counter()
    rss_before = paper.current_rss_bytes()
    with paper.PeakRSSMonitor() as memory, paper.trial_alarm(
        paper.SINGLE_TRIAL_LIMIT_SECONDS
    ):
        scenario = paper.build_scenario(
            spec,
            rov_asns=rov_asns,
            da_asns=da_asns,
            engine=engine,
        )
        engine.setup(scenario)
        assignment_counts = paper.verify_policy_assignment(
            engine, rov_asns, da_asns
        )
        engine.run(propagation_round=0, scenario=scenario)
        outcomes, partition_checks = paper.analyze_grouped_outcomes(
            engine, pair, rov_asns
        )
    elapsed = perf_counter() - started
    if elapsed > paper.SINGLE_TRIAL_LIMIT_SECONDS:
        raise RuntimeError(
            f"{trial.scenario_id} exceeded {paper.SINGLE_TRIAL_LIMIT_SECONDS}s"
        )
    if memory.peak_bytes > paper.PER_WORKER_RSS_LIMIT_BYTES:
        raise RuntimeError(
            f"{trial.scenario_id} exceeded "
            f"{paper.PER_WORKER_RSS_LIMIT_BYTES} bytes RSS"
        )
    attacker_asn = attacker_degree = None
    if trial.attacker_class is not None:
        attacker_asn, attacker_degree = unit.attacker(trial.attacker_class)
    order_sha256 = orders[str(trial.order_id)].order_sha256
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "success",
        "scenario_id": trial.scenario_id,
        "manifest_sha256": manifest_digest,
        "unit_id": unit.unit_id,
        "pair_index": unit.pair_index,
        "source_row": unit.source_row,
        "cluster_id": unit.cluster_id,
        "holder_stratum": unit.holder_stratum,
        "holder_stratum_degree_range": unit.holder_stratum_degree_range,
        "N_h": unit.N_h,
        "n_h": unit.n_h,
        "stratum_population_N_h": unit.stratum_population_N_h,
        "stratum_sample_n_h": unit.stratum_sample_n_h,
        "design_weight": unit.design_weight,
        "lane": trial.lane,
        "announcement_set": trial.announcement_set,
        "policy_reference": trial.policy_reference,
        "attacker_class": trial.attacker_class,
        "deployment_strategy": trial.deployment_strategy,
        "deployment_seed": trial.deployment_seed,
        "deployment_percent_target": trial.deployment_percent_target,
        "deployment_count": len(da_asns),
        "deployment_fraction_actual": len(da_asns) / len(rov_asns),
        "order_id": trial.order_id,
        "order_sha256": order_sha256,
        "deployment_set_sha256": paper._asn_set_hash(da_asns),
        "shared_for_order_ids": list(trial.shared_for_order_ids),
        "root_prefix": unit.root_prefix,
        "leaf_prefix": unit.leaf_prefix,
        "holder_asn": unit.holder_asn,
        "delegate_asn": unit.delegate_asn,
        "holder_degree": unit.holder_degree,
        "delegate_degree": unit.delegate_degree,
        "attacker_asn": attacker_asn,
        "attacker_degree": attacker_degree,
        "fixed_rov_count": len(rov_asns),
        "policy_assignment_counts": assignment_counts,
        "outcomes": outcomes,
        "partition_checks": partition_checks,
        "elapsed_seconds": elapsed,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": paper.current_rss_bytes(),
        "peak_rss_bytes": memory.peak_bytes,
        **worker_metadata,
    }


def _validate_outcome_partitions(
    row: Mapping[str, Any], context: paper.ResultValidationContext
) -> None:
    scenario_id = str(row["scenario_id"])
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping) or set(outcomes) != {
        "all",
        "rov",
        "non_rov",
    }:
        raise GridExtensionError(f"{scenario_id}: invalid population outcomes")
    denominators = {
        "all": context.topology_asns,
        "rov": len(context.fixed_rov_asns),
        "non_rov": context.topology_asns - len(context.fixed_rov_asns),
    }
    for population, denominator in denominators.items():
        section = outcomes[population]
        if not isinstance(section, Mapping) or section.get(
            "denominator_asns"
        ) != denominator:
            raise GridExtensionError(
                f"{scenario_id}/{population}: denominator mismatch"
            )
        for partition, expected_keys in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            values = section.get(partition)
            if not isinstance(values, Mapping):
                raise GridExtensionError(
                    f"{scenario_id}/{population}: missing {partition}"
                )
            counts = values.get("counts")
            fractions = values.get("fractions")
            if not isinstance(counts, Mapping) or set(counts) != set(expected_keys):
                raise GridExtensionError(
                    f"{scenario_id}/{population}/{partition}: invalid counts"
                )
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counts.values()
            ) or sum(counts.values()) != denominator:
                raise GridExtensionError(
                    f"{scenario_id}/{population}/{partition}: incomplete partition"
                )
            if not isinstance(fractions, Mapping) or set(fractions) != set(counts):
                raise GridExtensionError(
                    f"{scenario_id}/{population}/{partition}: invalid fractions"
                )
            for outcome, count in counts.items():
                fraction = fractions[outcome]
                if isinstance(fraction, bool) or not isinstance(
                    fraction, (int, float)
                ) or not math.isclose(
                    float(fraction), count / denominator, rel_tol=0, abs_tol=1e-15
                ):
                    raise GridExtensionError(
                        f"{scenario_id}/{population}/{partition}/{outcome}: "
                        "fraction mismatch"
                    )
    for partition, expected_keys in (
        ("child", CHILD_OUTCOMES),
        ("destination", DESTINATION_OUTCOMES),
    ):
        for outcome in expected_keys:
            if outcomes["all"][partition]["counts"][outcome] != (
                outcomes["rov"][partition]["counts"][outcome]
                + outcomes["non_rov"][partition]["counts"][outcome]
            ):
                raise GridExtensionError(
                    f"{scenario_id}/{partition}/{outcome}: all != subgroups"
                )
    expected_checks = {
        f"{population}_{partition}_complete"
        for population in ("all", "rov", "non_rov")
        for partition in ("child", "destination")
    } | {"all_equals_rov_plus_non_rov"}
    checks = row.get("partition_checks")
    if not isinstance(checks, Mapping) or set(checks) != expected_checks or not all(
        value is True for value in checks.values()
    ):
        raise GridExtensionError(f"{scenario_id}: partition checks failed")


def _require_exact(
    row: Mapping[str, Any], scenario_id: str, field: str, expected: Any
) -> None:
    if field not in row or row[field] != expected:
        raise GridExtensionError(
            f"checkpoint {scenario_id}: {field}={row.get(field)!r}, "
            f"expected {expected!r}"
        )


def validate_success_result_row(
    row: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    context: paper.ResultValidationContext | None = None,
) -> None:
    """Revalidate one completed row against the extension manifest."""

    if row.get("status") != "success":
        raise GridExtensionError("checkpoint row is not successful")
    validation = context or paper._result_validation_context(manifest)
    scenario_id = row.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in validation.trial_by_id:
        raise GridExtensionError(
            f"checkpoint contains unknown scenario ID {scenario_id!r}"
        )
    _require_exact(row, scenario_id, "schema_version", SCHEMA_VERSION)
    _require_exact(
        row, scenario_id, "manifest_sha256", validation.manifest_sha256
    )
    trial = validation.trial_by_id[scenario_id]
    unit = validation.unit_by_id.get(str(trial["unit_id"]))
    if unit is None:
        raise GridExtensionError(f"checkpoint {scenario_id}: unknown unit")
    for field in (
        "unit_id",
        "pair_index",
        "lane",
        "announcement_set",
        "policy_reference",
        "attacker_class",
        "deployment_strategy",
        "deployment_seed",
        "deployment_percent_target",
        "order_id",
    ):
        _require_exact(row, scenario_id, field, trial[field])
    _require_exact(
        row,
        scenario_id,
        "shared_for_order_ids",
        list(trial.get("shared_for_order_ids", ())),
    )
    for field in (
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
    ):
        _require_exact(row, scenario_id, field, unit[field])

    attacker_class = trial["attacker_class"]
    if attacker_class is None:
        expected_attacker = expected_attacker_degree = None
    elif attacker_class == "uniform":
        expected_attacker = unit["uniform_attacker_asn"]
        expected_attacker_degree = unit["uniform_attacker_degree"]
    else:
        raise GridExtensionError(f"checkpoint {scenario_id}: attacker drift")
    _require_exact(row, scenario_id, "attacker_asn", expected_attacker)
    _require_exact(
        row, scenario_id, "attacker_degree", expected_attacker_degree
    )

    percent = int(trial["deployment_percent_target"])
    allowed = tuple(int(value) for value in manifest["design"]["deployment_percentages"])
    if percent not in allowed or percent not in FORMAL_PERCENTAGES:
        raise GridExtensionError(f"checkpoint {scenario_id}: percentage drift")
    order = validation.order_by_id.get(str(trial["order_id"]))
    if order is None:
        raise GridExtensionError(f"checkpoint {scenario_id}: missing order")
    count = deployment_count(percent, len(validation.fixed_rov_asns))
    expected_da = frozenset(int(asn) for asn in order["asns"][:count])
    _require_exact(row, scenario_id, "deployment_count", count)
    fraction = row.get("deployment_fraction_actual")
    if isinstance(fraction, bool) or not isinstance(
        fraction, (int, float)
    ) or not math.isclose(
        float(fraction), count / len(validation.fixed_rov_asns), rel_tol=0, abs_tol=1e-15
    ):
        raise GridExtensionError(
            f"checkpoint {scenario_id}: deployment fraction mismatch"
        )
    _require_exact(row, scenario_id, "order_sha256", order["order_sha256"])
    _require_exact(
        row,
        scenario_id,
        "deployment_set_sha256",
        paper._asn_set_hash(expected_da),
    )
    _require_exact(
        row,
        scenario_id,
        "fixed_rov_count",
        len(validation.fixed_rov_asns),
    )
    expected_assignments = {
        "bgp": validation.topology_asns - len(validation.fixed_rov_asns),
        "rov": len(validation.fixed_rov_asns) - count,
        "s2rov": count,
    }
    _require_exact(
        row,
        scenario_id,
        "policy_assignment_counts",
        expected_assignments,
    )

    attempt = row.get("attempt")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 1
        or row.get("prior_failure_count") != attempt - 1
        or row.get("retry_authorized") is not (attempt > 1)
    ):
        raise GridExtensionError(
            f"checkpoint {scenario_id}: invalid attempt provenance"
        )
    for field in (
        "worker_pid",
        "worker_trial_sequence",
        "worker_graph_build_peak_rss_bytes",
        "rss_before_bytes",
        "rss_after_bytes",
        "peak_rss_bytes",
    ):
        value = row.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise GridExtensionError(
                f"checkpoint {scenario_id}: invalid runtime field {field}"
            )
    for field in ("worker_graph_build_seconds", "elapsed_seconds"):
        value = row.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise GridExtensionError(
                f"checkpoint {scenario_id}: invalid runtime field {field}"
            )
    if row["elapsed_seconds"] > paper.SINGLE_TRIAL_LIMIT_SECONDS:
        raise GridExtensionError(f"checkpoint {scenario_id}: trial timeout")
    if row["peak_rss_bytes"] > paper.PER_WORKER_RSS_LIMIT_BYTES:
        raise GridExtensionError(f"checkpoint {scenario_id}: worker RSS limit")
    _validate_outcome_partitions(row, validation)


def _worker_initializer(manifest_path: str) -> None:
    global _WORKER_CONTEXT
    manifest = load_manifest(Path(manifest_path))
    verify_artifact_hashes(manifest)
    verify_runtime_environment(manifest)
    units = {
        unit.unit_id: unit
        for unit in _units_from_documents(manifest["selected_units"])
    }
    orders = {
        order.order_id: order
        for order in _orders_from_documents(manifest["deployment_orders"])
    }
    started = perf_counter()
    with paper.PeakRSSMonitor() as memory:
        graph = paper.build_fixed_graph()
    _WORKER_CONTEXT = WorkerContext(
        engine=SimulationEngine(graph),
        units=units,
        orders=orders,
        rov_asns=frozenset(manifest["topology"]["fixed_rov_asns"]),
        manifest_sha256=manifest["manifest_sha256"],
        graph_build_seconds=perf_counter() - started,
        graph_build_peak_rss_bytes=memory.peak_bytes,
    )


def _worker_execute(raw_trial: Mapping[str, Any]) -> dict[str, Any]:
    context = _WORKER_CONTEXT
    if context is None:
        raise RuntimeError("extension worker was not initialized")
    attempt = raw_trial.get("_attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise RuntimeError("extension worker task has no attempt number")
    trial = paper.CampaignTrial(
        **{
            **{key: value for key, value in raw_trial.items() if key != "_attempt"},
            "shared_for_order_ids": tuple(
                raw_trial.get("shared_for_order_ids", ())
            ),
        }
    )
    context.sequence += 1
    try:
        if context.graph_build_peak_rss_bytes > paper.PER_WORKER_RSS_LIMIT_BYTES:
            raise RuntimeError("extension worker graph exceeded RSS contract")
        return run_extension_trial(
            context.engine,
            trial,
            context.units[trial.unit_id],
            rov_asns=context.rov_asns,
            orders=context.orders,
            manifest_digest=context.manifest_sha256,
            worker_metadata={
                "worker_pid": os.getpid(),
                "worker_trial_sequence": context.sequence,
                "worker_graph_build_seconds": context.graph_build_seconds,
                "worker_graph_build_peak_rss_bytes": (
                    context.graph_build_peak_rss_bytes
                ),
                "attempt": attempt,
                "prior_failure_count": attempt - 1,
                "retry_authorized": attempt > 1,
            },
        )
    except Exception as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "scenario_id": trial.scenario_id,
            "manifest_sha256": context.manifest_sha256,
            "worker_pid": os.getpid(),
            "attempt": attempt,
            "prior_failure_count": attempt - 1,
            "retry_authorized": attempt > 1,
            "failed_at_utc": utc_now(),
            "exception": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }


def scan_results_jsonl(
    path: Path,
    manifest: Mapping[str, Any],
    *,
    repair_truncated_tail: bool = False,
) -> tuple[frozenset[str], dict[str, Any] | None]:
    if not path.exists():
        return frozenset(), None
    context = paper._result_validation_context(manifest)
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    completed: set[str] = set()
    offset = 0
    repair: dict[str, Any] | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            offset += len(line)
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            is_last = index == len(lines) - 1
            if not (is_last and repair_truncated_tail):
                raise GridExtensionError(
                    f"invalid extension JSONL at byte {offset}: {exc}; pass "
                    "--repair-truncated-tail only for a damaged final line"
                ) from exc
            with path.open("r+b") as handle:
                handle.truncate(offset)
            repair = {
                "repaired_at_utc": utc_now(),
                "truncated_from_bytes": len(raw),
                "truncated_to_bytes": offset,
            }
            break
        if not isinstance(row, dict):
            raise GridExtensionError(f"non-object extension row at byte {offset}")
        validate_success_result_row(row, manifest, context=context)
        scenario_id = str(row["scenario_id"])
        if scenario_id in completed:
            raise GridExtensionError(
                f"extension checkpoint repeats scenario ID {scenario_id}"
            )
        completed.add(scenario_id)
        offset += len(line)
    return frozenset(completed), repair


def scan_failures_jsonl(
    path: Path, manifest: Mapping[str, Any]
) -> dict[str, tuple[Mapping[str, Any], ...]]:
    try:
        return paper.scan_failures_jsonl(path, manifest)
    except paper.CampaignContractError as exc:
        raise GridExtensionError(str(exc)) from exc


def _checkpoint_document(
    manifest: Mapping[str, Any],
    completed: set[str],
    *,
    started_at_utc: str | None,
    last_scenario_id: str | None,
    repair: Mapping[str, Any] | None,
) -> dict[str, Any]:
    planned = len(manifest["trial_plan"])
    if len(completed) == planned:
        status = "complete"
    elif not completed and started_at_utc is None:
        status = "planned"
    else:
        status = "in_progress"
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": EXPERIMENT_ID,
        "mode": manifest["mode"],
        "manifest_sha256": manifest["manifest_sha256"],
        "started_at_utc": started_at_utc,
        "updated_at_utc": utc_now(),
        "completed_trials": len(completed),
        "planned_trials": planned,
        "remaining_trials": planned - len(completed),
        "last_scenario_id": last_scenario_id,
        "truncated_tail_repair": repair,
        "status": status,
    }


def campaign_status(
    output_dir: Path, *, repair_truncated_tail: bool = False
) -> dict[str, Any]:
    _ensure_safe_output_dir(output_dir)
    manifest = load_manifest(output_dir / "manifest.json")
    completed, repair = scan_results_jsonl(
        output_dir / "raw_scenarios.jsonl",
        manifest,
        repair_truncated_tail=repair_truncated_tail,
    )
    failures = scan_failures_jsonl(output_dir / "failures.jsonl", manifest)
    unresolved = sorted(set(failures).difference(completed))
    status = _checkpoint_document(
        manifest,
        set(completed),
        started_at_utc=None,
        last_scenario_id=None,
        repair=repair,
    )
    status.update(
        {
            "failed_attempts_recorded": sum(len(rows) for rows in failures.values()),
            "unresolved_failed_scenarios": len(unresolved),
            "unresolved_failure_ids": unresolved[:20],
        }
    )
    if unresolved:
        status["status"] = "failed_closed"
    return status


def run_campaign(
    output_dir: Path,
    *,
    workers: int,
    max_new_trials: int | None,
    dry_run: bool,
    repair_truncated_tail: bool,
    fsync_every: int,
    checkpoint_every: int,
    retry_failures: bool = False,
) -> dict[str, Any]:
    """Run or resume an extension manifest with no implicit retries."""

    _ensure_safe_output_dir(output_dir)
    if workers < 1 or fsync_every < 1 or checkpoint_every < 1:
        raise GridExtensionError("workers and checkpoint intervals must be positive")
    manifest_path = output_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    verify_artifact_hashes(manifest)
    verify_runtime_environment(manifest)
    results_path = output_dir / "raw_scenarios.jsonl"
    failures_path = output_dir / "failures.jsonl"
    completed_frozen, repair = scan_results_jsonl(
        results_path,
        manifest,
        repair_truncated_tail=repair_truncated_tail,
    )
    completed = set(completed_frozen)
    failure_history = scan_failures_jsonl(failures_path, manifest)
    unresolved = sorted(set(failure_history).difference(completed))
    if unresolved and not retry_failures:
        raise GridExtensionError(
            f"{len(unresolved)} unresolved failed scenario(s); inspect "
            "failures.jsonl and explicitly pass --retry-failures "
            f"(first: {unresolved[0]})"
        )
    pending = [
        {
            **trial,
            "_attempt": len(failure_history.get(trial["scenario_id"], ())) + 1,
        }
        for trial in manifest["trial_plan"]
        if trial["scenario_id"] not in completed
    ]
    if max_new_trials is not None:
        if max_new_trials < 0:
            raise GridExtensionError("max-new-trials cannot be negative")
        pending = pending[:max_new_trials]
    started_at = utc_now()
    status = _checkpoint_document(
        manifest,
        completed,
        started_at_utc=started_at,
        last_scenario_id=None,
        repair=repair,
    )
    status.update(
        {
            "workers_requested": workers,
            "new_trials_selected": len(pending),
            "dry_run": dry_run,
            "retry_failures_authorized": retry_failures,
            "failed_attempts_recorded": sum(
                len(rows) for rows in failure_history.values()
            ),
            "unresolved_failed_scenarios_before_run": len(unresolved),
            "next_scenario_ids": [
                trial["scenario_id"] for trial in pending[:10]
            ],
        }
    )
    if dry_run:
        status["status"] = "dry_run"
        return status
    if not pending:
        return status
    available_before = paper._mem_available_bytes()
    if available_before < paper.MIN_MEM_AVAILABLE_BYTES:
        raise paper.ParentResourceStop(
            f"MemAvailable {available_before} below {paper.MIN_MEM_AVAILABLE_BYTES}"
        )

    checkpoint_path = output_dir / "checkpoint.json"
    validation_context = paper._result_validation_context(manifest)
    process_context = multiprocessing.get_context("spawn")
    last_scenario_id: str | None = None
    started = perf_counter()
    with process_context.Pool(
        processes=workers,
        initializer=_worker_initializer,
        initargs=(str(manifest_path),),
    ) as pool:
        monitor = paper.ParentResourceMonitor(
            lambda: [process.pid for process in pool._pool if process.pid]
        )

        def write_failed_checkpoint(reason: str) -> None:
            failed = _checkpoint_document(
                manifest,
                completed,
                started_at_utc=started_at,
                last_scenario_id=last_scenario_id,
                repair=repair,
            )
            failed["status"] = "failed_closed"
            failed["failure_reason"] = reason
            failed["run_wall_seconds"] = perf_counter() - started
            failed["workers"] = workers
            failed["peak_aggregate_rss_bytes"] = monitor.peak_aggregate_rss_bytes
            failed["minimum_mem_available_bytes"] = (
                monitor.minimum_mem_available_bytes
            )
            failed["retry_failures_authorized"] = retry_failures
            _atomic_write_json(checkpoint_path, failed)

        def resource_signal_handler(_signum: int, _frame: object) -> None:
            reason = monitor.breach_reason or "parent resource monitor stopped run"
            write_failed_checkpoint(reason)
            raise paper.ParentResourceStop(reason)

        previous_handler = signal.getsignal(signal.SIGUSR1)
        signal.signal(signal.SIGUSR1, resource_signal_handler)
        monitor.start()
        try:
            for result_index, result in enumerate(
                pool.imap_unordered(_worker_execute, pending, chunksize=1), start=1
            ):
                if result.get("status") != "success":
                    paper._append_jsonl(failures_path, result, fsync=True)
                    write_failed_checkpoint(
                        f"worker failed {result.get('scenario_id')}"
                    )
                    raise RuntimeError(
                        f"worker failed {result.get('scenario_id')}: "
                        f"{result.get('exception')}"
                    )
                scenario_id = str(result["scenario_id"])
                if scenario_id in completed:
                    raise GridExtensionError(
                        f"worker returned completed scenario {scenario_id}"
                    )
                try:
                    validate_success_result_row(
                        result, manifest, context=validation_context
                    )
                except (GridExtensionError, paper.CampaignContractError) as exc:
                    attempt = len(failure_history.get(scenario_id, ())) + 1
                    semantic_failure = {
                        "schema_version": SCHEMA_VERSION,
                        "status": "failed",
                        "scenario_id": scenario_id,
                        "manifest_sha256": manifest["manifest_sha256"],
                        "worker_pid": result.get("worker_pid"),
                        "attempt": attempt,
                        "prior_failure_count": attempt - 1,
                        "retry_authorized": attempt > 1,
                        "failed_at_utc": utc_now(),
                        "exception": {
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    }
                    paper._append_jsonl(
                        failures_path, semantic_failure, fsync=True
                    )
                    write_failed_checkpoint(str(exc))
                    raise
                paper._append_jsonl(
                    results_path,
                    result,
                    fsync=(
                        result_index % fsync_every == 0
                        or result_index == len(pending)
                    ),
                )
                completed.add(scenario_id)
                last_scenario_id = scenario_id
                if (
                    result_index % checkpoint_every == 0
                    or result_index == len(pending)
                ):
                    checkpoint = _checkpoint_document(
                        manifest,
                        completed,
                        started_at_utc=started_at,
                        last_scenario_id=last_scenario_id,
                        repair=repair,
                    )
                    checkpoint["run_wall_seconds"] = perf_counter() - started
                    checkpoint["workers"] = workers
                    checkpoint["peak_aggregate_rss_bytes"] = (
                        monitor.peak_aggregate_rss_bytes
                    )
                    checkpoint["minimum_mem_available_bytes"] = (
                        monitor.minimum_mem_available_bytes
                    )
                    checkpoint["retry_failures_authorized"] = retry_failures
                    _atomic_write_json(checkpoint_path, checkpoint)
        finally:
            monitor.stop()
            signal.signal(signal.SIGUSR1, previous_handler)

    final = _checkpoint_document(
        manifest,
        completed,
        started_at_utc=started_at,
        last_scenario_id=last_scenario_id,
        repair=repair,
    )
    final["run_wall_seconds"] = perf_counter() - started
    final["workers"] = workers
    final["peak_aggregate_rss_bytes"] = monitor.peak_aggregate_rss_bytes
    final["minimum_mem_available_bytes"] = monitor.minimum_mem_available_bytes
    final["retry_failures_authorized"] = retry_failures
    _atomic_write_json(checkpoint_path, final)
    return final


def plan_campaign(output_dir: Path, *, mode: str = "formal") -> dict[str, Any]:
    """Freeze a new extension manifest and zero-trial checkpoint."""

    _ensure_safe_output_dir(output_dir)
    for name in ("raw_scenarios.jsonl", "failures.jsonl"):
        path = output_dir / name
        if path.exists() and path.stat().st_size:
            raise GridExtensionError(
                f"refusing to plan over nonempty extension checkpoint {path}"
            )
    document = build_manifest_document(mode)
    write_manifest(output_dir / "manifest.json", document)
    checkpoint_path = output_dir / "checkpoint.json"
    if not checkpoint_path.exists():
        checkpoint = _checkpoint_document(
            document,
            set(),
            started_at_utc=None,
            last_scenario_id=None,
            repair=None,
        )
        _atomic_write_json(checkpoint_path, checkpoint)
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="write manifest; run no trials")
    plan.add_argument("--mode", choices=("formal", "smoke"), default="formal")
    plan.add_argument("--output-dir", type=Path)

    run = subparsers.add_parser("run", help="execute or resume manifest")
    run.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    run.add_argument("--workers", type=int, default=16)
    run.add_argument("--max-new-trials", type=int)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--repair-truncated-tail", action="store_true")
    run.add_argument(
        "--retry-failures",
        action="store_true",
        help="explicitly authorize retries recorded in failures.jsonl",
    )
    run.add_argument("--fsync-every", type=int, default=8)
    run.add_argument("--checkpoint-every", type=int, default=8)

    status = subparsers.add_parser("status", help="validate checkpoint and report")
    status.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    status.add_argument("--repair-truncated-tail", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "plan":
        output_dir = args.output_dir
        if output_dir is None:
            output_dir = DEFAULT_OUTPUT_DIR if args.mode == "formal" else DEFAULT_SMOKE_DIR
        manifest = plan_campaign(output_dir, mode=args.mode)
        print(
            json.dumps(
                {
                    "status": manifest["status"],
                    "mode": manifest["mode"],
                    "manifest": str(output_dir / "manifest.json"),
                    "manifest_sha256": manifest["manifest_sha256"],
                    "units": len(manifest["selected_units"]),
                    "orders": len(manifest["deployment_orders"]),
                    "trials": len(manifest["trial_plan"]),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "run":
        result = run_campaign(
            args.output_dir,
            workers=args.workers,
            max_new_trials=args.max_new_trials,
            dry_run=args.dry_run,
            repair_truncated_tail=args.repair_truncated_tail,
            fsync_every=args.fsync_every,
            checkpoint_every=args.checkpoint_every,
            retry_failures=args.retry_failures,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "status":
        result = campaign_status(
            args.output_dir,
            repair_truncated_tail=args.repair_truncated_tail,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
