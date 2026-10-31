"""Plan, run, resume, and validate the Phase-8 sibling endpoint campaign.

The campaign is deliberately separate from the frozen Phase-7 runner and
artifacts.  It imports the pinned graph and policy adapters read-only, copies
the 200-holder design from the Phase-7 manifest, and writes only below the
Phase-8 output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import signal
import subprocess
import threading
import traceback
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable, Mapping, Sequence

from frozendict import frozendict
from roa_checker import ROA

from bgpy.simulation_engine import BGP, ROV, SimulationEngine
from bgpy.simulation_framework import ScenarioConfig
from phase4_encoding.scripts.utils.daroa import ValidationState
from phase7_simulation.campaign.full_graph_gate import (
    DAROV,
    FixedDeploymentScenario,
    PairSpec,
    PeakRSSMonitor,
    build_fixed_graph,
    current_rss_bytes,
    make_open_policy,
    origin_announcement,
    trial_alarm,
    verify_policy_assignment,
)
from phase7_simulation.campaign.paper_campaign import (
    manifest_sha256 as phase7_manifest_sha256,
)
from phase7_simulation.campaign.paper_campaign import runtime_environment_fingerprint


SCHEMA_VERSION = 1
VERSION_LABEL = "phase8-sibling-endpoint-v1"
EXPECTED_HOLDERS = 200
EXPECTED_TRIALS = 600
EXPECTED_ROV_ASNS = 589
BENCHMARK_TRIALS = 32
BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_SEED = 20260823

SINGLE_TRIAL_LIMIT_SECONDS = 60.0
PER_WORKER_RSS_LIMIT_BYTES = 1536 * 1024**2
AGGREGATE_RSS_LIMIT_BYTES = 24 * 1024**3
MIN_MEM_AVAILABLE_BYTES = 16 * 1024**3

B1_SIBLING = "B1_sibling_aggregate"
A1_SIBLING = "A1_open_sibling"
LANE_PERCENTAGES = ((B1_SIBLING, 0), (A1_SIBLING, 0), (A1_SIBLING, 100))
POPULATIONS = ("all", "rov", "non_rov")

ROUTE_OUTCOMES = {
    "sibling_route": ("attacker", "absent"),
    "leaf_route": ("delegate", "absent"),
}
DESTINATION_OUTCOMES = {
    "sibling_destination": (
        "attacker",
        "holder_fallback",
        "disconnected",
        "loop",
    ),
    "leaf_destination": (
        "delegate",
        "holder_fallback",
        "disconnected",
        "loop",
    ),
}
PARTITION_OUTCOMES = {**ROUTE_OUTCOMES, **DESTINATION_OUTCOMES}

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PHASE8_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PHASE8_ROOT / "results"
PHASE7_ROOT = REPOSITORY_ROOT / "phase7_simulation"
PHASE7_RESULT_ROOT = PHASE7_ROOT / "results" / "paper_campaign"
PHASE7_MANIFEST = PHASE7_RESULT_ROOT / "manifest.json"
PHASE7_RAW_RESULTS = PHASE7_RESULT_ROOT / "raw_scenarios.jsonl"
TOPOLOGY_PATH = PHASE7_ROOT / "data" / "inputs" / "as-rel-fixed.txt"
ROV_JSON_PATH = PHASE7_ROOT / "data" / "inputs" / "rov_ases.json"
DEPENDENCY_LOCK_PATH = PHASE7_ROOT / "requirements-bgpy.lock.txt"
THIRD_PARTY_LOCK_PATH = PHASE7_ROOT / "third_party.lock.json"


class Phase8ContractError(ValueError):
    """Raised whenever a Phase-8 artifact violates the frozen contract."""


class Phase8ResourceStop(RuntimeError):
    """Raised when a declared time or memory gate is crossed."""


def require_phase8_path(path: Path, *, label: str) -> Path:
    """Reject writes or campaign inputs outside the isolated Phase-8 tree."""

    resolved = path.resolve()
    root = PHASE8_ROOT.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise Phase8ContractError(f"{label} must be below {root}")
    return resolved


@dataclass(frozen=True)
class SiblingUnit:
    """One copied Phase-7 holder unit plus its deterministic sibling prefix."""

    unit_id: str
    pair_index: int
    source_row: int
    holder_asn: int
    delegate_asn: int
    uniform_attacker_asn: int
    holder_degree: int
    delegate_degree: int
    uniform_attacker_degree: int
    holder_stratum: str
    holder_stratum_degree_range: str
    N_h: int
    n_h: int
    design_weight: float
    root_prefix: str
    leaf_prefix: str
    sibling_prefix: str


@dataclass(frozen=True)
class SiblingTrial:
    """One physical endpoint trial."""

    scenario_id: str
    unit_id: str
    pair_index: int
    lane: str
    deployment_percent_target: int


@dataclass
class WorkerContext:
    engine: SimulationEngine
    units: dict[str, SiblingUnit]
    rov_asns: frozenset[int]
    manifest_sha256: str
    graph_build_seconds: float
    graph_build_peak_rss_bytes: int
    sequence: int = 0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(document: Mapping[str, Any], omitted: str) -> str:
    core = dict(document)
    core.pop(omitted, None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def manifest_sha256(document: Mapping[str, Any]) -> str:
    return canonical_sha256(document, "manifest_sha256")


def sorted_ids_sha256(ids: Iterable[str]) -> str:
    payload = "\n".join(sorted(ids)) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def asn_set_sha256(asns: Iterable[int]) -> str:
    """Match Phase 7's canonical unordered-AS-set hash."""

    payload = "\n".join(str(asn) for asn in sorted(asns)) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def canonical_records_sha256(records: Iterable[Mapping[str, Any]], *, key: str) -> str:
    """Hash canonical JSON records after a stable sort by ``key``."""

    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: str(item[key])):
        digest.update(
            json.dumps(
                record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        )
        digest.update(b"\n")
    return digest.hexdigest()


def atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def append_jsonl(path: Path, document: Mapping[str, Any], *, fsync: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())


def git_value(args: Sequence[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def immediate_sibling(root_prefix: str, leaf_prefix: str) -> str:
    """Return the other child of the selected leaf's immediate parent."""

    root = ip_network(root_prefix, strict=True)
    leaf = ip_network(leaf_prefix, strict=True)
    if not isinstance(root, IPv4Network) or not isinstance(leaf, IPv4Network):
        raise Phase8ContractError("Phase 8 supports the frozen IPv4 units only")
    if root == leaf or not leaf.subnet_of(root):
        raise Phase8ContractError(f"leaf {leaf} is not a proper child of root {root}")
    if leaf.prefixlen >= 32:
        raise Phase8ContractError(f"leaf {leaf} has no immediate sibling child")
    parent = leaf.supernet(prefixlen_diff=1)
    candidates = tuple(
        prefix for prefix in parent.subnets(new_prefix=leaf.prefixlen) if prefix != leaf
    )
    if len(candidates) != 1:
        raise Phase8ContractError(f"leaf {leaf} does not yield one sibling")
    sibling = candidates[0]
    if not sibling.subnet_of(root) or sibling.overlaps(leaf):
        raise Phase8ContractError(f"derived sibling {sibling} violates root/leaf scope")
    return str(sibling)


def load_phase7_manifest() -> dict[str, Any]:
    document = json.loads(PHASE7_MANIFEST.read_text(encoding="utf-8"))
    if document.get("manifest_sha256") != phase7_manifest_sha256(document):
        raise Phase8ContractError("Phase-7 parent manifest self-hash is invalid")
    if len(document.get("selected_units", ())) != EXPECTED_HOLDERS:
        raise Phase8ContractError("Phase-7 parent does not contain 200 holders")
    topology = document.get("topology", {})
    if int(topology.get("fixed_rov_count", -1)) != EXPECTED_ROV_ASNS:
        raise Phase8ContractError("Phase-7 parent does not contain 589 ROV ASes")
    return document


def units_from_phase7(parent: Mapping[str, Any]) -> tuple[SiblingUnit, ...]:
    units: list[SiblingUnit] = []
    for raw in parent["selected_units"]:
        unit = SiblingUnit(
            unit_id=str(raw["unit_id"]),
            pair_index=int(raw["pair_index"]),
            source_row=int(raw["source_row"]),
            holder_asn=int(raw["holder_asn"]),
            delegate_asn=int(raw["delegate_asn"]),
            uniform_attacker_asn=int(raw["uniform_attacker_asn"]),
            holder_degree=int(raw["holder_degree"]),
            delegate_degree=int(raw["delegate_degree"]),
            uniform_attacker_degree=int(raw["uniform_attacker_degree"]),
            holder_stratum=str(raw["holder_stratum"]),
            holder_stratum_degree_range=str(raw["holder_stratum_degree_range"]),
            N_h=int(raw["N_h"]),
            n_h=int(raw["n_h"]),
            design_weight=float(raw["design_weight"]),
            root_prefix=str(raw["root_prefix"]),
            leaf_prefix=str(raw["leaf_prefix"]),
            sibling_prefix=immediate_sibling(
                str(raw["root_prefix"]), str(raw["leaf_prefix"])
            ),
        )
        if len({unit.holder_asn, unit.delegate_asn, unit.uniform_attacker_asn}) != 3:
            raise Phase8ContractError(f"{unit.unit_id} endpoint ASNs are not distinct")
        pair = unit_pair(unit)
        policy = make_open_policy(pair)
        if policy.max_length != ip_network(unit.leaf_prefix).prefixlen:
            raise Phase8ContractError(f"{unit.unit_id} policy max-length drift")
        if (
            policy.validate_route(unit.leaf_prefix, unit.delegate_asn)
            != ValidationState.DELEGATED
            or policy.validate_route(unit.sibling_prefix, unit.uniform_attacker_asn)
            != ValidationState.DELEGATED
            or policy.validate_route(unit.root_prefix, unit.uniform_attacker_asn)
            != ValidationState.INVALID
        ):
            raise Phase8ContractError(f"{unit.unit_id} policy boundary failed")
        units.append(unit)
    if len(units) != EXPECTED_HOLDERS:
        raise Phase8ContractError("Phase-8 unit count differs from 200")
    if len({unit.unit_id for unit in units}) != len(units):
        raise Phase8ContractError("Phase-8 unit IDs repeat")
    if len({unit.holder_asn for unit in units}) != len(units):
        raise Phase8ContractError("Phase-8 holder ASNs repeat")
    if len({unit.sibling_prefix for unit in units}) != len(units):
        raise Phase8ContractError("Phase-8 sibling prefixes repeat")
    strata: dict[str, int] = {}
    for unit in units:
        strata[unit.holder_stratum] = strata.get(unit.holder_stratum, 0) + 1
    if strata != {"S1": 50, "S2": 50, "S3": 50, "S4": 50}:
        raise Phase8ContractError(f"unexpected holder strata {strata}")
    return tuple(sorted(units, key=lambda item: item.pair_index))


def unit_pair(unit: SiblingUnit) -> PairSpec:
    stratum_index = int(unit.holder_stratum.removeprefix("S"))
    return PairSpec(
        pair_index=unit.pair_index,
        source_row=unit.source_row,
        root_prefix=unit.root_prefix,
        holder_asn=unit.holder_asn,
        leaf_prefix=unit.leaf_prefix,
        delegate_asn=unit.delegate_asn,
        holder_degree=unit.holder_degree,
        delegate_degree=unit.delegate_degree,
        degree_bin=stratum_index,
        attacker_asn=unit.uniform_attacker_asn,
        attacker_class="uniform",
        attacker_degree=unit.uniform_attacker_degree,
    )


def scenario_id(unit: SiblingUnit, lane: str, percent: int) -> str:
    return f"{unit.unit_id}__{lane}__pct-{percent:03d}"


def build_trial_plan(
    units: Sequence[SiblingUnit],
) -> tuple[tuple[SiblingTrial, ...], tuple[str, ...]]:
    all_trials = {
        (unit.unit_id, lane, percent): SiblingTrial(
            scenario_id(unit, lane, percent),
            unit.unit_id,
            unit.pair_index,
            lane,
            percent,
        )
        for unit in units
        for lane, percent in LANE_PERCENTAGES
    }
    benchmark: list[SiblingTrial] = []
    for stratum_index, stratum in enumerate(("S1", "S2", "S3", "S4")):
        members = [unit for unit in units if unit.holder_stratum == stratum][:8]
        if len(members) != 8:
            raise Phase8ContractError(f"benchmark lacks eight {stratum} holders")
        for local_index, unit in enumerate(members):
            lane, percent = LANE_PERCENTAGES[(local_index + stratum_index) % 3]
            benchmark.append(all_trials[(unit.unit_id, lane, percent)])
    benchmark_ids = tuple(trial.scenario_id for trial in benchmark)
    remaining = sorted(
        (
            trial
            for trial in all_trials.values()
            if trial.scenario_id not in set(benchmark_ids)
        ),
        key=lambda trial: (
            trial.pair_index,
            LANE_PERCENTAGES.index((trial.lane, trial.deployment_percent_target)),
        ),
    )
    trials = tuple(benchmark) + tuple(remaining)
    if len(trials) != EXPECTED_TRIALS or len({t.scenario_id for t in trials}) != len(
        trials
    ):
        raise Phase8ContractError("Phase-8 trial plan is not 600 unique scenarios")
    return trials, benchmark_ids


def artifact_hashes() -> dict[str, Any]:
    paths = {
        "phase8_runner": Path(__file__).resolve(),
        "phase8_analyzer": PHASE8_ROOT / "analyze.py",
        "phase8_contract": PHASE8_ROOT / "EXPERIMENT_CONTRACT.md",
        "phase8_readme": PHASE8_ROOT / "README.md",
        "phase8_test_runner": PHASE8_ROOT / "tests" / "test_runner.py",
        "phase8_test_analyzer": PHASE8_ROOT / "tests" / "test_analyze.py",
        "phase8_pre_execution_failure_record": (
            PHASE8_ROOT / "failed_plan_relative_path_20260823" / "failure_record.json"
        ),
        "phase7_parent_manifest": PHASE7_MANIFEST,
        "phase7_parent_raw_results": PHASE7_RAW_RESULTS,
        "phase7_topology": TOPOLOGY_PATH,
        "phase7_rov_json": ROV_JSON_PATH,
        "phase7_full_graph_gate": (PHASE7_ROOT / "campaign" / "full_graph_gate.py"),
        "phase7_paper_campaign": (PHASE7_ROOT / "campaign" / "paper_campaign.py"),
        "phase7_darov_policy": PHASE7_ROOT / "darov" / "policy.py",
        "phase4_daroa_oracle": (
            REPOSITORY_ROOT / "phase4_encoding" / "scripts" / "utils" / "daroa.py"
        ),
        "phase4_as_set": (
            REPOSITORY_ROOT / "phase4_encoding" / "scripts" / "utils" / "as_set.py"
        ),
        "dependency_lock": DEPENDENCY_LOCK_PATH,
        "third_party_lock": THIRD_PARTY_LOCK_PATH,
    }
    files = {name: file_sha256(path) for name, path in paths.items()}
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(value.encode())
        digest.update(b"\n")
    return {"files": files, "bundle_sha256": digest.hexdigest()}


def build_manifest() -> dict[str, Any]:
    parent = load_phase7_manifest()
    units = units_from_phase7(parent)
    trials, benchmark_ids = build_trial_plan(units)
    rov_asns = tuple(sorted(int(asn) for asn in parent["topology"]["fixed_rov_asns"]))
    if len(rov_asns) != EXPECTED_ROV_ASNS or len(set(rov_asns)) != len(rov_asns):
        raise Phase8ContractError("fixed ROV set is not 589 unique ASNs")
    runtime = runtime_environment_fingerprint()
    created = utc_now()
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "created_at_utc": created,
        "status": "planned_not_executed",
        "material_passport": {
            "origin_skill": "academic-research-suite/experiment-agent",
            "origin_mode": "run+validate",
            "origin_date": created[:10],
            "verification_status": "UNVERIFIED",
            "version_label": VERSION_LABEL,
        },
        "parent_phase7": {
            "manifest_path": PHASE7_MANIFEST.relative_to(REPOSITORY_ROOT).as_posix(),
            "manifest_file_sha256": file_sha256(PHASE7_MANIFEST),
            "manifest_canonical_sha256": parent["manifest_sha256"],
            "raw_results_path": PHASE7_RAW_RESULTS.relative_to(
                REPOSITORY_ROOT
            ).as_posix(),
            "raw_results_sha256": file_sha256(PHASE7_RAW_RESULTS),
        },
        "runtime_environment": runtime,
        "repository_commit": git_value(("rev-parse", "HEAD"), REPOSITORY_ROOT),
        "repository_dirty_at_plan": bool(
            git_value(("status", "--porcelain"), REPOSITORY_ROOT)
        ),
        "artifact_hashes": artifact_hashes(),
        "topology": {
            "path": TOPOLOGY_PATH.relative_to(REPOSITORY_ROOT).as_posix(),
            "asns": int(parent["topology"]["asns"]),
            "fixed_rov_count": len(rov_asns),
            "fixed_rov_asns": list(rov_asns),
            "fixed_rov_set_sha256": asn_set_sha256(rov_asns),
        },
        "design": {
            "research_question": (
                "How does upgrading the fixed measured ROV set from conventional "
                "ROV to open DA-ROV change route exposure for a deterministic "
                "same-length sibling prefix?"
            ),
            "independent_unit": "holder_asn",
            "design_population_holders": 691,
            "sample_holders": 200,
            "attacker_class": "uniform",
            "deployment_endpoints_percent": [0, 100],
            "deployment_sets": {
                "0": {
                    "count": 0,
                    "asn_set_sha256": asn_set_sha256(()),
                },
                "100": {
                    "count": len(rov_asns),
                    "asn_set_sha256": asn_set_sha256(rov_asns),
                },
            },
            "physical_trials_per_holder": 3,
            "physical_trials": EXPECTED_TRIALS,
            "sibling_derivation": (
                "the other child of leaf_prefix.supernet(prefixlen_diff=1), "
                "at the same prefix length"
            ),
            "announcements": [
                "root_prefix@holder_asn",
                "leaf_prefix@delegate_asn",
                "sibling_prefix@uniform_attacker_asn",
            ],
            "matched_lanes": [B1_SIBLING, f"{A1_SIBLING}@0", f"{A1_SIBLING}@100"],
            "leaf_invariance_reference": (
                "exact per-holder population partitions from matched frozen "
                "Phase-7 B1_delegate_only and D1_open_delegate_only endpoints"
            ),
        },
        "statistics": {
            "estimand": (
                "design-weighted holder-paired change in sibling-prefix attacker "
                "route/destination delivery"
            ),
            "bootstrap_replicates": BOOTSTRAP_REPLICATES,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_method": (
                "within-stratum paired SRSWOR-rescaled percentile bootstrap with FPC"
            ),
            "interval_type": "pointwise_95_percent",
        },
        "claim_boundary": {
            "supported": "conditional AS-level route exposure on frozen inputs",
            "not_supported": [
                "traffic-weighted impact",
                "sibling address utilization",
                "delegation legitimacy",
                "attack prevalence",
                "generalization beyond the frozen topology and measured ROV set",
            ],
        },
        "selected_units": [asdict(unit) for unit in units],
        "selected_units_canonical_sha256": canonical_records_sha256(
            (asdict(unit) for unit in units), key="unit_id"
        ),
        "trial_plan": [asdict(trial) for trial in trials],
        "expected_scenario_ids": {
            "count": len(trials),
            "sorted_newline_sha256": sorted_ids_sha256(
                trial.scenario_id for trial in trials
            ),
        },
        "benchmark": {
            "trials": BENCHMARK_TRIALS,
            "workers": 16,
            "scenario_ids": list(benchmark_ids),
            "covers_strata": ["S1", "S2", "S3", "S4"],
            "covers_lanes": [B1_SIBLING, A1_SIBLING],
            "covers_percentages": [0, 100],
        },
        "execution_contract": {
            "default_workers": 16,
            "required_workers": 16,
            "multiprocessing_start_method": "spawn",
            "graph_build_location": "worker initializer",
            "graph_reused_within_worker": True,
            "parent_single_jsonl_writer": True,
            "single_trial_limit_seconds": SINGLE_TRIAL_LIMIT_SECONDS,
            "per_worker_peak_rss_limit_bytes": PER_WORKER_RSS_LIMIT_BYTES,
            "aggregate_rss_limit_bytes": AGGREGATE_RSS_LIMIT_BYTES,
            "minimum_mem_available_bytes": MIN_MEM_AVAILABLE_BYTES,
            "silent_retries": 0,
            "incremental_zero_equivalence": True,
            "complete_partition_required": True,
        },
    }
    document["manifest_sha256"] = manifest_sha256(document)
    validate_manifest(document, verify_environment=False, verify_artifacts=True)
    return document


def write_plan(output_dir: Path) -> dict[str, Any]:
    output_dir = require_phase8_path(output_dir, label="output directory")
    manifest_path = output_dir / "manifest.json"
    raw_path = output_dir / "raw_scenarios.jsonl"
    if manifest_path.exists() or (raw_path.exists() and raw_path.stat().st_size):
        raise Phase8ContractError("refusing to plan over an existing campaign")
    document = build_manifest()
    atomic_write_json(manifest_path, document)
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "created_at_utc": utc_now(),
        "manifest_path": manifest_path.relative_to(REPOSITORY_ROOT).as_posix(),
        "manifest_file_sha256": file_sha256(manifest_path),
        "manifest_canonical_sha256": document["manifest_sha256"],
        "parent_phase7": document["parent_phase7"],
        "artifact_hashes": document["artifact_hashes"],
        "sibling_derivation": document["design"]["sibling_derivation"],
        "claim_boundary": document["claim_boundary"],
        "planned_commands": {
            "benchmark": (
                "PYTHONPATH=phase7_simulation/vendor/bgpy:. "
                "phase7_simulation/.venv-bgpy/bin/python "
                "-m phase8_sibling_sensitivity.runner run "
                "--output-dir phase8_sibling_sensitivity/results --workers 16 "
                "--max-new-trials 32 --benchmark-report "
                "phase8_sibling_sensitivity/results/benchmark_32.json"
            ),
            "full": (
                "PYTHONPATH=phase7_simulation/vendor/bgpy:. "
                "phase7_simulation/.venv-bgpy/bin/python "
                "-m phase8_sibling_sensitivity.runner run "
                "--output-dir phase8_sibling_sensitivity/results --workers 16"
            ),
            "analysis": (
                "PYTHONPATH=phase7_simulation/vendor/bgpy:. "
                "phase7_simulation/.venv-bgpy/bin/python "
                "-m phase8_sibling_sensitivity.analyze "
                "--manifest phase8_sibling_sensitivity/results/manifest.json "
                "--results phase8_sibling_sensitivity/results/raw_scenarios.jsonl "
                "--output-dir phase8_sibling_sensitivity/results/analysis"
            ),
            "analysis_recheck": (
                "PYTHONPATH=phase7_simulation/vendor/bgpy:. "
                "phase7_simulation/.venv-bgpy/bin/python "
                "-m phase8_sibling_sensitivity.analyze "
                "--manifest phase8_sibling_sensitivity/results/manifest.json "
                "--results phase8_sibling_sensitivity/results/raw_scenarios.jsonl "
                "--output-dir "
                "phase8_sibling_sensitivity/results/analysis_recheck "
                "--verify-reference "
                "phase8_sibling_sensitivity/results/analysis"
            ),
        },
    }
    atomic_write_json(output_dir / "provenance.json", provenance)
    return document


def validate_manifest(
    document: Mapping[str, Any],
    *,
    verify_environment: bool,
    verify_artifacts: bool,
) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        raise Phase8ContractError("unsupported manifest schema")
    if document.get("version_label") != VERSION_LABEL:
        raise Phase8ContractError("unexpected manifest version")
    if document.get("manifest_sha256") != manifest_sha256(document):
        raise Phase8ContractError("manifest self-hash mismatch")
    if verify_artifacts and document.get("artifact_hashes") != artifact_hashes():
        raise Phase8ContractError("current code/input hashes differ from manifest")
    if (
        verify_environment
        and document.get("runtime_environment") != runtime_environment_fingerprint()
    ):
        raise Phase8ContractError("runtime environment differs from manifest")
    raw_units = tuple(document.get("selected_units", ()))
    units = tuple(SiblingUnit(**item) for item in raw_units)
    trials = tuple(SiblingTrial(**item) for item in document.get("trial_plan", ()))
    if len(units) != EXPECTED_HOLDERS or len(trials) != EXPECTED_TRIALS:
        raise Phase8ContractError("manifest unit/trial count mismatch")
    unit_by_id = {unit.unit_id: unit for unit in units}
    if len(unit_by_id) != len(units):
        raise Phase8ContractError("manifest unit IDs repeat")
    if document.get("selected_units_canonical_sha256") != canonical_records_sha256(
        raw_units, key="unit_id"
    ):
        raise Phase8ContractError("manifest selected-unit digest mismatch")
    expected_units = units_from_phase7(load_phase7_manifest())
    if [asdict(unit) for unit in units] != [asdict(unit) for unit in expected_units]:
        raise Phase8ContractError("manifest units differ from frozen Phase-7 selection")
    actual_ids = [trial.scenario_id for trial in trials]
    expected_ids = document.get("expected_scenario_ids", {})
    if (
        len(set(actual_ids)) != len(actual_ids)
        or expected_ids.get("count") != len(actual_ids)
        or expected_ids.get("sorted_newline_sha256") != sorted_ids_sha256(actual_ids)
    ):
        raise Phase8ContractError("manifest scenario-ID contract mismatch")
    counts: dict[str, set[tuple[str, int]]] = {}
    for trial in trials:
        if trial.unit_id not in unit_by_id:
            raise Phase8ContractError(f"unknown trial unit {trial.unit_id}")
        if trial.pair_index != unit_by_id[trial.unit_id].pair_index:
            raise Phase8ContractError(f"pair mismatch for {trial.scenario_id}")
        counts.setdefault(trial.unit_id, set()).add(
            (trial.lane, trial.deployment_percent_target)
        )
    if any(cells != set(LANE_PERCENTAGES) for cells in counts.values()):
        raise Phase8ContractError("one or more holders lack the exact three cells")
    benchmark = document.get("benchmark", {})
    benchmark_ids = tuple(benchmark.get("scenario_ids", ()))
    if (
        int(benchmark.get("workers", -1)) != 16
        or len(benchmark_ids) != BENCHMARK_TRIALS
        or tuple(actual_ids[:32]) != benchmark_ids
    ):
        raise Phase8ContractError("benchmark is not the first 32 frozen trials")
    if document.get("execution_contract", {}).get("required_workers") != 16:
        raise Phase8ContractError("manifest required-worker gate mismatch")
    for unit in units:
        if unit.sibling_prefix != immediate_sibling(unit.root_prefix, unit.leaf_prefix):
            raise Phase8ContractError(f"sibling derivation drift for {unit.unit_id}")
    topology = document.get("topology", {})
    rov = tuple(topology.get("fixed_rov_asns", ()))
    if len(rov) != EXPECTED_ROV_ASNS or len(set(rov)) != EXPECTED_ROV_ASNS:
        raise Phase8ContractError("manifest fixed ROV set mismatch")
    parent_rov = tuple(load_phase7_manifest()["topology"]["fixed_rov_asns"])
    if rov != parent_rov or topology.get("fixed_rov_set_sha256") != asn_set_sha256(rov):
        raise Phase8ContractError("manifest ROV identity differs from frozen Phase 7")
    deployment_sets = document.get("design", {}).get("deployment_sets")
    expected_deployment_sets = {
        "0": {"count": 0, "asn_set_sha256": asn_set_sha256(())},
        "100": {
            "count": EXPECTED_ROV_ASNS,
            "asn_set_sha256": asn_set_sha256(rov),
        },
    }
    if deployment_sets != expected_deployment_sets:
        raise Phase8ContractError("manifest endpoint deployment sets mismatch")


def load_manifest(
    path: Path, *, verify_environment: bool = True, verify_artifacts: bool = True
) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    validate_manifest(
        document,
        verify_environment=verify_environment,
        verify_artifacts=verify_artifacts,
    )
    return document


def build_sibling_scenario(
    unit: SiblingUnit,
    lane: str,
    da_asns: frozenset[int],
    rov_asns: frozenset[int],
    engine: SimulationEngine,
) -> FixedDeploymentScenario:
    if lane not in {B1_SIBLING, A1_SIBLING}:
        raise Phase8ContractError(f"unknown lane {lane}")
    if lane == B1_SIBLING and da_asns:
        raise Phase8ContractError("conventional lane contains DA-aware ASes")
    if not da_asns.issubset(rov_asns):
        raise Phase8ContractError("DA set is not a subset of the fixed ROV set")
    root = ip_network(unit.root_prefix, strict=True)
    announcements = (
        origin_announcement(unit.root_prefix, unit.holder_asn),
        origin_announcement(unit.leaf_prefix, unit.delegate_asn),
        origin_announcement(unit.sibling_prefix, unit.uniform_attacker_asn),
    )
    policy_map: dict[int, type[BGP]] = {asn: ROV for asn in rov_asns}
    policy_map.update({asn: DAROV for asn in da_asns})
    config = ScenarioConfig(
        ScenarioCls=FixedDeploymentScenario,
        BasePolicyCls=BGP,
        AdoptPolicyCls=BGP,
        override_attacker_asns=frozenset({unit.uniform_attacker_asn}),
        override_victim_asns=frozenset({unit.holder_asn}),
        override_adopting_asns=frozenset(),
        override_announcements=announcements,
        override_roas=(ROA(root, unit.holder_asn, max_length=root.prefixlen),),
        hardcoded_asn_cls_dict=frozendict(policy_map),
    )
    return FixedDeploymentScenario(scenario_config=config, engine=engine)


def empty_counts(outcomes: Sequence[str]) -> dict[str, int]:
    return {outcome: 0 for outcome in outcomes}


def trace_destination(
    engine: SimulationEngine,
    start_asn: int,
    prefixes: Sequence[str],
    allowed_origins: Mapping[int, str],
) -> str:
    current = start_asn
    visited: set[int] = set()
    for _ in range(len(engine.as_graph) + 1):
        if current in visited:
            return "loop"
        visited.add(current)
        policy = engine.as_graph.as_dict[current].policy
        announcement = next(
            (
                candidate
                for prefix in prefixes
                if (candidate := policy.local_rib.get(prefix)) is not None
            ),
            None,
        )
        if announcement is None:
            return "disconnected"
        if current == announcement.origin:
            outcome = allowed_origins.get(current)
            if outcome is None:
                raise RuntimeError(
                    f"unexpected destination origin AS{current} for {prefixes}"
                )
            return outcome
        next_hop = announcement.next_hop_asn
        if next_hop not in engine.as_graph.as_dict:
            return "disconnected"
        current = next_hop
    return "loop"


def analyze_outcomes(
    engine: SimulationEngine,
    unit: SiblingUnit,
    rov_asns: frozenset[int],
) -> tuple[dict[str, Any], dict[str, bool]]:
    groups = {
        population: {
            partition: empty_counts(outcomes)
            for partition, outcomes in PARTITION_OUTCOMES.items()
        }
        for population in POPULATIONS
    }
    denominators = {"all": len(engine.as_graph), "rov": 0, "non_rov": 0}
    for as_obj in engine.as_graph:
        subgroup = "rov" if as_obj.asn in rov_asns else "non_rov"
        denominators[subgroup] += 1
        sibling_ann = as_obj.policy.local_rib.get(unit.sibling_prefix)
        if sibling_ann is None:
            sibling_route = "absent"
        elif sibling_ann.origin == unit.uniform_attacker_asn:
            sibling_route = "attacker"
        else:
            raise RuntimeError(
                f"unexpected sibling origin AS{sibling_ann.origin} at AS{as_obj.asn}"
            )
        leaf_ann = as_obj.policy.local_rib.get(unit.leaf_prefix)
        if leaf_ann is None:
            leaf_route = "absent"
        elif leaf_ann.origin == unit.delegate_asn:
            leaf_route = "delegate"
        else:
            raise RuntimeError(
                f"unexpected leaf origin AS{leaf_ann.origin} at AS{as_obj.asn}"
            )
        sibling_destination = trace_destination(
            engine,
            as_obj.asn,
            (unit.sibling_prefix, unit.root_prefix),
            {
                unit.uniform_attacker_asn: "attacker",
                unit.holder_asn: "holder_fallback",
            },
        )
        leaf_destination = trace_destination(
            engine,
            as_obj.asn,
            (unit.leaf_prefix, unit.root_prefix),
            {
                unit.delegate_asn: "delegate",
                unit.holder_asn: "holder_fallback",
            },
        )
        values = {
            "sibling_route": sibling_route,
            "leaf_route": leaf_route,
            "sibling_destination": sibling_destination,
            "leaf_destination": leaf_destination,
        }
        for population in ("all", subgroup):
            for partition, outcome in values.items():
                groups[population][partition][outcome] += 1
    if denominators["rov"] != len(rov_asns):
        raise RuntimeError("ROV population denominator differs from fixed set")
    output: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    for population, partitions in groups.items():
        denominator = denominators[population]
        output[population] = {"denominator_asns": denominator}
        for partition, counts in partitions.items():
            complete = sum(counts.values()) == denominator
            checks[f"{population}_{partition}_complete"] = complete
            if not complete:
                raise RuntimeError(f"incomplete {population}/{partition} partition")
            output[population][partition] = {
                "counts": counts,
                "fractions": {
                    key: value / denominator for key, value in counts.items()
                },
            }
    for partition, outcomes in PARTITION_OUTCOMES.items():
        for outcome in outcomes:
            additive = output["all"][partition]["counts"][outcome] == (
                output["rov"][partition]["counts"][outcome]
                + output["non_rov"][partition]["counts"][outcome]
            )
            checks[f"{partition}_{outcome}_all_equals_subgroups"] = additive
            if not additive:
                raise RuntimeError(f"nonadditive {partition}/{outcome}")
    checks["all_equals_rov_plus_non_rov"] = True
    return output, checks


def run_trial(
    engine: SimulationEngine,
    unit: SiblingUnit,
    trial: SiblingTrial,
    rov_asns: frozenset[int],
    manifest_digest: str,
    worker_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    da_asns = rov_asns if trial.deployment_percent_target == 100 else frozenset()
    pair = unit_pair(unit)
    policy = make_open_policy(pair)
    DAROV.configure(policy)
    started = perf_counter()
    rss_before = current_rss_bytes()
    with PeakRSSMonitor() as memory, trial_alarm(SINGLE_TRIAL_LIMIT_SECONDS):
        scenario = build_sibling_scenario(unit, trial.lane, da_asns, rov_asns, engine)
        engine.setup(scenario)
        assignments = verify_policy_assignment(engine, rov_asns, da_asns)
        engine.run(propagation_round=0, scenario=scenario)
        outcomes, checks = analyze_outcomes(engine, unit, rov_asns)
    elapsed = perf_counter() - started
    if elapsed > SINGLE_TRIAL_LIMIT_SECONDS:
        raise Phase8ResourceStop(
            f"{trial.scenario_id} exceeded {SINGLE_TRIAL_LIMIT_SECONDS}s"
        )
    if memory.peak_bytes > PER_WORKER_RSS_LIMIT_BYTES:
        raise Phase8ResourceStop(f"{trial.scenario_id} exceeded per-worker RSS gate")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "success",
        "scenario_id": trial.scenario_id,
        "manifest_sha256": manifest_digest,
        "unit_id": unit.unit_id,
        "pair_index": unit.pair_index,
        "source_row": unit.source_row,
        "holder_asn": unit.holder_asn,
        "delegate_asn": unit.delegate_asn,
        "attacker_asn": unit.uniform_attacker_asn,
        "attacker_class": "uniform",
        "holder_degree": unit.holder_degree,
        "delegate_degree": unit.delegate_degree,
        "attacker_degree": unit.uniform_attacker_degree,
        "holder_stratum": unit.holder_stratum,
        "holder_stratum_degree_range": unit.holder_stratum_degree_range,
        "N_h": unit.N_h,
        "n_h": unit.n_h,
        "design_weight": unit.design_weight,
        "lane": trial.lane,
        "deployment_percent_target": trial.deployment_percent_target,
        "deployment_count": len(da_asns),
        "deployment_fraction_actual": len(da_asns) / len(rov_asns),
        "deployment_set_sha256": asn_set_sha256(da_asns),
        "fixed_rov_count": len(rov_asns),
        "root_prefix": unit.root_prefix,
        "leaf_prefix": unit.leaf_prefix,
        "sibling_prefix": unit.sibling_prefix,
        "sibling_relation": "other_child_of_leaf_immediate_parent",
        "policy_max_length": policy.max_length,
        "leaf_da_state": policy.validate_route(
            unit.leaf_prefix, unit.delegate_asn
        ).value,
        "sibling_da_state": policy.validate_route(
            unit.sibling_prefix, unit.uniform_attacker_asn
        ).value,
        "policy_assignment_counts": assignments,
        "outcomes": outcomes,
        "partition_checks": checks,
        "elapsed_seconds": elapsed,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": current_rss_bytes(),
        "peak_rss_bytes": memory.peak_bytes,
        **worker_metadata,
    }


def validate_result_row(
    row: Mapping[str, Any],
    trial: SiblingTrial,
    unit: SiblingUnit,
    manifest: Mapping[str, Any],
) -> None:
    if row.get("schema_version") != SCHEMA_VERSION or row.get("status") != "success":
        raise Phase8ContractError(f"{trial.scenario_id}: invalid row status/schema")
    exact = {
        "scenario_id": trial.scenario_id,
        "manifest_sha256": manifest["manifest_sha256"],
        "unit_id": unit.unit_id,
        "pair_index": unit.pair_index,
        "source_row": unit.source_row,
        "lane": trial.lane,
        "deployment_percent_target": trial.deployment_percent_target,
        "holder_asn": unit.holder_asn,
        "delegate_asn": unit.delegate_asn,
        "attacker_asn": unit.uniform_attacker_asn,
        "attacker_class": "uniform",
        "holder_degree": unit.holder_degree,
        "delegate_degree": unit.delegate_degree,
        "attacker_degree": unit.uniform_attacker_degree,
        "holder_stratum": unit.holder_stratum,
        "holder_stratum_degree_range": unit.holder_stratum_degree_range,
        "N_h": unit.N_h,
        "n_h": unit.n_h,
        "design_weight": unit.design_weight,
        "root_prefix": unit.root_prefix,
        "leaf_prefix": unit.leaf_prefix,
        "sibling_prefix": unit.sibling_prefix,
        "sibling_relation": "other_child_of_leaf_immediate_parent",
        "policy_max_length": ip_network(unit.leaf_prefix).prefixlen,
        "fixed_rov_count": EXPECTED_ROV_ASNS,
        "deployment_set_sha256": manifest["design"]["deployment_sets"][
            str(trial.deployment_percent_target)
        ]["asn_set_sha256"],
    }
    for field, expected in exact.items():
        if row.get(field) != expected:
            raise Phase8ContractError(
                f"{trial.scenario_id}: {field}={row.get(field)!r}, expected {expected!r}"
            )
    expected_deployment = (
        EXPECTED_ROV_ASNS if trial.deployment_percent_target == 100 else 0
    )
    actual_deployment = row.get("deployment_count")
    if (
        isinstance(actual_deployment, bool)
        or not isinstance(actual_deployment, int)
        or actual_deployment != expected_deployment
    ):
        raise Phase8ContractError(f"{trial.scenario_id}: deployment count mismatch")
    expected_fraction = expected_deployment / EXPECTED_ROV_ASNS
    actual_fraction = row.get("deployment_fraction_actual")
    if not math.isclose(
        float(actual_fraction)
        if isinstance(actual_fraction, (int, float))
        and not isinstance(actual_fraction, bool)
        else math.nan,
        expected_fraction,
        rel_tol=0,
        abs_tol=1e-15,
    ):
        raise Phase8ContractError(f"{trial.scenario_id}: deployment fraction mismatch")
    expected_assignments = {
        "bgp": int(manifest["topology"]["asns"]) - EXPECTED_ROV_ASNS,
        "rov": EXPECTED_ROV_ASNS - expected_deployment,
        "darov": expected_deployment,
    }
    if row.get("policy_assignment_counts") != expected_assignments:
        raise Phase8ContractError(f"{trial.scenario_id}: policy assignments mismatch")
    if (
        row.get("leaf_da_state") != ValidationState.DELEGATED.value
        or row.get("sibling_da_state") != ValidationState.DELEGATED.value
    ):
        raise Phase8ContractError(f"{trial.scenario_id}: DA boundary state mismatch")
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping):
        raise Phase8ContractError(f"{trial.scenario_id}: no outcome object")
    denominators = {
        "all": int(manifest["topology"]["asns"]),
        "rov": EXPECTED_ROV_ASNS,
        "non_rov": int(manifest["topology"]["asns"]) - EXPECTED_ROV_ASNS,
    }
    for population, denominator in denominators.items():
        section = outcomes.get(population)
        actual_denominator = (
            section.get("denominator_asns") if isinstance(section, Mapping) else None
        )
        if (
            not isinstance(section, Mapping)
            or isinstance(actual_denominator, bool)
            or not isinstance(actual_denominator, int)
            or actual_denominator != denominator
        ):
            raise Phase8ContractError(
                f"{trial.scenario_id}: {population} denominator mismatch"
            )
        for partition, expected_outcomes in PARTITION_OUTCOMES.items():
            item = section.get(partition)
            if not isinstance(item, Mapping):
                raise Phase8ContractError(
                    f"{trial.scenario_id}: missing {population}/{partition}"
                )
            counts = item.get("counts")
            fractions = item.get("fractions")
            if set(counts or {}) != set(expected_outcomes) or set(
                fractions or {}
            ) != set(expected_outcomes):
                raise Phase8ContractError(f"{trial.scenario_id}: outcome keys mismatch")
            if any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counts.values()
            ):
                raise Phase8ContractError(
                    f"{trial.scenario_id}: invalid count in {population}/{partition}"
                )
            if sum(counts.values()) != denominator:
                raise Phase8ContractError(
                    f"{trial.scenario_id}: incomplete {population}/{partition}"
                )
            for outcome in expected_outcomes:
                actual_fraction = fractions[outcome]
                expected_fraction = counts[outcome] / denominator
                if not math.isclose(
                    float(actual_fraction)
                    if isinstance(actual_fraction, (int, float))
                    and not isinstance(actual_fraction, bool)
                    else math.nan,
                    expected_fraction,
                    rel_tol=0,
                    abs_tol=1e-15,
                ):
                    raise Phase8ContractError(f"{trial.scenario_id}: fraction mismatch")
    checks = row.get("partition_checks")
    expected_check_keys = {
        f"{population}_{partition}_complete"
        for population in POPULATIONS
        for partition in PARTITION_OUTCOMES
    }
    expected_check_keys.update(
        f"{partition}_{outcome}_all_equals_subgroups"
        for partition, expected_outcomes in PARTITION_OUTCOMES.items()
        for outcome in expected_outcomes
    )
    expected_check_keys.add("all_equals_rov_plus_non_rov")
    if (
        not isinstance(checks, Mapping)
        or set(checks) != expected_check_keys
        or not all(checks.values())
    ):
        raise Phase8ContractError(f"{trial.scenario_id}: partition checks failed")
    for partition, expected_outcomes in PARTITION_OUTCOMES.items():
        for outcome in expected_outcomes:
            if outcomes["all"][partition]["counts"][outcome] != (
                outcomes["rov"][partition]["counts"][outcome]
                + outcomes["non_rov"][partition]["counts"][outcome]
            ):
                raise Phase8ContractError(
                    f"{trial.scenario_id}: nonadditive {partition}/{outcome}"
                )
    if (
        row.get("attempt") != 1
        or row.get("prior_failure_count") != 0
        or row.get("retry_authorized") is not False
    ):
        raise Phase8ContractError(f"{trial.scenario_id}: retry provenance invalid")
    resource_fields = {
        "elapsed_seconds": SINGLE_TRIAL_LIMIT_SECONDS,
        "peak_rss_bytes": PER_WORKER_RSS_LIMIT_BYTES,
        "worker_graph_build_peak_rss_bytes": PER_WORKER_RSS_LIMIT_BYTES,
    }
    for field, limit in resource_fields.items():
        value = row.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= float(value) <= limit
        ):
            raise Phase8ContractError(
                f"{trial.scenario_id}: {field} violates its resource gate"
            )


def outcome_fingerprint(row: Mapping[str, Any]) -> str:
    payload = {
        "policy_assignment_counts": row["policy_assignment_counts"],
        "outcomes": row["outcomes"],
        "partition_checks": row["partition_checks"],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def record_zero_equivalence(
    row: Mapping[str, Any], state: dict[int, dict[str, str]]
) -> None:
    lane = str(row["lane"])
    percent = int(row["deployment_percent_target"])
    if lane == B1_SIBLING:
        role = "reference"
    elif lane == A1_SIBLING and percent == 0:
        role = "open_zero"
    else:
        return
    holder = int(row["holder_asn"])
    cell = state.setdefault(holder, {})
    if role in cell:
        raise Phase8ContractError(f"duplicate zero-equivalence {holder}/{role}")
    counterpart = "open_zero" if role == "reference" else "reference"
    fingerprint = outcome_fingerprint(row)
    if counterpart in cell and cell[counterpart] != fingerprint:
        raise Phase8ContractError(f"zero-equivalence failed for holder AS{holder}")
    cell[role] = fingerprint


def scan_results(
    path: Path, manifest: Mapping[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, str]]]:
    trials = {
        item["scenario_id"]: SiblingTrial(**item) for item in manifest["trial_plan"]
    }
    units = {
        item["unit_id"]: SiblingUnit(**item) for item in manifest["selected_units"]
    }
    rows: dict[str, dict[str, Any]] = {}
    zero_state: dict[int, dict[str, str]] = {}
    if not path.exists():
        return rows, zero_state
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise Phase8ContractError(
                    f"{path}:{line_number}: invalid JSON; no implicit repair"
                ) from exc
            scenario = row.get("scenario_id")
            if scenario not in trials or scenario in rows:
                raise Phase8ContractError(
                    f"{path}:{line_number}: unknown/duplicate scenario {scenario!r}"
                )
            trial = trials[scenario]
            validate_result_row(row, trial, units[trial.unit_id], manifest)
            record_zero_equivalence(row, zero_state)
            rows[scenario] = row
    return rows, zero_state


def mem_available_bytes() -> int:
    with Path("/proc/meminfo").open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("/proc/meminfo does not report MemAvailable")


def process_rss_bytes(pid: int) -> int:
    try:
        with Path(f"/proc/{pid}/status").open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except FileNotFoundError:
        return 0
    return 0


class ParentResourceMonitor:
    def __init__(self, pid_provider, interval_seconds: float = 0.5) -> None:
        self.pid_provider = pid_provider
        self.interval_seconds = interval_seconds
        self.peak_aggregate_rss_bytes = 0
        self.minimum_mem_available_bytes = mem_available_bytes()
        self.breach_reason: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _sample(self) -> None:
        try:
            while not self._stop.wait(self.interval_seconds):
                pids = {os.getpid(), *self.pid_provider()}
                aggregate = sum(process_rss_bytes(pid) for pid in pids)
                available = mem_available_bytes()
                self.peak_aggregate_rss_bytes = max(
                    self.peak_aggregate_rss_bytes, aggregate
                )
                self.minimum_mem_available_bytes = min(
                    self.minimum_mem_available_bytes, available
                )
                if aggregate > AGGREGATE_RSS_LIMIT_BYTES:
                    self.breach_reason = (
                        f"aggregate RSS {aggregate} exceeds {AGGREGATE_RSS_LIMIT_BYTES}"
                    )
                elif available < MIN_MEM_AVAILABLE_BYTES:
                    self.breach_reason = (
                        f"MemAvailable {available} below {MIN_MEM_AVAILABLE_BYTES}"
                    )
                if self.breach_reason:
                    os.kill(os.getpid(), signal.SIGUSR1)
                    return
        except Exception as exc:
            self.breach_reason = (
                f"resource monitor failed closed: {type(exc).__name__}: {exc}"
            )
            os.kill(os.getpid(), signal.SIGUSR1)


_WORKER_CONTEXT: WorkerContext | None = None
_WORKER_INIT_FAILURE: dict[str, Any] | None = None


def worker_initializer(manifest_path: str) -> None:
    global _WORKER_CONTEXT, _WORKER_INIT_FAILURE
    _WORKER_CONTEXT = None
    _WORKER_INIT_FAILURE = None
    try:
        manifest = load_manifest(
            Path(manifest_path), verify_environment=False, verify_artifacts=False
        )
        units = {
            item["unit_id"]: SiblingUnit(**item) for item in manifest["selected_units"]
        }
        started = perf_counter()
        with PeakRSSMonitor() as memory:
            graph = build_fixed_graph()
        _WORKER_CONTEXT = WorkerContext(
            engine=SimulationEngine(graph),
            units=units,
            rov_asns=frozenset(manifest["topology"]["fixed_rov_asns"]),
            manifest_sha256=manifest["manifest_sha256"],
            graph_build_seconds=perf_counter() - started,
            graph_build_peak_rss_bytes=memory.peak_bytes,
        )
    except Exception as exc:
        _WORKER_INIT_FAILURE = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }


def worker_execute(raw_trial: Mapping[str, Any]) -> dict[str, Any]:
    context = _WORKER_CONTEXT
    trial: SiblingTrial | None = None
    attempt = raw_trial.get("_attempt")
    try:
        trial = SiblingTrial(
            **{key: value for key, value in raw_trial.items() if key != "_attempt"}
        )
        if isinstance(attempt, bool) or not isinstance(attempt, int):
            raise Phase8ContractError("worker attempt is not an integer")
        if _WORKER_INIT_FAILURE is not None:
            raise RuntimeError(
                "worker initializer failed: "
                f"{_WORKER_INIT_FAILURE['type']}: {_WORKER_INIT_FAILURE['message']}"
            )
        if context is None:
            raise RuntimeError("worker context is uninitialized")
        context.sequence += 1
        if attempt != 1:
            raise Phase8ContractError("Phase 8 forbids automatic retries")
        if context.graph_build_peak_rss_bytes > PER_WORKER_RSS_LIMIT_BYTES:
            raise Phase8ResourceStop("worker graph build exceeded RSS gate")
        return run_trial(
            context.engine,
            context.units[trial.unit_id],
            trial,
            context.rov_asns,
            context.manifest_sha256,
            {
                "worker_pid": os.getpid(),
                "worker_trial_sequence": context.sequence,
                "worker_graph_build_seconds": context.graph_build_seconds,
                "worker_graph_build_peak_rss_bytes": context.graph_build_peak_rss_bytes,
                "attempt": attempt,
                "prior_failure_count": 0,
                "retry_authorized": False,
            },
        )
    except Exception as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "scenario_id": (
                trial.scenario_id if trial is not None else raw_trial.get("scenario_id")
            ),
            "manifest_sha256": (
                context.manifest_sha256 if context is not None else None
            ),
            "worker_pid": os.getpid(),
            "attempt": attempt,
            "initializer_exception": _WORKER_INIT_FAILURE,
            "failed_at_utc": utc_now(),
            "exception": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }


def checkpoint_document(
    manifest: Mapping[str, Any],
    completed: int,
    *,
    started_at_utc: str,
    last_scenario_id: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "manifest_sha256": manifest["manifest_sha256"],
        "started_at_utc": started_at_utc,
        "updated_at_utc": utc_now(),
        "completed_trials": completed,
        "planned_trials": EXPECTED_TRIALS,
        "remaining_trials": EXPECTED_TRIALS - completed,
        "last_scenario_id": last_scenario_id,
        "status": "complete" if completed == EXPECTED_TRIALS else "in_progress",
    }


def write_benchmark_report(
    path: Path,
    manifest: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    wall_seconds: float,
    workers: int,
    monitor: ParentResourceMonitor,
) -> dict[str, Any]:
    expected = set(manifest["benchmark"]["scenario_ids"])
    actual = {str(row["scenario_id"]) for row in rows}
    if actual != expected or len(rows) != BENCHMARK_TRIALS:
        raise Phase8ContractError("benchmark rows differ from frozen 32-trial set")
    gate_checks = {
        "resource_monitor_healthy": monitor.breach_reason is None,
        "all_32_first_attempt_trials_succeeded": all(
            int(row["attempt"]) == 1 and int(row["prior_failure_count"]) == 0
            for row in rows
        ),
        "single_trial_time_at_most_60_seconds": max(
            float(row["elapsed_seconds"]) for row in rows
        )
        <= SINGLE_TRIAL_LIMIT_SECONDS,
        "trial_peak_rss_at_most_1_5_gib": max(
            int(row["peak_rss_bytes"]) for row in rows
        )
        <= PER_WORKER_RSS_LIMIT_BYTES,
        "worker_graph_peak_rss_at_most_1_5_gib": max(
            int(row["worker_graph_build_peak_rss_bytes"]) for row in rows
        )
        <= PER_WORKER_RSS_LIMIT_BYTES,
        "aggregate_rss_at_most_24_gib": (
            monitor.peak_aggregate_rss_bytes <= AGGREGATE_RSS_LIMIT_BYTES
        ),
        "mem_available_at_least_16_gib": (
            monitor.minimum_mem_available_bytes >= MIN_MEM_AVAILABLE_BYTES
        ),
    }
    approved = all(gate_checks.values())
    report = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "created_at_utc": utc_now(),
        "status": "passed" if approved else "failed",
        "manifest_sha256": manifest["manifest_sha256"],
        "trials": len(rows),
        "workers": workers,
        "run_wall_seconds": wall_seconds,
        "mean_trial_seconds": sum(float(row["elapsed_seconds"]) for row in rows)
        / len(rows),
        "max_trial_seconds": max(float(row["elapsed_seconds"]) for row in rows),
        "max_trial_peak_rss_bytes": max(int(row["peak_rss_bytes"]) for row in rows),
        "max_worker_graph_build_peak_rss_bytes": max(
            int(row["worker_graph_build_peak_rss_bytes"]) for row in rows
        ),
        "peak_aggregate_rss_bytes": monitor.peak_aggregate_rss_bytes,
        "minimum_mem_available_bytes": monitor.minimum_mem_available_bytes,
        "gates": manifest["execution_contract"],
        "gate_checks": gate_checks,
        "scenario_ids_sha256": sorted_ids_sha256(actual),
        "approved_for_full_run": approved,
    }
    report["benchmark_report_sha256"] = canonical_sha256(
        report, "benchmark_report_sha256"
    )
    atomic_write_json(path, report)
    if not approved:
        raise Phase8ResourceStop("32-trial benchmark failed one or more gates")
    return report


def validate_benchmark_approval(
    path: Path, manifest: Mapping[str, Any]
) -> Mapping[str, Any]:
    if not path.exists():
        raise Phase8ContractError(
            "full run requires the frozen 32-trial benchmark approval"
        )
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("benchmark_report_sha256") != canonical_sha256(
        report, "benchmark_report_sha256"
    ):
        raise Phase8ContractError("benchmark report self-hash mismatch")
    expected = {
        "manifest_sha256": manifest["manifest_sha256"],
        "trials": BENCHMARK_TRIALS,
        "workers": int(manifest["benchmark"]["workers"]),
        "scenario_ids_sha256": sorted_ids_sha256(manifest["benchmark"]["scenario_ids"]),
        "status": "passed",
        "approved_for_full_run": True,
    }
    for field, value in expected.items():
        if report.get(field) != value:
            raise Phase8ContractError(
                f"benchmark report {field} differs from frozen approval"
            )
    checks = report.get("gate_checks")
    if not isinstance(checks, Mapping) or not checks or not all(checks.values()):
        raise Phase8ContractError("benchmark report contains a failed gate")
    return report


def _run_campaign_impl(
    output_dir: Path,
    *,
    workers: int,
    max_new_trials: int | None,
    benchmark_report: Path | None,
) -> dict[str, Any]:
    output_dir = require_phase8_path(output_dir, label="output directory")
    manifest_path = output_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    expected_workers = int(manifest["benchmark"]["workers"])
    if workers != expected_workers:
        raise Phase8ContractError(
            f"campaign requires exactly {expected_workers} workers"
        )
    if (
        benchmark_report is not None
        and benchmark_report.resolve() != (output_dir / "benchmark_32.json").resolve()
    ):
        raise Phase8ContractError(
            "benchmark report must be output-dir/benchmark_32.json"
        )
    failures_path = output_dir / "failures.jsonl"
    if failures_path.exists() and failures_path.stat().st_size:
        raise Phase8ContractError(
            "failure history exists; Phase 8 forbids silent or automatic retry"
        )
    results_path = output_dir / "raw_scenarios.jsonl"
    completed_rows, zero_state = scan_results(results_path, manifest)
    completed_before = len(completed_rows)
    trials = [SiblingTrial(**item) for item in manifest["trial_plan"]]
    pending = [trial for trial in trials if trial.scenario_id not in completed_rows]
    if max_new_trials is not None:
        if max_new_trials < 0:
            raise Phase8ContractError("max-new-trials cannot be negative")
        pending = pending[:max_new_trials]
    if benchmark_report is not None and (
        completed_before != 0
        or max_new_trials != BENCHMARK_TRIALS
        or [trial.scenario_id for trial in pending]
        != list(manifest["benchmark"]["scenario_ids"])
    ):
        raise Phase8ContractError(
            "benchmark report requires the frozen first 32 trials on an empty checkpoint"
        )
    if not pending:
        return checkpoint_document(
            manifest,
            completed_before,
            started_at_utc=utc_now(),
            last_scenario_id=None,
        )
    if benchmark_report is None:
        if completed_before == 0:
            raise Phase8ContractError(
                "run the frozen 32-trial benchmark before the full campaign"
            )
        validate_benchmark_approval(output_dir / "benchmark_32.json", manifest)
        benchmark_ids = set(manifest["benchmark"]["scenario_ids"])
        if not benchmark_ids.issubset(completed_rows):
            raise Phase8ContractError(
                "raw results do not contain all approved benchmark scenarios"
            )
    invocation_id = hashlib.sha256(
        f"{manifest['manifest_sha256']}|{utc_now()}|{os.getpid()}".encode()
    ).hexdigest()[:24]
    invocation_path = output_dir / "active_invocation.json"
    invocation = {
        "schema_version": SCHEMA_VERSION,
        "version_label": VERSION_LABEL,
        "invocation_id": invocation_id,
        "manifest_sha256": manifest["manifest_sha256"],
        "started_at_utc": utc_now(),
        "status": "running",
        "mode": "benchmark" if benchmark_report is not None else "full",
        "workers": workers,
        "completed_before_invocation": completed_before,
        "pending_selected_for_invocation": len(pending),
    }
    atomic_write_json(invocation_path, invocation)
    if mem_available_bytes() < MIN_MEM_AVAILABLE_BYTES:
        raise Phase8ResourceStop("host memory headroom is below the 16-GiB gate")
    trial_by_id = {trial.scenario_id: trial for trial in trials}
    unit_by_id = {
        item["unit_id"]: SiblingUnit(**item) for item in manifest["selected_units"]
    }
    started_at = utc_now()
    started = perf_counter()
    checkpoint_path = output_dir / "checkpoint.json"
    last_scenario_id: str | None = None
    new_rows: list[dict[str, Any]] = []
    context = multiprocessing.get_context("spawn")
    with context.Pool(
        processes=workers,
        initializer=worker_initializer,
        initargs=(str(manifest_path),),
    ) as pool:
        monitor = ParentResourceMonitor(
            lambda: [process.pid for process in pool._pool if process.pid]
        )

        def resource_signal_handler(_signum: int, _frame: object) -> None:
            reason = monitor.breach_reason or "parent resource gate stopped run"
            raise Phase8ResourceStop(reason)

        previous_handler = signal.getsignal(signal.SIGUSR1)
        signal.signal(signal.SIGUSR1, resource_signal_handler)
        monitor.start()
        try:
            raw_pending = [{**asdict(trial), "_attempt": 1} for trial in pending]
            for result_index, result in enumerate(
                pool.imap_unordered(worker_execute, raw_pending, chunksize=1), start=1
            ):
                if result.get("status") != "success":
                    append_jsonl(failures_path, result, fsync=True)
                    raise RuntimeError(
                        f"worker failed {result.get('scenario_id')}: "
                        f"{result.get('exception')}"
                    )
                sid = str(result["scenario_id"])
                trial = trial_by_id[sid]
                validate_result_row(result, trial, unit_by_id[trial.unit_id], manifest)
                record_zero_equivalence(result, zero_state)
                append_jsonl(
                    results_path,
                    result,
                    fsync=result_index % 8 == 0 or result_index == len(pending),
                )
                completed_rows[sid] = result
                new_rows.append(result)
                last_scenario_id = sid
                if result_index % 8 == 0 or result_index == len(pending):
                    checkpoint = checkpoint_document(
                        manifest,
                        len(completed_rows),
                        started_at_utc=started_at,
                        last_scenario_id=last_scenario_id,
                    )
                    checkpoint.update(
                        {
                            "run_wall_seconds_this_invocation": perf_counter()
                            - started,
                            "workers": workers,
                            "peak_aggregate_rss_bytes": monitor.peak_aggregate_rss_bytes,
                            "minimum_mem_available_bytes": monitor.minimum_mem_available_bytes,
                        }
                    )
                    atomic_write_json(checkpoint_path, checkpoint)
        finally:
            monitor.stop()
            signal.signal(signal.SIGUSR1, previous_handler)
    wall_seconds = perf_counter() - started
    final = checkpoint_document(
        manifest,
        len(completed_rows),
        started_at_utc=started_at,
        last_scenario_id=last_scenario_id,
    )
    final.update(
        {
            "run_wall_seconds_this_invocation": wall_seconds,
            "workers": workers,
            "new_trials_completed": len(new_rows),
            "completed_before_invocation": completed_before,
            "peak_aggregate_rss_bytes": monitor.peak_aggregate_rss_bytes,
            "minimum_mem_available_bytes": monitor.minimum_mem_available_bytes,
        }
    )
    atomic_write_json(checkpoint_path, final)
    history = {
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        **{
            key: final[key]
            for key in (
                "manifest_sha256",
                "workers",
                "new_trials_completed",
                "completed_before_invocation",
                "completed_trials",
                "run_wall_seconds_this_invocation",
                "peak_aggregate_rss_bytes",
                "minimum_mem_available_bytes",
            )
        },
    }
    append_jsonl(output_dir / "run_history.jsonl", history, fsync=True)
    if benchmark_report is not None:
        write_benchmark_report(
            benchmark_report,
            manifest,
            new_rows,
            wall_seconds=wall_seconds,
            workers=workers,
            monitor=monitor,
        )
    invocation.update(
        {
            "status": "complete",
            "finished_at_utc": utc_now(),
            "completed_after_invocation": len(completed_rows),
        }
    )
    atomic_write_json(invocation_path, invocation)
    return final


def run_campaign(
    output_dir: Path,
    *,
    workers: int,
    max_new_trials: int | None,
    benchmark_report: Path | None,
) -> dict[str, Any]:
    """Run one fail-closed invocation and ledger any post-preflight failure."""

    invocation_path = output_dir / "active_invocation.json"
    try:
        return _run_campaign_impl(
            output_dir,
            workers=workers,
            max_new_trials=max_new_trials,
            benchmark_report=benchmark_report,
        )
    except Exception as exc:
        if invocation_path.exists():
            try:
                invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
            except Exception:
                invocation = {}
            if invocation.get("status") == "running":
                failure = {
                    "schema_version": SCHEMA_VERSION,
                    "version_label": VERSION_LABEL,
                    "status": "failed",
                    "failure_scope": "parent_invocation",
                    "invocation_id": invocation.get("invocation_id"),
                    "manifest_sha256": invocation.get("manifest_sha256"),
                    "scenario_id": None,
                    "failed_at_utc": utc_now(),
                    "retry_authorized": False,
                    "exception": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "traceback": traceback.format_exc(),
                    },
                }
                append_jsonl(output_dir / "failures.jsonl", failure, fsync=True)
                invocation.update(
                    {
                        "status": "failed_closed",
                        "finished_at_utc": utc_now(),
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                    }
                )
                atomic_write_json(invocation_path, invocation)
        raise


def campaign_status(output_dir: Path) -> dict[str, Any]:
    output_dir = require_phase8_path(output_dir, label="output directory")
    manifest = load_manifest(output_dir / "manifest.json")
    rows, zero_state = scan_results(output_dir / "raw_scenarios.jsonl", manifest)
    failures = output_dir / "failures.jsonl"
    failure_rows = 0
    if failures.exists():
        with failures.open(encoding="utf-8") as handle:
            failure_rows = sum(1 for line in handle if line.strip())
    complete_zero_pairs = sum(
        set(cell) == {"reference", "open_zero"} for cell in zero_state.values()
    )
    result = checkpoint_document(
        manifest,
        len(rows),
        started_at_utc=utc_now(),
        last_scenario_id=None,
    )
    result.update(
        {
            "failure_rows": failure_rows,
            "zero_equivalence_complete_holders": complete_zero_pairs,
            "raw_results_sha256": file_sha256(output_dir / "raw_scenarios.jsonl")
            if rows
            else None,
        }
    )
    if failure_rows:
        result["status"] = "failed_closed"
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    run = commands.add_parser("run")
    run.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    run.add_argument("--workers", type=int, default=16)
    run.add_argument("--max-new-trials", type=int)
    run.add_argument("--benchmark-report", type=Path)
    status = commands.add_parser("status")
    status.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        manifest = write_plan(args.output_dir)
        output = {
            "status": manifest["status"],
            "manifest": str(args.output_dir / "manifest.json"),
            "manifest_sha256": manifest["manifest_sha256"],
            "holders": len(manifest["selected_units"]),
            "trials": len(manifest["trial_plan"]),
            "benchmark_trials": len(manifest["benchmark"]["scenario_ids"]),
        }
    elif args.command == "run":
        output = run_campaign(
            args.output_dir,
            workers=args.workers,
            max_new_trials=args.max_new_trials,
            benchmark_report=args.benchmark_report,
        )
    elif args.command == "status":
        output = campaign_status(args.output_dir)
    else:
        raise AssertionError(f"unknown command {args.command}")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
