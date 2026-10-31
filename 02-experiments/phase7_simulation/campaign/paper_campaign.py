"""Paper-scale, checkpointable BGPy campaign for DA-ROV.

This module keeps simulator code outside ``vendor``.  The manifest is the
frozen experimental contract: 200 unique-holder units, three within-unit
attacker classes, seven deployment-order blocks, shared 0/100% endpoints, and
announcement-matched delegate-only/competition lanes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import platform
import random
import re
import signal
import sys
import threading
import traceback
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable, Mapping, Sequence

import bgpy
from bgpy.as_graphs import ASGraph
from bgpy.simulation_engine import SimulationEngine

from phase4_encoding.scripts.utils.daroa import is_eligible_delegated_origin
from phase7_simulation.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    B1_COMPETITION,
    B1_DELEGATE,
    B2_COMPETITION,
    B2_DELEGATE,
    CHILD_OUTCOMES,
    DESTINATION_OUTCOMES,
    D1_OPEN_DELEGATE,
    RANDOM_SEED,
    REPOSITORY_ROOT,
    ROV_COUNT,
    SINGLE_TRIAL_LIMIT_SECONDS,
    TOPOLOGY_PATH,
    VENDOR_PATH,
    CandidateRow,
    DAROV,
    PairSpec,
    PeakRSSMonitor,
    _trace_destination,
    build_fixed_graph,
    build_scenario,
    collect_hashes,
    current_rss_bytes,
    degree_by_asn,
    git_value,
    load_candidate_rows,
    load_rov_asns,
    make_open_policy,
    trial_alarm,
    verify_policy_assignment,
)


SCHEMA_VERSION = 1
SAMPLE_SEED = RANDOM_SEED
ATTACKER_SEED = 20260805
SAMPLE_PER_STRATUM = 50
EXPECTED_UNITS = 200
DEPLOYMENT_PERCENTAGES = (0, 1, 5, 10, 25, 50, 75, 100)
INTERMEDIATE_PERCENTAGES = DEPLOYMENT_PERCENTAGES[1:-1]
RANDOM_DEPLOYMENT_SEEDS = (1, 2, 3, 4, 5)
ATTACKER_CLASSES = ("uniform", "edge", "high_degree")
PER_WORKER_RSS_LIMIT_BYTES = 1536 * 1024**2
AGGREGATE_RSS_LIMIT_BYTES = 24 * 1024**3
MIN_MEM_AVAILABLE_BYTES = 16 * 1024**3

HOLDER_STRATA = (
    ("S1", "1-2", 1, 2),
    ("S2", "3-18", 3, 18),
    ("S3", "19-101", 19, 101),
    ("S4", ">=102", 102, None),
)
EXPECTED_STRATUM_POPULATIONS = {
    "S1": 161,
    "S2": 177,
    "S3": 179,
    "S4": 174,
}

PAPER_CAMPAIGN_PATH = Path(__file__).resolve()
DEFAULT_OUTPUT_DIR = REPOSITORY_ROOT / "phase7_simulation" / "results" / "paper_campaign"
DEPENDENCY_LOCK_PATH = (
    REPOSITORY_ROOT / "phase7_simulation" / "requirements-bgpy.lock.txt"
)
THIRD_PARTY_LOCK_PATH = REPOSITORY_ROOT / "phase7_simulation" / "third_party.lock.json"


class CampaignContractError(ValueError):
    """Raised when a manifest or checkpoint violates the frozen contract."""


class ParentResourceStop(RuntimeError):
    """Raised when the aggregate production memory contract is crossed."""


class ZeroEquivalenceError(CampaignContractError):
    """Raised as soon as an announcement-matched zero cell disagrees."""

    def __init__(self, current_id: str, matched_id: str) -> None:
        self.current_id = current_id
        self.matched_id = matched_id
        super().__init__(
            f"zero-upgrade outcome mismatch: {current_id} != {matched_id}"
        )


@dataclass(frozen=True)
class SampledUnit:
    """One unique-holder/root counterfactual unit."""

    unit_id: str
    pair_index: int
    source_row: int
    root_prefix: str
    holder_asn: int
    leaf_prefix: str
    delegate_asn: int
    holder_degree: int
    delegate_degree: int
    holder_stratum: str
    holder_stratum_degree_range: str
    N_h: int
    n_h: int
    stratum_population_N_h: int
    stratum_sample_n_h: int
    design_weight: float
    cluster_id: str
    holder_selection_sha256: str
    root_selection_sha256: str
    delegate_selection_sha256: str
    leaf_selection_sha256: str
    uniform_attacker_asn: int | None = None
    uniform_attacker_degree: int | None = None
    edge_attacker_asn: int | None = None
    edge_attacker_degree: int | None = None
    high_degree_attacker_asn: int | None = None
    high_degree_attacker_degree: int | None = None

    def attacker(self, attacker_class: str) -> tuple[int, int]:
        if attacker_class not in ATTACKER_CLASSES:
            raise CampaignContractError(f"unknown attacker class {attacker_class!r}")
        asn = getattr(self, f"{attacker_class}_attacker_asn")
        degree = getattr(self, f"{attacker_class}_attacker_degree")
        if asn is None or degree is None:
            raise CampaignContractError(
                f"unit {self.unit_id} has no {attacker_class} attacker"
            )
        return asn, degree


@dataclass(frozen=True)
class DeploymentOrder:
    """One nested deployment block over the fixed 589-AS ROV set."""

    order_id: str
    strategy: str
    seed: int | None
    asns: tuple[int, ...]
    order_sha256: str


@dataclass(frozen=True)
class CampaignTrial:
    """One physical simulation listed in the manifest."""

    scenario_id: str
    unit_id: str
    pair_index: int
    lane: str
    announcement_set: str
    policy_reference: str
    attacker_class: str | None
    deployment_strategy: str
    deployment_seed: int | None
    deployment_percent_target: int
    order_id: str | None
    shared_for_order_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PaperExecutionSpec:
    """Duck-typed input accepted by the gate's scenario builder."""

    pair: PairSpec
    lane: str
    deployment_percent: int
    deployment_strategy: str
    scenario_id: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_sha256(seed: int, domain: str, *parts: object) -> str:
    payload = "\0".join((str(seed), domain, *(str(part) for part in parts)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def holder_stratum(degree: int) -> str:
    if degree < 1:
        raise CampaignContractError(f"holder degree must be positive, got {degree}")
    for name, _range_label, lower, upper in HOLDER_STRATA:
        if degree >= lower and (upper is None or degree <= upper):
            return name
    raise AssertionError("unreachable holder stratum")


def _hash_pick(
    values: Iterable[Any],
    *,
    seed: int,
    domain: str,
    key,
) -> tuple[Any, str]:
    ranked = sorted(
        ((stable_sha256(seed, domain, *key(value)), value) for value in values),
        key=lambda item: (item[0], key(item[1])),
    )
    if not ranked:
        raise CampaignContractError(f"empty selection level {domain}")
    return ranked[0][1], ranked[0][0]


def sample_holder_units(
    rows: Iterable[CandidateRow],
    degrees: Mapping[int, int],
    *,
    seed: int = SAMPLE_SEED,
    n_per_stratum: int = SAMPLE_PER_STRATUM,
    expected_populations: Mapping[str, int] | None = EXPECTED_STRATUM_POPULATIONS,
) -> tuple[tuple[SampledUnit, ...], dict[str, Any]]:
    """SHA256-sample holder -> root -> distinct delegate -> leaf."""

    by_holder: dict[int, list[CandidateRow]] = defaultdict(list)
    for row in rows:
        if row.holder_asn not in degrees or row.delegate_asn not in degrees:
            continue
        if not all(
            is_eligible_delegated_origin(asn)
            for asn in (row.holder_asn, row.delegate_asn)
        ):
            continue
        by_holder[row.holder_asn].append(row)

    holders_by_stratum: dict[str, list[int]] = defaultdict(list)
    for holder in by_holder:
        holders_by_stratum[holder_stratum(degrees[holder])].append(holder)
    populations = {
        name: len(holders_by_stratum.get(name, ()))
        for name, _, _, _ in HOLDER_STRATA
    }
    if expected_populations is not None and populations != dict(expected_populations):
        raise CampaignContractError(
            f"eligible-holder population drift: {populations}, expected "
            f"{dict(expected_populations)}"
        )

    selected: list[tuple[str, int, str, CandidateRow, tuple[str, str, str]]] = []
    allocation: dict[str, dict[str, float | int]] = {}
    range_by_stratum = {name: label for name, label, _, _ in HOLDER_STRATA}
    for stratum_name, _range_label, _, _ in HOLDER_STRATA:
        population = sorted(holders_by_stratum.get(stratum_name, ()))
        if len(population) < n_per_stratum:
            raise CampaignContractError(
                f"stratum {stratum_name} has {len(population)} holders, "
                f"cannot sample {n_per_stratum}"
            )
        holder_ranked = sorted(
            (
                (stable_sha256(seed, "holder", stratum_name, holder), holder)
                for holder in population
            ),
            key=lambda item: (item[0], item[1]),
        )[:n_per_stratum]
        allocation[stratum_name] = {
            "N_h": len(population),
            "n_h": n_per_stratum,
            "design_weight_N_h_over_n_h": len(population) / n_per_stratum,
        }
        for holder_hash, holder in holder_ranked:
            holder_rows = by_holder[holder]
            root, root_hash = _hash_pick(
                {row.root_prefix for row in holder_rows},
                seed=seed,
                domain="root",
                key=lambda value: (holder, value),
            )
            root_rows = [row for row in holder_rows if row.root_prefix == root]
            delegate, delegate_hash = _hash_pick(
                {row.delegate_asn for row in root_rows},
                seed=seed,
                domain="delegate",
                key=lambda value: (holder, root, value),
            )
            delegate_rows = [
                row for row in root_rows if row.delegate_asn == delegate
            ]
            chosen_row, leaf_hash = _hash_pick(
                delegate_rows,
                seed=seed,
                domain="leaf",
                key=lambda row: (
                    holder,
                    root,
                    delegate,
                    row.leaf_prefix,
                    row.source_row,
                ),
            )
            selected.append(
                (
                    stratum_name,
                    holder,
                    holder_hash,
                    chosen_row,
                    (root_hash, delegate_hash, leaf_hash),
                )
            )

    selected.sort(key=lambda item: (item[0], item[1]))
    units: list[SampledUnit] = []
    for pair_index, (
        stratum_name,
        holder,
        holder_hash,
        row,
        level_hashes,
    ) in enumerate(selected, start=1):
        N_h = len(holders_by_stratum[stratum_name])
        units.append(
            SampledUnit(
                unit_id=f"unit{pair_index:04d}",
                pair_index=pair_index,
                source_row=row.source_row,
                root_prefix=row.root_prefix,
                holder_asn=holder,
                leaf_prefix=row.leaf_prefix,
                delegate_asn=row.delegate_asn,
                holder_degree=degrees[holder],
                delegate_degree=degrees[row.delegate_asn],
                holder_stratum=stratum_name,
                holder_stratum_degree_range=range_by_stratum[stratum_name],
                N_h=N_h,
                n_h=n_per_stratum,
                stratum_population_N_h=N_h,
                stratum_sample_n_h=n_per_stratum,
                design_weight=N_h / n_per_stratum,
                cluster_id=f"holder:{holder}",
                holder_selection_sha256=holder_hash,
                root_selection_sha256=level_hashes[0],
                delegate_selection_sha256=level_hashes[1],
                leaf_selection_sha256=level_hashes[2],
            )
        )

    if len({unit.holder_asn for unit in units}) != len(units):
        raise CampaignContractError("sample contains repeated holders")
    if len({unit.root_prefix for unit in units}) != len(units):
        raise CampaignContractError("sample contains repeated roots")
    return tuple(units), {
        "seed": seed,
        "hierarchy": "holder -> root -> distinct delegate -> leaf",
        "allocation": allocation,
        "eligible_unique_holders": len(by_holder),
        "sampled_units": len(units),
        "sampling_unit": "holder",
        "cluster_id": "holder ASN",
    }


def attach_attackers(
    units: Sequence[SampledUnit],
    degrees: Mapping[int, int],
    *,
    seed: int = ATTACKER_SEED,
    top_fraction: float = 0.01,
) -> tuple[tuple[SampledUnit, ...], dict[str, Any]]:
    """Assign three within-unit attacker factors without replacement per class."""

    endpoints = {
        asn for unit in units for asn in (unit.holder_asn, unit.delegate_asn)
    }
    eligible_universe = sorted(
        asn for asn in degrees if is_eligible_delegated_origin(asn)
    )
    top_n = max(1, math.ceil(len(eligible_universe) * top_fraction))
    top_ranked = sorted(
        eligible_universe, key=lambda asn: (-degrees[asn], asn)
    )[:top_n]
    pools = {
        "uniform": [asn for asn in eligible_universe if asn not in endpoints],
        "edge": [
            asn
            for asn in eligible_universe
            if degrees[asn] == 1 and asn not in endpoints
        ],
        "high_degree": [asn for asn in top_ranked if asn not in endpoints],
    }
    selected_by_class: dict[str, list[int]] = {}
    provenance: dict[str, Any] = {
        "seed": seed,
        "without_replacement_within_class": True,
        "excluded_holder_delegate_asns": len(endpoints),
        "eligible_universe_size": len(eligible_universe),
        "top_fraction": top_fraction,
        "top_n_before_endpoint_exclusion": top_n,
        "top_degree_cutoff": degrees[top_ranked[-1]],
        "classes": {},
    }
    used_by_unit = [set() for _ in units]
    for attacker_class in ATTACKER_CLASSES:
        pool = pools[attacker_class]
        if len(pool) < len(units):
            raise CampaignContractError(
                f"{attacker_class} pool has {len(pool)} ASes for {len(units)} units"
            )
        ranked = sorted(
            pool,
            key=lambda asn: (
                stable_sha256(seed, "attacker", attacker_class, asn),
                asn,
            ),
        )
        selected: list[int] = []
        used_in_class: set[int] = set()
        for unit_index in range(len(units)):
            candidate = next(
                (
                    asn
                    for asn in ranked
                    if asn not in used_in_class
                    and asn not in used_by_unit[unit_index]
                ),
                None,
            )
            if candidate is None:
                raise CampaignContractError(
                    f"cannot assign distinct {attacker_class} attacker to "
                    f"unit index {unit_index}"
                )
            selected.append(candidate)
            used_in_class.add(candidate)
            used_by_unit[unit_index].add(candidate)
        selected_by_class[attacker_class] = selected
        provenance["classes"][attacker_class] = {
            "pool_size_after_endpoint_exclusion": len(pool),
            "selected": len(units),
            "selected_asns_sha256": hashlib.sha256(
                "\n".join(str(asn) for asn in selected).encode()
            ).hexdigest(),
        }

    attached: list[SampledUnit] = []
    for index, unit in enumerate(units):
        uniform = selected_by_class["uniform"][index]
        edge = selected_by_class["edge"][index]
        high = selected_by_class["high_degree"][index]
        attached.append(
            replace(
                unit,
                uniform_attacker_asn=uniform,
                uniform_attacker_degree=degrees[uniform],
                edge_attacker_asn=edge,
                edge_attacker_degree=degrees[edge],
                high_degree_attacker_asn=high,
                high_degree_attacker_degree=degrees[high],
            )
        )
    for attacker_class in ATTACKER_CLASSES:
        assigned = [unit.attacker(attacker_class)[0] for unit in attached]
        if len(set(assigned)) != len(attached):
            raise CampaignContractError(
                f"{attacker_class} assignments are not without replacement"
            )
    for unit in attached:
        assigned = {unit.attacker(name)[0] for name in ATTACKER_CLASSES}
        if len(assigned) != len(ATTACKER_CLASSES):
            raise CampaignContractError(
                f"unit {unit.unit_id} does not have three distinct attackers"
            )
    return tuple(attached), provenance


def customer_cone_sizes(
    graph: ASGraph, target_asns: Iterable[int]
) -> dict[int, int]:
    """Use BGPy's exact customer-cone routine, then select target ASNs."""

    graph._get_and_store_customer_cone_and_set_size(False)
    result: dict[int, int] = {}
    for asn in target_asns:
        size = graph.as_dict[asn].customer_cone_size
        if size is None:
            raise CampaignContractError(f"BGPy did not compute cone size for AS{asn}")
        result[asn] = size
    return result


def _order_hash(asns: Sequence[int]) -> str:
    return hashlib.sha256("\n".join(str(asn) for asn in asns).encode()).hexdigest()


def build_deployment_orders(
    rov_asns: frozenset[int],
    degrees: Mapping[int, int],
    cone_sizes: Mapping[int, int],
    *,
    random_seeds: Sequence[int] = RANDOM_DEPLOYMENT_SEEDS,
) -> tuple[DeploymentOrder, ...]:
    if len(rov_asns) != ROV_COUNT:
        raise CampaignContractError(f"expected {ROV_COUNT} fixed ROV ASes")
    if rov_asns.difference(degrees) or rov_asns.difference(cone_sizes):
        raise CampaignContractError("deployment score is missing a fixed ROV AS")
    orders: list[DeploymentOrder] = []
    degree_order = tuple(sorted(rov_asns, key=lambda asn: (-degrees[asn], asn)))
    orders.append(
        DeploymentOrder(
            "degree",
            "degree",
            None,
            degree_order,
            _order_hash(degree_order),
        )
    )
    cone_order = tuple(sorted(rov_asns, key=lambda asn: (-cone_sizes[asn], asn)))
    orders.append(
        DeploymentOrder(
            "customer_cone",
            "customer_cone",
            None,
            cone_order,
            _order_hash(cone_order),
        )
    )
    for seed in random_seeds:
        values = sorted(rov_asns)
        random.Random(seed).shuffle(values)
        order = tuple(values)
        orders.append(
            DeploymentOrder(
                f"random_{seed:02d}",
                "random",
                seed,
                order,
                _order_hash(order),
            )
        )
    if any(set(order.asns) != set(rov_asns) for order in orders):
        raise CampaignContractError("a deployment order is not an ROV permutation")
    return tuple(orders)


def deployment_count(percent: int, rov_count: int = ROV_COUNT) -> int:
    if percent not in DEPLOYMENT_PERCENTAGES:
        raise CampaignContractError(f"unsupported deployment percentage {percent}")
    return rov_count if percent == 100 else int(rov_count * percent / 100)


def _scenario_id(
    unit: SampledUnit,
    lane: str,
    attacker_class: str | None,
    strategy: str,
    seed: int | None,
    percent: int,
) -> str:
    seed_label = "na" if seed is None else f"{seed:02d}"
    attacker_label = "none" if attacker_class is None else attacker_class
    return (
        f"{unit.unit_id}__{lane}__atk-{attacker_label}__{strategy}__"
        f"seed-{seed_label}__pct-{percent:03d}"
    )


def build_trial_plan(
    units: Sequence[SampledUnit],
    orders: Sequence[DeploymentOrder],
) -> tuple[CampaignTrial, ...]:
    """Build the frozen 184-trial/unit physical matrix."""

    order_ids = tuple(order.order_id for order in orders)
    trials: list[CampaignTrial] = []
    for unit in units:
        # Eight fixed references: B1/B2 delegate, then B1/B2 competition x3.
        for lane, reference in (
            (B1_DELEGATE, "aggregate_only_reference"),
            (B2_DELEGATE, "exact_child_reference"),
        ):
            trials.append(
                CampaignTrial(
                    _scenario_id(unit, lane, None, "reference", None, 0),
                    unit.unit_id,
                    unit.pair_index,
                    lane,
                    "delegate_only",
                    reference,
                    None,
                    "reference",
                    None,
                    0,
                    None,
                )
            )
        for attacker_class in ATTACKER_CLASSES:
            for lane, reference in (
                (B1_COMPETITION, "aggregate_only_reference"),
                (B2_COMPETITION, "exact_child_reference"),
            ):
                trials.append(
                    CampaignTrial(
                        _scenario_id(
                            unit, lane, attacker_class, "reference", None, 0
                        ),
                        unit.unit_id,
                        unit.pair_index,
                        lane,
                        "competition",
                        reference,
                        attacker_class,
                        "reference",
                        None,
                        0,
                        None,
                    )
                )

        # 0/100 are identical across deployment orders and physically shared.
        for percent in (0, 100):
            trials.append(
                CampaignTrial(
                    _scenario_id(
                        unit,
                        D1_OPEN_DELEGATE,
                        None,
                        "shared",
                        None,
                        percent,
                    ),
                    unit.unit_id,
                    unit.pair_index,
                    D1_OPEN_DELEGATE,
                    "delegate_only",
                    "open_staged",
                    None,
                    "shared",
                    None,
                    percent,
                    None,
                    order_ids,
                )
            )
            for attacker_class in ATTACKER_CLASSES:
                trials.append(
                    CampaignTrial(
                        _scenario_id(
                            unit,
                            A1_OPEN_COMPETITION,
                            attacker_class,
                            "shared",
                            None,
                            percent,
                        ),
                        unit.unit_id,
                        unit.pair_index,
                        A1_OPEN_COMPETITION,
                        "competition",
                        "open_staged",
                        attacker_class,
                        "shared",
                        None,
                        percent,
                        None,
                        order_ids,
                    )
                )

        for order in orders:
            for percent in INTERMEDIATE_PERCENTAGES:
                trials.append(
                    CampaignTrial(
                        _scenario_id(
                            unit,
                            D1_OPEN_DELEGATE,
                            None,
                            order.strategy,
                            order.seed,
                            percent,
                        ),
                        unit.unit_id,
                        unit.pair_index,
                        D1_OPEN_DELEGATE,
                        "delegate_only",
                        "open_staged",
                        None,
                        order.strategy,
                        order.seed,
                        percent,
                        order.order_id,
                    )
                )
                for attacker_class in ATTACKER_CLASSES:
                    trials.append(
                        CampaignTrial(
                            _scenario_id(
                                unit,
                                A1_OPEN_COMPETITION,
                                attacker_class,
                                order.strategy,
                                order.seed,
                                percent,
                            ),
                            unit.unit_id,
                            unit.pair_index,
                            A1_OPEN_COMPETITION,
                            "competition",
                            "open_staged",
                            attacker_class,
                            order.strategy,
                            order.seed,
                            percent,
                            order.order_id,
                        )
                    )
    expected = 184 * len(units)
    if len(trials) != expected:
        raise CampaignContractError(
            f"trial plan has {len(trials)} rows, expected {expected}"
        )
    ids = [trial.scenario_id for trial in trials]
    if len(ids) != len(set(ids)):
        raise CampaignContractError("trial plan contains duplicate scenario IDs")
    return tuple(trials)


# Execution/checkpoint implementation follows below in this module.  Keeping
# planning functions importable makes manifest and statistics audits possible
# without constructing a BGPy graph or launching worker processes.


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    """Hash an imported package tree without cache or machine-specific paths."""

    if not root.is_dir():
        raise CampaignContractError(f"imported package root does not exist: {root}")
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )
    if not files:
        raise CampaignContractError(f"imported package tree is empty: {root}")
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_file_sha256(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_dependencies() -> tuple[dict[str, str], str]:
    """Parse the exact, marker-free Phase-7 environment lock."""

    locked: dict[str, str] = {}
    for line_number, raw in enumerate(
        DEPENDENCY_LOCK_PATH.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1 or any(token in line for token in (";", "@", " ")):
            raise CampaignContractError(
                f"{DEPENDENCY_LOCK_PATH.name}:{line_number}: "
                "expected an exact name==version pin"
            )
        raw_name, locked_version = line.split("==", 1)
        name = _canonical_distribution_name(raw_name)
        if not name or not locked_version or name in locked:
            raise CampaignContractError(
                f"{DEPENDENCY_LOCK_PATH.name}:{line_number}: invalid/duplicate pin"
            )
        locked[name] = locked_version
    if "bgpy-pkg" not in locked or "numpy" not in locked:
        raise CampaignContractError(
            "dependency lock must include bgpy-pkg and numpy"
        )
    normalized = "".join(
        f"{name}=={locked[name]}\n" for name in sorted(locked)
    )
    return locked, hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _locked_bgpy_vendor() -> Mapping[str, Any]:
    document = json.loads(THIRD_PARTY_LOCK_PATH.read_text(encoding="utf-8"))
    dependencies = document.get("dependencies") if isinstance(document, dict) else None
    if not isinstance(dependencies, list):
        raise CampaignContractError("third_party.lock.json has no dependency list")
    matches = [
        item
        for item in dependencies
        if isinstance(item, dict) and item.get("name") == "BGPy"
    ]
    if len(matches) != 1:
        raise CampaignContractError("third_party.lock.json must pin BGPy once")
    return matches[0]


def runtime_environment_fingerprint() -> dict[str, Any]:
    """Describe and validate the exact interpreter and imported BGPy code.

    Stored paths are logical labels, never host-specific absolute paths.  The
    package-tree digest distinguishes the vendored checkout from an installed
    wheel even when both advertise the same distribution version.
    """

    locked, dependency_digest = _locked_dependencies()
    resolved: dict[str, str] = {}
    for name, locked_version in sorted(locked.items()):
        try:
            installed_version = version(name)
        except PackageNotFoundError as exc:
            raise CampaignContractError(
                f"locked dependency {name} is not installed"
            ) from exc
        if installed_version != locked_version:
            raise CampaignContractError(
                f"locked dependency {name} is {installed_version}, "
                f"expected {locked_version}"
            )
        resolved[name] = installed_version

    vendor_lock = _locked_bgpy_vendor()
    vendor_commit = git_value(("rev-parse", "HEAD"), VENDOR_PATH)
    locked_commit = str(vendor_lock.get("commit", ""))
    if vendor_commit != locked_commit:
        raise CampaignContractError(
            f"BGPy vendor commit {vendor_commit} != lock {locked_commit}"
        )
    vendor_status = git_value(("status", "--porcelain"), VENDOR_PATH)
    if vendor_status:
        raise CampaignContractError("BGPy vendor checkout is dirty")

    bgpy_version = version("bgpy-pkg")
    locked_distribution = str(vendor_lock.get("distribution", ""))
    expected_distribution = f"bgpy-pkg=={bgpy_version}"
    if locked_distribution != expected_distribution:
        raise CampaignContractError(
            f"BGPy distribution {expected_distribution} != third-party lock "
            f"{locked_distribution!r}"
        )

    module_file = Path(bgpy.__file__).resolve()
    module_root = module_file.parent
    vendor_module_root = (VENDOR_PATH / "bgpy").resolve()
    installed_module_root = Path(
        distribution("bgpy-pkg").locate_file("bgpy")
    ).resolve()
    if module_root == vendor_module_root:
        source_kind = "vendor_checkout"
        source_label = "phase7_simulation/vendor/bgpy/bgpy"
    elif module_root == installed_module_root:
        source_kind = "installed_distribution"
        source_label = "python-site-packages/bgpy"
    else:
        raise CampaignContractError(
            "bgpy was imported from neither the pinned vendor checkout nor "
            "the installed bgpy-pkg distribution"
        )

    return {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "cache_tag": sys.implementation.cache_tag,
        },
        "bgpy": {
            "distribution": "bgpy-pkg",
            "version": bgpy_version,
            "import_source_kind": source_kind,
            "import_source_label": source_label,
            "imported_package_tree_sha256": _tree_sha256(module_root),
            "vendor_commit": vendor_commit,
            "vendor_dirty": False,
        },
        "dependencies": {
            "lock_path": "phase7_simulation/requirements-bgpy.lock.txt",
            "lock_file_sha256": _file_sha256(DEPENDENCY_LOCK_PATH),
            "normalized_pins_sha256": dependency_digest,
            "resolved_versions": resolved,
        },
    }


def verify_runtime_environment(manifest: Mapping[str, Any]) -> None:
    expected = manifest.get("runtime_environment")
    if not isinstance(expected, Mapping):
        raise CampaignContractError("manifest has no runtime-environment contract")
    actual = runtime_environment_fingerprint()
    if dict(expected) != actual:
        raise CampaignContractError(
            "current Python/dependencies/imported BGPy differ from manifest"
        )


def campaign_artifact_hashes() -> dict[str, Any]:
    inherited = collect_hashes()
    files = dict(inherited["files"])
    files["paper_campaign_runner"] = hashlib.sha256(
        PAPER_CAMPAIGN_PATH.read_bytes()
    ).hexdigest()
    files["dependency_lock"] = _file_sha256(DEPENDENCY_LOCK_PATH)
    files["third_party_lock"] = _file_sha256(THIRD_PARTY_LOCK_PATH)
    bundle = hashlib.sha256()
    for name, digest in sorted(files.items()):
        bundle.update(name.encode())
        bundle.update(b"\0")
        bundle.update(digest.encode())
        bundle.update(b"\n")
    return {"files": files, "bundle_sha256": bundle.hexdigest()}


def manifest_sha256(document: Mapping[str, Any]) -> str:
    core = dict(document)
    core.pop("manifest_sha256", None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def expected_ids_sha256(trials: Sequence[CampaignTrial]) -> str:
    return hashlib.sha256(
        ("\n".join(sorted(trial.scenario_id for trial in trials)) + "\n").encode()
    ).hexdigest()


def build_manifest_document(
    graph: ASGraph,
    *,
    sample_seed: int = SAMPLE_SEED,
    attacker_seed: int = ATTACKER_SEED,
) -> dict[str, Any]:
    """Build the complete frozen manifest without running propagation."""

    degrees = degree_by_asn(graph)
    rov_asns = load_rov_asns()
    units, sampling = sample_holder_units(
        load_candidate_rows(),
        degrees,
        seed=sample_seed,
    )
    units, attacker_provenance = attach_attackers(
        units,
        degrees,
        seed=attacker_seed,
    )
    cone_started = perf_counter()
    with PeakRSSMonitor() as cone_memory:
        cones = customer_cone_sizes(graph, rov_asns)
    cone_elapsed = perf_counter() - cone_started
    orders = build_deployment_orders(rov_asns, degrees, cones)
    trials = build_trial_plan(units, orders)
    runtime = runtime_environment_fingerprint()
    order_documents = []
    for order in orders:
        item = asdict(order)
        item["deployment_counts"] = {
            str(percent): deployment_count(percent)
            for percent in DEPLOYMENT_PERCENTAGES
        }
        order_documents.append(item)

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": utc_now(),
        "status": "planned_not_executed",
        "engine": {
            "name": "BGPy",
            "version": runtime["bgpy"]["version"],
            "vendor_commit": runtime["bgpy"]["vendor_commit"],
            "vendor_dirty": runtime["bgpy"]["vendor_dirty"],
            "vendor_modified_by_campaign": False,
        },
        "runtime_environment": runtime,
        "repository_commit": git_value(("rev-parse", "HEAD"), REPOSITORY_ROOT),
        "repository_dirty_at_plan": bool(
            git_value(("status", "--porcelain"), REPOSITORY_ROOT)
        ),
        "artifact_hashes_sha256": campaign_artifact_hashes(),
        "topology": {
            "path": TOPOLOGY_PATH.relative_to(REPOSITORY_ROOT).as_posix(),
            "asns": len(graph),
            "fixed_rov_asns": sorted(rov_asns),
            "fixed_rov_count": len(rov_asns),
            "customer_cone_algorithm": (
                "BGPy _get_and_store_customer_cone_and_set_size(False)"
            ),
            "customer_cone_elapsed_seconds": cone_elapsed,
            "customer_cone_peak_rss_bytes": cone_memory.peak_bytes,
            "rov_customer_cone_sizes": {
                str(asn): cones[asn] for asn in sorted(cones)
            },
        },
        "design": {
            "estimand": (
                "design-weighted eligible-holder counterfactual mean within "
                "four fixed holder-degree strata"
            ),
            "sampling": sampling,
            "expected_stratum_populations": EXPECTED_STRATUM_POPULATIONS,
            "attacker_assignment": attacker_provenance,
            "attacker_classes": list(ATTACKER_CLASSES),
            "deployment_percentages": list(DEPLOYMENT_PERCENTAGES),
            "random_deployment_seeds": list(RANDOM_DEPLOYMENT_SEEDS),
            "random_seed_role": (
                "repeated deployment block; not an independent sample unit"
            ),
            "shared_endpoints": [0, 100],
            "physical_trials_per_unit": 184,
            "fixed_reference_trials_per_unit": 8,
            "staged_trials_per_unit": 176,
            "announcement_matched_lanes": {
                "delegate_only": [B1_DELEGATE, B2_DELEGATE, D1_OPEN_DELEGATE],
                "competition": [
                    B1_COMPETITION,
                    B2_COMPETITION,
                    A1_OPEN_COMPETITION,
                ],
            },
        },
        "selected_units": [
            {
                **asdict(unit),
                "attackers": {
                    attacker_class: {
                        "asn": unit.attacker(attacker_class)[0],
                        "degree": unit.attacker(attacker_class)[1],
                    }
                    for attacker_class in ATTACKER_CLASSES
                },
            }
            for unit in units
        ],
        "deployment_orders": order_documents,
        "trial_plan": [asdict(trial) for trial in trials],
        "expected_scenario_ids": {
            "source": "trial_plan[].scenario_id",
            "count": len(trials),
            "sorted_newline_sha256": expected_ids_sha256(trials),
        },
        "execution_contract": {
            "default_workers": 16,
            "benchmark_workers_before_scale_up": 16,
            "candidate_workers_after_benchmark": 24,
            "multiprocessing_start_method": "spawn",
            "graph_build_location": "worker initializer",
            "graph_reused_within_worker": True,
            "parent_single_jsonl_writer": True,
            "single_trial_limit_seconds": SINGLE_TRIAL_LIMIT_SECONDS,
            "per_worker_peak_rss_limit_bytes": PER_WORKER_RSS_LIMIT_BYTES,
            "aggregate_rss_limit_bytes": AGGREGATE_RSS_LIMIT_BYTES,
            "minimum_mem_available_bytes": MIN_MEM_AVAILABLE_BYTES,
            "silent_retries": 0,
            "failed_scenario_resume": "explicit_retry_failures_flag_only",
            "incremental_zero_equivalence": True,
        },
    }
    document["manifest_sha256"] = manifest_sha256(document)
    validate_manifest(document, production=True)
    return document


def validate_manifest(document: Mapping[str, Any], *, production: bool) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        raise CampaignContractError("unsupported manifest schema")
    expected_digest = manifest_sha256(document)
    if document.get("manifest_sha256") != expected_digest:
        raise CampaignContractError("manifest SHA256 mismatch")
    runtime = document.get("runtime_environment")
    engine = document.get("engine")
    if not isinstance(runtime, Mapping) or not isinstance(
        runtime.get("bgpy"), Mapping
    ):
        raise CampaignContractError("manifest has no BGPy runtime fingerprint")
    if not isinstance(engine, Mapping) or any(
        engine.get(key) != runtime["bgpy"].get(key)
        for key in ("version", "vendor_commit", "vendor_dirty")
    ):
        raise CampaignContractError("engine metadata differs from runtime fingerprint")
    if runtime["bgpy"].get("vendor_dirty") is not False:
        raise CampaignContractError("production manifest cannot pin a dirty BGPy tree")
    raw_trials = document.get("trial_plan")
    raw_units = document.get("selected_units")
    if not isinstance(raw_trials, list) or not isinstance(raw_units, list):
        raise CampaignContractError("manifest units/trial_plan must be lists")
    ids = [trial.get("scenario_id") for trial in raw_trials]
    if any(not isinstance(scenario_id, str) for scenario_id in ids):
        raise CampaignContractError("manifest has a non-string scenario ID")
    if len(ids) != len(set(ids)):
        raise CampaignContractError("manifest has duplicate scenario IDs")
    ids_contract = document.get("expected_scenario_ids")
    if not isinstance(ids_contract, Mapping):
        raise CampaignContractError("manifest has no scenario-ID contract")
    digest = hashlib.sha256(
        ("\n".join(sorted(ids)) + "\n").encode()  # type: ignore[arg-type]
    ).hexdigest()
    if ids_contract.get("count") != len(ids) or ids_contract.get(
        "sorted_newline_sha256"
    ) != digest:
        raise CampaignContractError("scenario-ID enumeration digest mismatch")
    if production:
        if len(raw_units) != EXPECTED_UNITS or len(raw_trials) != 36_800:
            raise CampaignContractError(
                f"production manifest must contain 200 units/36,800 trials, got "
                f"{len(raw_units)}/{len(raw_trials)}"
            )
        holders = [unit.get("holder_asn") for unit in raw_units]
        roots = [unit.get("root_prefix") for unit in raw_units]
        if len(set(holders)) != EXPECTED_UNITS or len(set(roots)) != EXPECTED_UNITS:
            raise CampaignContractError("production sample repeats a holder or root")
        strata = Counter(unit.get("holder_stratum") for unit in raw_units)
        if strata != Counter({name: 50 for name, _, _, _ in HOLDER_STRATA}):
            raise CampaignContractError(f"production stratum allocation drift: {strata}")


def _atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def write_manifest(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists():
        existing = load_manifest(path, production=True)
        if existing["manifest_sha256"] == document["manifest_sha256"]:
            return
        raise CampaignContractError(
            f"refusing to overwrite different manifest {path}; use a new output dir"
        )
    _atomic_write_json(path, document)


def load_manifest(path: Path, *, production: bool = True) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise CampaignContractError("manifest root must be a JSON object")
    validate_manifest(document, production=production)
    return document


def verify_artifact_hashes(manifest: Mapping[str, Any]) -> None:
    expected = manifest.get("artifact_hashes_sha256")
    actual = campaign_artifact_hashes()
    if expected != actual:
        raise CampaignContractError(
            "current inputs/code differ from manifest artifact hashes"
        )


def _unit_pair(unit: SampledUnit, attacker_class: str | None) -> PairSpec:
    effective_class = "uniform" if attacker_class is None else attacker_class
    attacker_asn, attacker_degree = unit.attacker(effective_class)
    stratum_index = [name for name, _, _, _ in HOLDER_STRATA].index(
        unit.holder_stratum
    ) + 1
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
        attacker_asn=attacker_asn,
        attacker_class=effective_class,
        attacker_degree=attacker_degree,
    )


def _empty_partition(keys: Sequence[str]) -> dict[str, int]:
    return {key: 0 for key in keys}


def analyze_grouped_outcomes(
    engine: SimulationEngine,
    pair: PairSpec,
    rov_asns: frozenset[int],
) -> tuple[dict[str, Any], dict[str, bool]]:
    """Compute complete all/ROV/non-ROV partitions in one AS traversal."""

    groups = {
        name: {
            "child": _empty_partition(CHILD_OUTCOMES),
            "destination": _empty_partition(DESTINATION_OUTCOMES),
        }
        for name in ("all", "rov", "non_rov")
    }
    denominators = {"all": len(engine.as_graph), "rov": 0, "non_rov": 0}
    for as_obj in engine.as_graph:
        subgroup = "rov" if as_obj.asn in rov_asns else "non_rov"
        denominators[subgroup] += 1
        ann = as_obj.policy.local_rib.get(pair.leaf_prefix)
        if ann is None:
            child_outcome = "absent"
        elif ann.origin == pair.delegate_asn:
            child_outcome = "delegate"
        elif ann.origin == pair.attacker_asn:
            child_outcome = "attacker"
        else:
            raise RuntimeError(
                f"unexpected child origin AS{ann.origin} at AS{as_obj.asn}"
            )
        destination_outcome = _trace_destination(engine, as_obj.asn, pair)
        for group in ("all", subgroup):
            groups[group]["child"][child_outcome] += 1
            groups[group]["destination"][destination_outcome] += 1

    if denominators["rov"] != len(rov_asns):
        raise RuntimeError("ROV subgroup denominator differs from fixed ROV set")
    output: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    for group, partitions in groups.items():
        denominator = denominators[group]
        output[group] = {"denominator_asns": denominator}
        for partition, counts in partitions.items():
            complete = sum(counts.values()) == denominator
            checks[f"{group}_{partition}_complete"] = complete
            if not complete:
                raise RuntimeError(f"{group}/{partition} partition is incomplete")
            output[group][partition] = {
                "counts": counts,
                "fractions": {
                    key: value / denominator for key, value in counts.items()
                },
            }
    for partition, outcomes in (
        ("child", CHILD_OUTCOMES),
        ("destination", DESTINATION_OUTCOMES),
    ):
        for outcome in outcomes:
            all_count = output["all"][partition]["counts"][outcome]
            subgroup_count = (
                output["rov"][partition]["counts"][outcome]
                + output["non_rov"][partition]["counts"][outcome]
            )
            if all_count != subgroup_count:
                raise RuntimeError(
                    f"{partition}/{outcome}: all != ROV + non-ROV"
                )
    checks["all_equals_rov_plus_non_rov"] = True
    return output, checks


def _resolve_da_asns(
    trial: CampaignTrial,
    rov_asns: frozenset[int],
    orders: Mapping[str, DeploymentOrder],
) -> frozenset[int]:
    if trial.policy_reference != "open_staged":
        return frozenset()
    percent = trial.deployment_percent_target
    if percent == 0:
        return frozenset()
    if percent == 100:
        return rov_asns
    if trial.order_id is None or trial.order_id not in orders:
        raise CampaignContractError(f"trial {trial.scenario_id} has no deployment order")
    count = deployment_count(percent, len(rov_asns))
    return frozenset(orders[trial.order_id].asns[:count])


def _asn_set_hash(asns: Iterable[int]) -> str:
    return hashlib.sha256(
        ("\n".join(str(asn) for asn in sorted(asns)) + "\n").encode()
    ).hexdigest()


@dataclass(frozen=True)
class ResultValidationContext:
    manifest_sha256: str
    trial_by_id: dict[str, Mapping[str, Any]]
    unit_by_id: dict[str, Mapping[str, Any]]
    order_by_id: dict[str, Mapping[str, Any]]
    fixed_rov_asns: frozenset[int]
    topology_asns: int


def _result_validation_context(
    manifest: Mapping[str, Any],
) -> ResultValidationContext:
    trials = manifest.get("trial_plan")
    units = manifest.get("selected_units")
    raw_orders = manifest.get("deployment_orders")
    topology = manifest.get("topology")
    if (
        not isinstance(trials, list)
        or not isinstance(units, list)
        or not isinstance(raw_orders, list)
        or not isinstance(topology, Mapping)
    ):
        raise CampaignContractError("manifest lacks result-validation metadata")
    trial_by_id = {str(item["scenario_id"]): item for item in trials}
    unit_by_id = {str(item["unit_id"]): item for item in units}
    order_by_id = {str(item["order_id"]): item for item in raw_orders}
    if len(trial_by_id) != len(trials) or len(unit_by_id) != len(units):
        raise CampaignContractError("manifest trial/unit identifiers are not unique")
    if len(order_by_id) != len(raw_orders):
        raise CampaignContractError("manifest deployment-order identifiers repeat")
    fixed_rov = frozenset(int(asn) for asn in topology["fixed_rov_asns"])
    if len(fixed_rov) != int(topology["fixed_rov_count"]):
        raise CampaignContractError("manifest fixed ROV set is not unique")
    for order_id, order in order_by_id.items():
        asns = tuple(int(asn) for asn in order["asns"])
        if len(asns) != len(fixed_rov) or frozenset(asns) != fixed_rov:
            raise CampaignContractError(
                f"deployment order {order_id} is not the fixed ROV permutation"
            )
        if order.get("order_sha256") != _order_hash(asns):
            raise CampaignContractError(
                f"deployment order {order_id} SHA256 mismatch"
            )
    return ResultValidationContext(
        manifest_sha256=str(manifest["manifest_sha256"]),
        trial_by_id=trial_by_id,
        unit_by_id=unit_by_id,
        order_by_id=order_by_id,
        fixed_rov_asns=fixed_rov,
        topology_asns=int(topology["asns"]),
    )


def _require_exact_row_value(
    row: Mapping[str, Any], scenario_id: str, field: str, expected: Any
) -> None:
    if field not in row or row[field] != expected:
        raise CampaignContractError(
            f"checkpoint {scenario_id}: {field}={row.get(field)!r}, "
            f"expected {expected!r}"
        )


def validate_success_result_row(
    row: Mapping[str, Any], context: ResultValidationContext
) -> None:
    """Revalidate a completed row against the complete immutable plan."""

    if row.get("status") != "success":
        raise CampaignContractError("checkpoint row is not successful")
    scenario_id = row.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in context.trial_by_id:
        raise CampaignContractError(
            f"checkpoint contains unknown scenario ID {scenario_id!r}"
        )
    if row.get("manifest_sha256") != context.manifest_sha256:
        raise CampaignContractError(
            f"checkpoint manifest mismatch for {scenario_id}"
        )
    _require_exact_row_value(row, scenario_id, "schema_version", SCHEMA_VERSION)
    trial = context.trial_by_id[scenario_id]
    unit_id = str(trial["unit_id"])
    unit = context.unit_by_id.get(unit_id)
    if unit is None:
        raise CampaignContractError(
            f"checkpoint {scenario_id}: unknown selected unit {unit_id}"
        )
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
        _require_exact_row_value(row, scenario_id, field, trial[field])
    _require_exact_row_value(
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
        _require_exact_row_value(row, scenario_id, field, unit[field])

    attacker_class = trial["attacker_class"]
    if attacker_class is None:
        expected_attacker = expected_attacker_degree = None
    else:
        expected_attacker = unit[f"{attacker_class}_attacker_asn"]
        expected_attacker_degree = unit[f"{attacker_class}_attacker_degree"]
    _require_exact_row_value(
        row, scenario_id, "attacker_asn", expected_attacker
    )
    _require_exact_row_value(
        row, scenario_id, "attacker_degree", expected_attacker_degree
    )

    percent = int(trial["deployment_percent_target"])
    if trial["policy_reference"] != "open_staged" or percent == 0:
        expected_da = frozenset()
    elif percent == 100:
        expected_da = context.fixed_rov_asns
    else:
        order_id = trial["order_id"]
        order = context.order_by_id.get(str(order_id))
        if order is None:
            raise CampaignContractError(
                f"checkpoint {scenario_id}: unknown deployment order {order_id}"
            )
        count = deployment_count(percent, len(context.fixed_rov_asns))
        expected_da = frozenset(int(asn) for asn in order["asns"][:count])
    expected_count = len(expected_da)
    _require_exact_row_value(
        row, scenario_id, "deployment_count", expected_count
    )
    actual_fraction = row.get("deployment_fraction_actual")
    expected_fraction = expected_count / len(context.fixed_rov_asns)
    if isinstance(actual_fraction, bool) or not isinstance(
        actual_fraction, (int, float)
    ) or not math.isclose(
        float(actual_fraction), expected_fraction, rel_tol=0, abs_tol=1e-15
    ):
        raise CampaignContractError(
            f"checkpoint {scenario_id}: deployment fraction mismatch"
        )
    order_id = trial["order_id"]
    expected_order_hash = (
        None
        if order_id is None
        else context.order_by_id[str(order_id)]["order_sha256"]
    )
    _require_exact_row_value(
        row, scenario_id, "order_sha256", expected_order_hash
    )
    _require_exact_row_value(
        row, scenario_id, "deployment_set_sha256", _asn_set_hash(expected_da)
    )
    _require_exact_row_value(
        row, scenario_id, "fixed_rov_count", len(context.fixed_rov_asns)
    )

    assignments = row.get("policy_assignment_counts")
    expected_assignments = {
        "bgp": context.topology_asns - len(context.fixed_rov_asns),
        "rov": len(context.fixed_rov_asns) - expected_count,
        "darov": expected_count,
    }
    if assignments != expected_assignments:
        raise CampaignContractError(
            f"checkpoint {scenario_id}: policy assignments {assignments!r}, "
            f"expected {expected_assignments!r}"
        )

    attempt = row.get("attempt")
    prior_failures = row.get("prior_failure_count")
    retry_authorized = row.get("retry_authorized")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 1
        or prior_failures != attempt - 1
        or retry_authorized is not (attempt > 1)
    ):
        raise CampaignContractError(
            f"checkpoint {scenario_id}: invalid attempt/retry provenance"
        )

    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping) or set(outcomes) != {
        "all",
        "rov",
        "non_rov",
    }:
        raise CampaignContractError(
            f"checkpoint {scenario_id}: invalid population outcomes"
        )
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
            raise CampaignContractError(
                f"checkpoint {scenario_id}/{population}: denominator mismatch"
            )
        for partition, expected_keys in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            values = section.get(partition)
            if not isinstance(values, Mapping):
                raise CampaignContractError(
                    f"checkpoint {scenario_id}/{population}: missing {partition}"
                )
            counts = values.get("counts")
            fractions = values.get("fractions")
            if not isinstance(counts, Mapping) or set(counts) != set(expected_keys):
                raise CampaignContractError(
                    f"checkpoint {scenario_id}/{population}/{partition}: bad counts"
                )
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counts.values()
            ) or sum(counts.values()) != denominator:
                raise CampaignContractError(
                    f"checkpoint {scenario_id}/{population}/{partition}: "
                    "incomplete partition"
                )
            if not isinstance(fractions, Mapping) or set(fractions) != set(counts):
                raise CampaignContractError(
                    f"checkpoint {scenario_id}/{population}/{partition}: bad fractions"
                )
            for outcome, count in counts.items():
                fraction = fractions[outcome]
                if isinstance(fraction, bool) or not isinstance(
                    fraction, (int, float)
                ) or not math.isclose(
                    float(fraction), count / denominator, rel_tol=0, abs_tol=1e-15
                ):
                    raise CampaignContractError(
                        f"checkpoint {scenario_id}/{population}/{partition}/"
                        f"{outcome}: fraction mismatch"
                    )
    for partition, expected_keys in (
        ("child", CHILD_OUTCOMES),
        ("destination", DESTINATION_OUTCOMES),
    ):
        for outcome in expected_keys:
            all_count = outcomes["all"][partition]["counts"][outcome]
            subgroup_count = (
                outcomes["rov"][partition]["counts"][outcome]
                + outcomes["non_rov"][partition]["counts"][outcome]
            )
            if all_count != subgroup_count:
                raise CampaignContractError(
                    f"checkpoint {scenario_id}/{partition}/{outcome}: "
                    "all != ROV + non-ROV"
                )
    checks = row.get("partition_checks")
    expected_check_keys = {
        f"{population}_{partition}_complete"
        for population in ("all", "rov", "non_rov")
        for partition in ("child", "destination")
    } | {"all_equals_rov_plus_non_rov"}
    if not isinstance(checks, Mapping) or set(checks) != expected_check_keys or not all(
        value is True for value in checks.values()
    ):
        raise CampaignContractError(
            f"checkpoint {scenario_id}: partition checks missing or failed"
        )


def _outcome_partition_fingerprint(row: Mapping[str, Any]) -> tuple[Any, ...]:
    outcomes = row["outcomes"]
    return tuple(
        (
            population,
            outcomes[population]["denominator_asns"],
            tuple(
                (
                    partition,
                    tuple(
                        (outcome, outcomes[population][partition]["counts"][outcome])
                        for outcome in expected_keys
                    ),
                )
                for partition, expected_keys in (
                    ("child", CHILD_OUTCOMES),
                    ("destination", DESTINATION_OUTCOMES),
                )
            ),
        )
        for population in ("all", "rov", "non_rov")
    )


def _zero_equivalence_key_role(
    row: Mapping[str, Any],
) -> tuple[tuple[str, str, str | None], str] | None:
    lane = row["lane"]
    if lane == B1_DELEGATE:
        return (str(row["unit_id"]), "delegate_only", None), "baseline"
    if lane == D1_OPEN_DELEGATE and row["deployment_percent_target"] == 0:
        return (str(row["unit_id"]), "delegate_only", None), "staged_zero"
    if lane == B1_COMPETITION:
        return (
            str(row["unit_id"]),
            "competition",
            str(row["attacker_class"]),
        ), "baseline"
    if lane == A1_OPEN_COMPETITION and row["deployment_percent_target"] == 0:
        return (
            str(row["unit_id"]),
            "competition",
            str(row["attacker_class"]),
        ), "staged_zero"
    return None


def record_incremental_zero_equivalence(
    row: Mapping[str, Any],
    state: dict[tuple[str, str, str | None], dict[str, Mapping[str, Any]]],
) -> None:
    key_role = _zero_equivalence_key_role(row)
    if key_role is None:
        return
    key, role = key_role
    cell = state.setdefault(key, {})
    if role in cell:
        raise CampaignContractError(
            f"duplicate zero-equivalence {role} for {key}"
        )
    counterpart = "staged_zero" if role == "baseline" else "baseline"
    matched = cell.get(counterpart)
    if matched is not None and _outcome_partition_fingerprint(
        row
    ) != _outcome_partition_fingerprint(matched):
        raise ZeroEquivalenceError(
            str(row["scenario_id"]), str(matched["scenario_id"])
        )
    cell[role] = row


def run_paper_trial(
    engine: SimulationEngine,
    trial: CampaignTrial,
    unit: SampledUnit,
    *,
    rov_asns: frozenset[int],
    orders: Mapping[str, DeploymentOrder],
    manifest_digest: str,
    worker_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    pair = _unit_pair(unit, trial.attacker_class)
    da_asns = _resolve_da_asns(trial, rov_asns, orders)
    DAROV.configure(make_open_policy(pair))
    spec = PaperExecutionSpec(
        pair=pair,
        lane=trial.lane,
        deployment_percent=trial.deployment_percent_target,
        deployment_strategy=trial.deployment_strategy,
        scenario_id=trial.scenario_id,
    )
    started = perf_counter()
    rss_before = current_rss_bytes()
    with PeakRSSMonitor() as memory, trial_alarm(SINGLE_TRIAL_LIMIT_SECONDS):
        scenario = build_scenario(
            spec,
            rov_asns=rov_asns,
            da_asns=da_asns,
            engine=engine,
        )
        engine.setup(scenario)
        assignment_counts = verify_policy_assignment(engine, rov_asns, da_asns)
        engine.run(propagation_round=0, scenario=scenario)
        outcomes, partition_checks = analyze_grouped_outcomes(
            engine, pair, rov_asns
        )
    elapsed = perf_counter() - started
    if elapsed > SINGLE_TRIAL_LIMIT_SECONDS:
        raise RuntimeError(
            f"{trial.scenario_id} exceeded {SINGLE_TRIAL_LIMIT_SECONDS}s"
        )
    if memory.peak_bytes > PER_WORKER_RSS_LIMIT_BYTES:
        raise RuntimeError(
            f"{trial.scenario_id} exceeded {PER_WORKER_RSS_LIMIT_BYTES} bytes RSS"
        )
    attacker_asn = None
    attacker_degree = None
    if trial.attacker_class is not None:
        attacker_asn, attacker_degree = unit.attacker(trial.attacker_class)
    order_sha256 = None
    if trial.order_id is not None:
        order_sha256 = orders[trial.order_id].order_sha256
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
        "deployment_set_sha256": _asn_set_hash(da_asns),
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
        "rss_after_bytes": current_rss_bytes(),
        "peak_rss_bytes": memory.peak_bytes,
        **worker_metadata,
    }


@dataclass
class WorkerContext:
    engine: SimulationEngine
    units: dict[str, SampledUnit]
    orders: dict[str, DeploymentOrder]
    rov_asns: frozenset[int]
    manifest_sha256: str
    graph_build_seconds: float
    graph_build_peak_rss_bytes: int
    sequence: int = 0


_WORKER_CONTEXT: WorkerContext | None = None


def _worker_initializer(manifest_path: str) -> None:
    """Build one unpicklable graph/engine in each spawned worker."""

    global _WORKER_CONTEXT
    manifest = load_manifest(Path(manifest_path), production=True)
    verify_runtime_environment(manifest)
    unit_fields = set(SampledUnit.__dataclass_fields__)
    units = {
        raw["unit_id"]: SampledUnit(
            **{key: value for key, value in raw.items() if key in unit_fields}
        )
        for raw in manifest["selected_units"]
    }
    orders = {
        raw["order_id"]: DeploymentOrder(
            order_id=raw["order_id"],
            strategy=raw["strategy"],
            seed=raw["seed"],
            asns=tuple(raw["asns"]),
            order_sha256=raw["order_sha256"],
        )
        for raw in manifest["deployment_orders"]
    }
    started = perf_counter()
    with PeakRSSMonitor() as memory:
        graph = build_fixed_graph()
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
        raise RuntimeError("worker context was not initialized")
    attempt = raw_trial.get("_attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise RuntimeError("worker task has no valid attempt number")
    trial = CampaignTrial(
        **{
            **{key: value for key, value in raw_trial.items() if key != "_attempt"},
            "shared_for_order_ids": tuple(raw_trial.get("shared_for_order_ids", ())),
        }
    )
    context.sequence += 1
    try:
        if context.graph_build_peak_rss_bytes > PER_WORKER_RSS_LIMIT_BYTES:
            raise RuntimeError(
                "worker graph build exceeded per-worker RSS contract"
            )
        return run_paper_trial(
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
    zero_state: (
        dict[tuple[str, str, str | None], dict[str, Mapping[str, Any]]] | None
    ) = None,
) -> tuple[frozenset[str], dict[str, Any] | None]:
    """Validate an append-only checkpoint and return completed scenario IDs."""

    if not path.exists():
        return frozenset(), None
    context = _result_validation_context(manifest)
    equivalence_state = {} if zero_state is None else zero_state
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
                raise CampaignContractError(
                    f"invalid JSONL at byte {offset}: {exc}; pass "
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
            raise CampaignContractError(f"non-object row at byte {offset}")
        validate_success_result_row(row, context)
        scenario_id = row.get("scenario_id")
        assert isinstance(scenario_id, str)
        if scenario_id in completed:
            raise CampaignContractError(
                f"checkpoint contains duplicate scenario ID {scenario_id}"
            )
        record_incremental_zero_equivalence(row, equivalence_state)
        completed.add(scenario_id)
        offset += len(line)
    return frozenset(completed), repair


def scan_failures_jsonl(
    path: Path, manifest: Mapping[str, Any]
) -> dict[str, tuple[Mapping[str, Any], ...]]:
    """Validate immutable failure history and return it by scenario ID."""

    if not path.exists():
        return {}
    expected_ids = {
        str(trial["scenario_id"]) for trial in manifest["trial_plan"]
    }
    manifest_digest = manifest["manifest_sha256"]
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CampaignContractError(
                    f"invalid failure JSONL at line {line_number}"
                ) from exc
            if not isinstance(row, dict) or row.get("status") != "failed":
                raise CampaignContractError(
                    f"failure line {line_number} is not a failed object"
                )
            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or scenario_id not in expected_ids:
                raise CampaignContractError(
                    f"failure line {line_number} has unknown scenario ID"
                )
            if row.get("manifest_sha256") != manifest_digest:
                raise CampaignContractError(
                    f"failure line {line_number} has a manifest mismatch"
                )
            attempt = row.get("attempt")
            if (
                isinstance(attempt, bool)
                or not isinstance(attempt, int)
                or attempt < 1
                or row.get("prior_failure_count") != attempt - 1
                or row.get("retry_authorized") is not (attempt > 1)
            ):
                raise CampaignContractError(
                    f"failure line {line_number} has invalid retry provenance"
                )
            if not isinstance(row.get("exception"), Mapping):
                raise CampaignContractError(
                    f"failure line {line_number} has no exception record"
                )
            grouped[scenario_id].append(row)
    for scenario_id, rows in grouped.items():
        attempts = sorted(int(row["attempt"]) for row in rows)
        if attempts != list(range(1, len(attempts) + 1)):
            raise CampaignContractError(
                f"failure history for {scenario_id} is not sequential: {attempts}"
            )
    return {
        scenario_id: tuple(sorted(rows, key=lambda row: int(row["attempt"])))
        for scenario_id, rows in grouped.items()
    }


def _append_jsonl(path: Path, document: Mapping[str, Any], *, fsync: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_separator = path.exists() and path.stat().st_size > 0
    if needs_separator:
        with path.open("rb") as probe:
            probe.seek(-1, os.SEEK_END)
            needs_separator = probe.read(1) != b"\n"
    with path.open("a", encoding="utf-8") as handle:
        if needs_separator:
            handle.write("\n")
        handle.write(json.dumps(document, sort_keys=True) + "\n")
        handle.flush()
        if fsync:
            os.fsync(handle.fileno())


def _checkpoint_document(
    manifest: Mapping[str, Any],
    completed: set[str],
    *,
    started_at_utc: str,
    last_scenario_id: str | None,
    repair: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "started_at_utc": started_at_utc,
        "updated_at_utc": utc_now(),
        "completed_trials": len(completed),
        "planned_trials": len(manifest["trial_plan"]),
        "remaining_trials": len(manifest["trial_plan"]) - len(completed),
        "last_scenario_id": last_scenario_id,
        "truncated_tail_repair": repair,
        "status": (
            "complete"
            if len(completed) == len(manifest["trial_plan"])
            else "in_progress"
        ),
    }


def campaign_status(
    output_dir: Path,
    *,
    repair_truncated_tail: bool = False,
) -> dict[str, Any]:
    manifest = load_manifest(output_dir / "manifest.json", production=True)
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
        started_at_utc=utc_now(),
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


def _process_rss_bytes(pid: int) -> int:
    path = Path(f"/proc/{pid}/status")
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except FileNotFoundError:
        return 0
    return 0


def _mem_available_bytes() -> int:
    with Path("/proc/meminfo").open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("/proc/meminfo does not report MemAvailable")


class ParentResourceMonitor:
    """Stop the parent if aggregate RSS or host headroom crosses contract."""

    def __init__(self, pid_provider, interval_seconds: float = 0.5) -> None:
        self.pid_provider = pid_provider
        self.interval_seconds = interval_seconds
        self.peak_aggregate_rss_bytes = 0
        self.minimum_mem_available_bytes = _mem_available_bytes()
        self.breach_reason: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _sample(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            pids = {os.getpid(), *self.pid_provider()}
            aggregate = sum(_process_rss_bytes(pid) for pid in pids)
            available = _mem_available_bytes()
            self.peak_aggregate_rss_bytes = max(
                self.peak_aggregate_rss_bytes, aggregate
            )
            self.minimum_mem_available_bytes = min(
                self.minimum_mem_available_bytes, available
            )
            if aggregate > AGGREGATE_RSS_LIMIT_BYTES:
                self.breach_reason = (
                    f"aggregate RSS {aggregate} exceeds "
                    f"{AGGREGATE_RSS_LIMIT_BYTES}"
                )
            elif available < MIN_MEM_AVAILABLE_BYTES:
                self.breach_reason = (
                    f"MemAvailable {available} below {MIN_MEM_AVAILABLE_BYTES}"
                )
            if self.breach_reason is not None:
                os.kill(os.getpid(), signal.SIGUSR1)
                return


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
    """Resume the manifest using spawned workers and one parent JSONL writer."""

    if workers < 1:
        raise CampaignContractError("workers must be positive")
    if fsync_every < 1:
        raise CampaignContractError("fsync-every must be positive")
    if checkpoint_every < 1:
        raise CampaignContractError("checkpoint-every must be positive")
    manifest_path = output_dir / "manifest.json"
    manifest = load_manifest(manifest_path, production=True)
    verify_artifact_hashes(manifest)
    verify_runtime_environment(manifest)
    results_path = output_dir / "raw_scenarios.jsonl"
    failures_path = output_dir / "failures.jsonl"
    zero_state: dict[
        tuple[str, str, str | None], dict[str, Mapping[str, Any]]
    ] = {}
    completed_frozen, repair = scan_results_jsonl(
        results_path,
        manifest,
        repair_truncated_tail=repair_truncated_tail,
        zero_state=zero_state,
    )
    completed = set(completed_frozen)
    failure_history = scan_failures_jsonl(failures_path, manifest)
    unresolved_failures = sorted(set(failure_history).difference(completed))
    if unresolved_failures and not retry_failures:
        raise CampaignContractError(
            f"{len(unresolved_failures)} unresolved failed scenario(s) exist; "
            "inspect failures.jsonl and pass --retry-failures for an explicit "
            f"retry (first: {unresolved_failures[0]})"
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
            raise CampaignContractError("max-new-trials cannot be negative")
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
            "unresolved_failed_scenarios_before_run": len(unresolved_failures),
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
    available_before = _mem_available_bytes()
    if available_before < MIN_MEM_AVAILABLE_BYTES:
        raise ParentResourceStop(
            f"MemAvailable {available_before} below {MIN_MEM_AVAILABLE_BYTES}"
        )

    checkpoint_path = output_dir / "checkpoint.json"
    result_context = _result_validation_context(manifest)
    context = multiprocessing.get_context("spawn")
    last_scenario_id: str | None = None
    started = perf_counter()
    with context.Pool(
        processes=workers,
        initializer=_worker_initializer,
        initargs=(str(manifest_path),),
    ) as pool:
        monitor = ParentResourceMonitor(
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
            failed["peak_aggregate_rss_bytes"] = (
                monitor.peak_aggregate_rss_bytes
            )
            failed["minimum_mem_available_bytes"] = (
                monitor.minimum_mem_available_bytes
            )
            failed["retry_failures_authorized"] = retry_failures
            _atomic_write_json(checkpoint_path, failed)

        def resource_signal_handler(_signum: int, _frame: object) -> None:
            reason = monitor.breach_reason or "parent resource monitor stopped run"
            write_failed_checkpoint(reason)
            raise ParentResourceStop(
                reason
            )

        previous_handler = signal.getsignal(signal.SIGUSR1)
        signal.signal(signal.SIGUSR1, resource_signal_handler)
        monitor.start()
        try:
            for result_index, result in enumerate(
                pool.imap_unordered(_worker_execute, pending, chunksize=1), start=1
            ):
                if result.get("status") != "success":
                    _append_jsonl(failures_path, result, fsync=True)
                    write_failed_checkpoint(
                        f"worker failed {result.get('scenario_id')}"
                    )
                    raise RuntimeError(
                        f"worker failed {result.get('scenario_id')}: "
                        f"{result.get('exception')}"
                    )
                scenario_id = result["scenario_id"]
                if scenario_id in completed:
                    raise CampaignContractError(
                        f"worker returned already-completed {scenario_id}"
                    )
                try:
                    validate_success_result_row(result, result_context)
                    record_incremental_zero_equivalence(result, zero_state)
                except CampaignContractError as exc:
                    expected_attempt = len(failure_history.get(scenario_id, ())) + 1
                    semantic_failure = {
                        "schema_version": SCHEMA_VERSION,
                        "status": "failed",
                        "scenario_id": scenario_id,
                        "manifest_sha256": manifest["manifest_sha256"],
                        "worker_pid": result.get("worker_pid"),
                        "attempt": expected_attempt,
                        "prior_failure_count": expected_attempt - 1,
                        "retry_authorized": expected_attempt > 1,
                        "failed_at_utc": utc_now(),
                        "exception": {
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                    }
                    if isinstance(exc, ZeroEquivalenceError):
                        semantic_failure["compared_scenario_id"] = exc.matched_id
                    _append_jsonl(failures_path, semantic_failure, fsync=True)
                    write_failed_checkpoint(str(exc))
                    raise
                _append_jsonl(
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


def plan_campaign(output_dir: Path) -> dict[str, Any]:
    """Create the manifest only; no propagation trials are launched."""

    raw_results = output_dir / "raw_scenarios.jsonl"
    if raw_results.exists() and raw_results.stat().st_size:
        raise CampaignContractError(
            "refusing to plan over an existing nonempty result checkpoint"
        )
    started = perf_counter()
    with PeakRSSMonitor() as memory:
        graph = build_fixed_graph()
    document = build_manifest_document(graph)
    document["topology"]["planning_graph_build_seconds"] = perf_counter() - started
    document["topology"]["planning_graph_build_peak_rss_bytes"] = memory.peak_bytes
    document["manifest_sha256"] = manifest_sha256(document)
    validate_manifest(document, production=True)
    write_manifest(output_dir / "manifest.json", document)
    return document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="write manifest; run no trials")
    plan.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)

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
        manifest = plan_campaign(args.output_dir)
        print(
            json.dumps(
                {
                    "status": manifest["status"],
                    "manifest": str(args.output_dir / "manifest.json"),
                    "manifest_sha256": manifest["manifest_sha256"],
                    "units": len(manifest["selected_units"]),
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
