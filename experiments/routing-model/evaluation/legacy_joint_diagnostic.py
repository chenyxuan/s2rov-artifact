#!/usr/bin/env python3
"""Reproduce the post-hoc Phase-7 W2 delivery/exposure diagnostic.

This program reads only the frozen Phase-7 manifest, raw scenario rows, and
their verified analysis manifest.  It does not consume derived cell summaries
when computing the diagnostic.  Delivery and exposure are extracted from the
same all-AS destination partition of each competition run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import tempfile
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "phase7_simulation/results/paper_campaign/manifest.json"
RAW_PATH = ROOT / "phase7_simulation/results/paper_campaign/raw_scenarios.jsonl"
ANALYSIS_MANIFEST_PATH = (
    ROOT
    / "phase7_simulation/results/paper_campaign/analysis/analysis_manifest.json"
)

VERSION = "phase7-legacy-w2-joint-diagnostic-v1"
REPLICATES = 10_000
BOOTSTRAP_SEED = 20260804
PERCENTAGES = (0, 1, 5, 10, 25, 50, 75, 100)
INTERMEDIATE_PERCENTAGES = frozenset(PERCENTAGES[1:-1])
RANDOM_ORDERS = tuple(f"random_{index:02d}" for index in range(1, 6))
EXPECTED_STRATA = {"S1": 50, "S2": 50, "S3": 50, "S4": 50}
EXPECTED_FRAME_SIZES = {"S1": 161, "S2": 177, "S3": 179, "S4": 174}
EXPECTED_DEPLOYMENT_COUNTS = {
    0: 0,
    1: 5,
    5: 29,
    10: 58,
    25: 147,
    50: 294,
    75: 441,
    100: 589,
}
EXPECTED_DENOMINATORS = {"all": 77_429, "rov": 589, "non_rov": 76_840}
CHILD_OUTCOMES = ("delegate", "attacker", "absent")
DESTINATION_OUTCOMES = (
    "delegate",
    "attacker",
    "holder_fallback",
    "disconnected",
    "loop",
)
PLAN_FIELDS = (
    "unit_id",
    "pair_index",
    "lane",
    "announcement_set",
    "attacker_class",
    "deployment_percent_target",
    "deployment_strategy",
    "deployment_seed",
    "order_id",
    "policy_reference",
    "shared_for_order_ids",
)
UNIT_FIELDS = (
    "cluster_id",
    "holder_asn",
    "holder_degree",
    "delegate_asn",
    "delegate_degree",
    "root_prefix",
    "leaf_prefix",
    "source_row",
    "pair_index",
    "holder_stratum",
    "holder_stratum_degree_range",
    "N_h",
    "n_h",
    "stratum_population_N_h",
    "stratum_sample_n_h",
    "design_weight",
)
PINNED_SHA256 = {
    "phase7_simulation/results/paper_campaign/manifest.json": (
        "a674b87afd90716521f19673c4ddbd1153c1b911ec5021a99e0eabe579bcbeae"
    ),
    "phase7_simulation/results/paper_campaign/raw_scenarios.jsonl": (
        "fb9ec8fa80d41b5a98b4bc956d82ebfec0514eaab27fd183f86683dfed6925b7"
    ),
    "phase7_simulation/results/paper_campaign/analysis/analysis_manifest.json": (
        "27298f787bfb8856b23d5c21138526dd9adbb3259a57e64067268eb2fc4c2a73"
    ),
}


class DiagnosticError(ValueError):
    """Raised when a frozen input violates the diagnostic contract."""


def sha256_file(path: Path) -> str:
    """Return a streaming SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_path(path: Path) -> str:
    """Render repository files without host-specific absolute paths."""

    return str(path.resolve().relative_to(ROOT.resolve()))


def load_json(path: Path) -> dict[str, Any]:
    """Load one JSON object with a useful error boundary."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"cannot load JSON object {path}") from exc
    if not isinstance(value, dict):
        raise DiagnosticError(f"{path} is not a JSON object")
    return value


def canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Recompute the runner's canonical self-hash."""

    core = dict(manifest)
    core.pop("manifest_sha256", None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def sorted_newline_sha256(values: Sequence[str]) -> str:
    """Hash sorted identifiers using the frozen newline convention."""

    payload = "".join(f"{value}\n" for value in sorted(values))
    return hashlib.sha256(payload.encode()).hexdigest()


def asn_set_sha256(asns: Sequence[int] | set[int] | frozenset[int]) -> str:
    """Match the runner's canonical unordered-AS-set digest."""

    payload = "\n".join(str(asn) for asn in sorted(asns)) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def require_equal(actual: Any, expected: Any, label: str) -> None:
    """Fail closed on a contract mismatch."""

    if actual != expected:
        raise DiagnosticError(f"{label}: {actual!r} != {expected!r}")


def verify_frozen_hashes(analysis_manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Verify pinned bytes and the hashes recorded by the Phase-7 analysis."""

    paths = (MANIFEST_PATH, RAW_PATH, ANALYSIS_MANIFEST_PATH)
    actual = {relative_path(path): sha256_file(path) for path in paths}
    for path, expected in PINNED_SHA256.items():
        require_equal(actual[path], expected, f"pinned SHA-256 for {path}")

    inputs = analysis_manifest.get("inputs")
    if not isinstance(inputs, Mapping):
        raise DiagnosticError("analysis manifest has no inputs object")
    require_equal(
        inputs.get("manifest"),
        relative_path(MANIFEST_PATH),
        "analysis-manifest input path",
    )
    require_equal(
        inputs.get("manifest_sha256"),
        actual[relative_path(MANIFEST_PATH)],
        "analysis-manifest manifest SHA-256",
    )
    shards = inputs.get("result_shards")
    if not isinstance(shards, list) or len(shards) != 1:
        raise DiagnosticError("analysis manifest must declare exactly one result shard")
    shard = shards[0]
    if not isinstance(shard, Mapping):
        raise DiagnosticError("analysis-manifest result shard is not an object")
    require_equal(shard.get("path"), relative_path(RAW_PATH), "raw shard path")
    require_equal(
        shard.get("sha256"),
        actual[relative_path(RAW_PATH)],
        "analysis-manifest raw SHA-256",
    )
    return {
        path: {
            "bytes": (ROOT / path).stat().st_size,
            "sha256": digest,
        }
        for path, digest in sorted(actual.items())
    }


def load_manifest_contract(
    manifest: Mapping[str, Any],
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
    dict[str, Any],
]:
    """Validate manifest identity, selected units, and the physical trial plan."""

    require_equal(manifest.get("schema_version"), 1, "manifest schema")
    declared_manifest_sha = manifest.get("manifest_sha256")
    require_equal(
        declared_manifest_sha,
        canonical_manifest_sha256(manifest),
        "manifest canonical SHA-256",
    )

    units = manifest.get("selected_units")
    if not isinstance(units, list) or len(units) != 200:
        raise DiagnosticError("manifest must contain exactly 200 selected units")
    units_by_id: dict[str, Mapping[str, Any]] = {}
    holders: set[int] = set()
    strata: Counter[str] = Counter()
    weight_sum = Decimal(0)
    for unit in units:
        if not isinstance(unit, Mapping):
            raise DiagnosticError("selected unit is not an object")
        unit_id = unit.get("unit_id")
        holder = unit.get("holder_asn")
        if not isinstance(unit_id, str) or not unit_id or unit_id in units_by_id:
            raise DiagnosticError(f"invalid or duplicate unit ID {unit_id!r}")
        if isinstance(holder, bool) or not isinstance(holder, int) or holder in holders:
            raise DiagnosticError(f"{unit_id}: invalid or duplicate holder ASN")
        stratum = str(unit.get("holder_stratum"))
        if stratum not in EXPECTED_STRATA:
            raise DiagnosticError(f"{unit_id}: unexpected stratum {stratum!r}")
        frame_size = int(unit["N_h"])
        sample_size = int(unit["n_h"])
        require_equal(frame_size, EXPECTED_FRAME_SIZES[stratum], f"{unit_id}/N_h")
        require_equal(sample_size, EXPECTED_STRATA[stratum], f"{unit_id}/n_h")
        weight = Decimal(str(unit["design_weight"]))
        require_equal(
            weight,
            Decimal(frame_size) / Decimal(sample_size),
            f"{unit_id}/design weight",
        )
        units_by_id[unit_id] = unit
        holders.add(holder)
        strata[stratum] += 1
        weight_sum += weight
    require_equal(dict(strata), EXPECTED_STRATA, "selected-unit stratum counts")
    require_equal(weight_sum, Decimal(691), "selected-unit design-weight sum")

    raw_plan = manifest.get("trial_plan")
    if not isinstance(raw_plan, list) or len(raw_plan) != 36_800:
        raise DiagnosticError("manifest trial plan must contain exactly 36,800 rows")
    plan_by_id: dict[str, Mapping[str, Any]] = {}
    for trial in raw_plan:
        if not isinstance(trial, Mapping):
            raise DiagnosticError("trial-plan row is not an object")
        scenario_id = trial.get("scenario_id")
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or scenario_id in plan_by_id
        ):
            raise DiagnosticError(f"invalid or duplicate scenario ID {scenario_id!r}")
        if trial.get("unit_id") not in units_by_id:
            raise DiagnosticError(f"{scenario_id}: trial has unknown selected unit")
        plan_by_id[scenario_id] = trial

    expected_ids = manifest.get("expected_scenario_ids")
    if not isinstance(expected_ids, Mapping):
        raise DiagnosticError("manifest has no expected-scenario-ID contract")
    scenario_digest = sorted_newline_sha256(tuple(plan_by_id))
    require_equal(expected_ids.get("count"), len(plan_by_id), "scenario-ID count")
    require_equal(
        expected_ids.get("sorted_newline_sha256"),
        scenario_digest,
        "scenario-ID digest",
    )

    topology = manifest.get("topology")
    if not isinstance(topology, Mapping):
        raise DiagnosticError("manifest has no topology object")
    require_equal(topology.get("asns"), EXPECTED_DENOMINATORS["all"], "AS count")
    require_equal(topology.get("fixed_rov_count"), 589, "fixed ROV count")
    fixed_rov_raw = topology.get("fixed_rov_asns")
    if not isinstance(fixed_rov_raw, list):
        raise DiagnosticError("manifest has no fixed-ROV ASN list")
    fixed_rov = tuple(int(asn) for asn in fixed_rov_raw)
    if len(fixed_rov) != 589 or len(set(fixed_rov)) != 589:
        raise DiagnosticError("fixed-ROV ASN list is not a 589-AS set")

    raw_orders = manifest.get("deployment_orders")
    if not isinstance(raw_orders, list):
        raise DiagnosticError("manifest has no deployment-orders list")
    order_ids: list[str] = []
    orders: dict[str, Mapping[str, Any]] = {}
    for order in raw_orders:
        if not isinstance(order, Mapping):
            raise DiagnosticError("deployment order is not an object")
        order_id = str(order.get("order_id"))
        order_ids.append(order_id)
        strategy = "random" if order_id.startswith("random_") else order_id
        seed = int(order_id.removeprefix("random_")) if strategy == "random" else None
        require_equal(order.get("strategy"), strategy, f"{order_id}/strategy")
        require_equal(order.get("seed"), seed, f"{order_id}/seed")
        asns_raw = order.get("asns")
        if not isinstance(asns_raw, list):
            raise DiagnosticError(f"{order_id}: no ordered ASN list")
        asns = tuple(int(asn) for asn in asns_raw)
        if len(asns) != 589 or set(asns) != set(fixed_rov):
            raise DiagnosticError(f"{order_id}: not a fixed-ROV permutation")
        order_digest = hashlib.sha256(
            "\n".join(str(asn) for asn in asns).encode()
        ).hexdigest()
        require_equal(order.get("order_sha256"), order_digest, f"{order_id}/SHA-256")
        counts = order.get("deployment_counts")
        if not isinstance(counts, Mapping):
            raise DiagnosticError(f"{order_id}: no deployment-count contract")
        normalized = {int(key): int(value) for key, value in counts.items()}
        require_equal(
            normalized,
            EXPECTED_DEPLOYMENT_COUNTS,
            f"{order_id}/deployment counts",
        )
        orders[order_id] = order
    require_equal(
        set(order_ids),
        {"degree", "customer_cone", *RANDOM_ORDERS},
        "deployment-order IDs",
    )
    if len(order_ids) != len(set(order_ids)):
        raise DiagnosticError("duplicate deployment-order ID")

    audit = {
        "canonical_manifest_sha256": declared_manifest_sha,
        "design_weight_sum": float(weight_sum),
        "expected_scenario_ids_sorted_newline_sha256": scenario_digest,
        "selected_holders": len(holders),
        "strata": dict(sorted(strata.items())),
        "trial_plan_rows": len(plan_by_id),
    }
    return units_by_id, plan_by_id, orders, audit


def normalized_attacker(value: Any) -> str | None:
    """Normalize the manifest's null attacker spellings."""

    return None if value in (None, "", "none", "na", "not_applicable") else str(value)


def validate_plan_and_unit_binding(
    row: Mapping[str, Any],
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    scenario_id: str,
) -> None:
    """Check immutable trial metadata and selected-unit identity."""

    for field in PLAN_FIELDS:
        actual = row.get(field)
        expected = plan.get(field)
        if field == "attacker_class":
            actual = normalized_attacker(actual)
            expected = normalized_attacker(expected)
        require_equal(actual, expected, f"{scenario_id}/{field}")
    for field in UNIT_FIELDS:
        require_equal(row.get(field), unit.get(field), f"{scenario_id}/{field}")

    attacker_class = normalized_attacker(row.get("attacker_class"))
    if attacker_class is None:
        require_equal(row.get("attacker_asn"), None, f"{scenario_id}/attacker ASN")
    else:
        attackers = unit.get("attackers")
        if not isinstance(attackers, Mapping):
            raise DiagnosticError(f"{scenario_id}: unit has no attacker assignments")
        attacker = attackers.get(attacker_class)
        if not isinstance(attacker, Mapping):
            raise DiagnosticError(
                f"{scenario_id}: unit has no {attacker_class} attacker assignment"
            )
        require_equal(
            row.get("attacker_asn"),
            attacker.get("asn"),
            f"{scenario_id}/attacker ASN",
        )
        require_equal(
            row.get("attacker_degree"),
            attacker.get("degree"),
            f"{scenario_id}/attacker degree",
        )
    require_equal(
        row.get("prior_failure_count"), 0, f"{scenario_id}/prior failure count"
    )
    require_equal(
        row.get("retry_authorized"), False, f"{scenario_id}/retry authorization"
    )


def validate_deployment(
    row: Mapping[str, Any],
    scenario_id: str,
    orders: Mapping[str, Mapping[str, Any]],
    fixed_rov: frozenset[int],
) -> None:
    """Reconstruct staged policy-assignment counts from the floor rule."""

    percent = int(row["deployment_percent_target"])
    if percent not in EXPECTED_DEPLOYMENT_COUNTS:
        raise DiagnosticError(f"{scenario_id}: unexpected deployment fraction")
    staged = row.get("lane") in {"D1_open_delegate_only", "A1_open_competition"}
    expected_count = EXPECTED_DEPLOYMENT_COUNTS[percent] if staged else 0
    require_equal(row.get("deployment_count"), expected_count, f"{scenario_id}/count")
    require_equal(row.get("fixed_rov_count"), 589, f"{scenario_id}/fixed ROV count")
    actual_fraction = float(row.get("deployment_fraction_actual"))
    if not np.isclose(actual_fraction, expected_count / 589, rtol=0, atol=1e-12):
        raise DiagnosticError(f"{scenario_id}: deployment fraction is inconsistent")
    order_id = row.get("order_id")
    if order_id is None:
        require_equal(row.get("order_sha256"), None, f"{scenario_id}/order SHA-256")
    else:
        if str(order_id) not in orders:
            raise DiagnosticError(f"{scenario_id}: unknown deployment order {order_id}")
        require_equal(
            row.get("order_sha256"),
            orders[str(order_id)].get("order_sha256"),
            f"{scenario_id}/order SHA-256",
        )
    if expected_count == 0:
        expected_deployment: Sequence[int] | set[int] | frozenset[int] = ()
    elif percent == 100:
        expected_deployment = fixed_rov
    else:
        if order_id is None:
            raise DiagnosticError(f"{scenario_id}: staged intermediate row has no order")
        order_asns = orders[str(order_id)].get("asns")
        if not isinstance(order_asns, list):
            raise DiagnosticError(f"{scenario_id}: deployment order has no ASNs")
        expected_deployment = tuple(int(asn) for asn in order_asns[:expected_count])
    require_equal(
        row.get("deployment_set_sha256"),
        asn_set_sha256(expected_deployment),
        f"{scenario_id}/deployment-set SHA-256",
    )
    assignments = row.get("policy_assignment_counts")
    if not isinstance(assignments, Mapping):
        raise DiagnosticError(f"{scenario_id}: missing policy assignments")
    require_equal(
        set(assignments), {"bgp", "rov", "s2rov"}, f"{scenario_id}/policy keys"
    )
    require_equal(assignments.get("s2rov"), expected_count, f"{scenario_id}/S2-ROV")
    require_equal(
        assignments.get("rov"), 589 - expected_count, f"{scenario_id}/ROV"
    )
    require_equal(
        sum(int(value) for value in assignments.values()),
        EXPECTED_DENOMINATORS["all"],
        f"{scenario_id}/policy total",
    )


def validate_partition(
    row: Mapping[str, Any], scenario_id: str
) -> dict[str, dict[str, float]]:
    """Recompute every child/destination fraction and subgroup additivity."""

    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping) or set(outcomes) != set(EXPECTED_DENOMINATORS):
        raise DiagnosticError(f"{scenario_id}: malformed outcome populations")
    recomputed: dict[str, dict[str, float]] = {}
    count_partitions: dict[str, dict[str, dict[str, int]]] = {}
    for population, expected_denominator in EXPECTED_DENOMINATORS.items():
        value = outcomes.get(population)
        if not isinstance(value, Mapping):
            raise DiagnosticError(f"{scenario_id}: missing {population} outcomes")
        require_equal(
            value.get("denominator_asns"),
            expected_denominator,
            f"{scenario_id}/{population}/denominator",
        )
        recomputed[population] = {}
        count_partitions[population] = {}
        for level, names in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            partition = value.get(level)
            if not isinstance(partition, Mapping):
                raise DiagnosticError(
                    f"{scenario_id}: missing {population}/{level} partition"
                )
            counts = partition.get("counts")
            stored = partition.get("fractions")
            if not isinstance(counts, Mapping) or set(counts) != set(names):
                raise DiagnosticError(
                    f"{scenario_id}: malformed {population}/{level} counts"
                )
            if not isinstance(stored, Mapping) or set(stored) != set(names):
                raise DiagnosticError(
                    f"{scenario_id}: malformed {population}/{level} fractions"
                )
            normalized_counts: dict[str, int] = {}
            for name in names:
                count = counts[name]
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise DiagnosticError(
                        f"{scenario_id}: invalid {population}/{level}/{name} count"
                    )
                normalized_counts[name] = count
                fraction = count / expected_denominator
                if not np.isclose(
                    float(stored[name]), fraction, rtol=0, atol=1e-12
                ):
                    raise DiagnosticError(
                        f"{scenario_id}: stored {population}/{level}/{name} "
                        "fraction differs from counts"
                    )
                recomputed[population][f"{level}.{name}"] = fraction
            require_equal(
                sum(normalized_counts.values()),
                expected_denominator,
                f"{scenario_id}/{population}/{level} partition sum",
            )
            count_partitions[population][level] = normalized_counts

    for level, names in (
        ("child", CHILD_OUTCOMES),
        ("destination", DESTINATION_OUTCOMES),
    ):
        for name in names:
            require_equal(
                count_partitions["all"][level][name],
                count_partitions["rov"][level][name]
                + count_partitions["non_rov"][level][name],
                f"{scenario_id}/{level}/{name}/subgroup additivity",
            )
    checks = row.get("partition_checks")
    if not isinstance(checks, Mapping) or not checks or not all(checks.values()):
        raise DiagnosticError(f"{scenario_id}: recorded partition check failed")
    return recomputed


def is_selected_diagnostic_row(row: Mapping[str, Any]) -> bool:
    """Select the frozen W2 baseline and random-deployment treatment curve."""

    if normalized_attacker(row.get("attacker_class")) != "uniform":
        return False
    lane = row.get("lane")
    percent = int(row.get("deployment_percent_target", -1))
    strategy = row.get("deployment_strategy")
    if lane == "B1_competition":
        return percent == 0 and strategy == "reference"
    if lane != "A1_open_competition" or percent not in PERCENTAGES:
        return False
    if percent in {0, 100}:
        return strategy == "shared"
    return percent in INTERMEDIATE_PERCENTAGES and strategy == "random"


def read_and_validate_raw(
    manifest: Mapping[str, Any],
    units_by_id: Mapping[str, Mapping[str, Any]],
    plan_by_id: Mapping[str, Mapping[str, Any]],
    orders: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Stream all rows, validate the frozen campaign, and retain 6,600 rows."""

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    status_counts: Counter[str] = Counter()
    attempt_counts: Counter[int] = Counter()
    manifest_sha = manifest["manifest_sha256"]
    fixed_rov = frozenset(int(asn) for asn in manifest["topology"]["fixed_rov_asns"])
    raw_rows = 0
    try:
        handle = RAW_PATH.open(encoding="utf-8")
    except OSError as exc:
        raise DiagnosticError(f"cannot open frozen raw rows {RAW_PATH}") from exc
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            raw_rows += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DiagnosticError(f"raw line {line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise DiagnosticError(f"raw line {line_number}: row is not an object")
            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or scenario_id not in plan_by_id:
                raise DiagnosticError(f"raw line {line_number}: unknown scenario ID")
            if scenario_id in seen:
                raise DiagnosticError(f"duplicate raw scenario {scenario_id}")
            seen.add(scenario_id)
            status_counts[str(row.get("status"))] += 1
            attempt = row.get("attempt")
            if isinstance(attempt, bool) or not isinstance(attempt, int):
                raise DiagnosticError(f"{scenario_id}: invalid attempt number")
            attempt_counts[attempt] += 1
            require_equal(row.get("status"), "success", f"{scenario_id}/status")
            require_equal(attempt, 1, f"{scenario_id}/attempt")
            require_equal(
                row.get("manifest_sha256"), manifest_sha, f"{scenario_id}/manifest SHA"
            )
            plan = plan_by_id[scenario_id]
            unit_id = plan["unit_id"]
            unit = units_by_id[str(unit_id)]
            validate_plan_and_unit_binding(row, plan, unit, scenario_id)
            validate_deployment(row, scenario_id, orders, fixed_rov)
            fractions = validate_partition(row, scenario_id)
            if is_selected_diagnostic_row(row):
                retained = dict(row)
                retained["_recomputed_fractions"] = fractions
                selected.append(retained)

    require_equal(raw_rows, 36_800, "raw row count")
    require_equal(seen, set(plan_by_id), "raw scenario set")
    observed_digest = sorted_newline_sha256(tuple(seen))
    require_equal(
        observed_digest,
        manifest["expected_scenario_ids"]["sorted_newline_sha256"],
        "raw scenario-ID digest",
    )
    require_equal(len(selected), 6_600, "selected diagnostic rows")
    audit = {
        "attempt_counts": {str(key): value for key, value in sorted(attempt_counts.items())},
        "raw_rows": raw_rows,
        "scenario_ids_exact": True,
        "scenario_ids_sorted_newline_sha256": observed_digest,
        "selected_diagnostic_rows": len(selected),
        "status_counts": dict(sorted(status_counts.items())),
    }
    return selected, audit


def destination_vector(row: Mapping[str, Any]) -> np.ndarray:
    """Return the five all-AS destination fractions in declared order."""

    fractions = row["_recomputed_fractions"]["all"]
    return np.asarray(
        [fractions[f"destination.{name}"] for name in DESTINATION_OUTCOMES],
        dtype=np.float64,
    )


def assemble_holder_curve(
    selected: Sequence[Mapping[str, Any]],
    units_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[list[int], np.ndarray, np.ndarray, dict[str, Any]]:
    """Average random orders within holder and construct paired deltas."""

    baseline: dict[str, Mapping[str, Any]] = {}
    treatments: dict[tuple[str, int], list[Mapping[str, Any]]] = defaultdict(list)
    cell_counts: Counter[tuple[str, int, str]] = Counter()
    for row in selected:
        unit_id = str(row["unit_id"])
        lane = str(row["lane"])
        percent = int(row["deployment_percent_target"])
        strategy = str(row["deployment_strategy"])
        cell_counts[(lane, percent, strategy)] += 1
        if lane == "B1_competition":
            if unit_id in baseline:
                raise DiagnosticError(f"duplicate B1 baseline for {unit_id}")
            baseline[unit_id] = row
        else:
            treatments[(unit_id, percent)].append(row)

    expected_units = set(units_by_id)
    require_equal(set(baseline), expected_units, "B1 holder coverage")
    expected_cell_counts = {
        ("B1_competition", 0, "reference"): 200,
        ("A1_open_competition", 0, "shared"): 200,
        ("A1_open_competition", 100, "shared"): 200,
        **{
            ("A1_open_competition", percent, "random"): 1_000
            for percent in PERCENTAGES[1:-1]
        },
    }
    require_equal(dict(cell_counts), expected_cell_counts, "selected physical cells")

    holders = sorted(int(unit["holder_asn"]) for unit in units_by_id.values())
    unit_for_holder = {
        int(unit["holder_asn"]): unit_id for unit_id, unit in units_by_id.items()
    }
    deltas = np.zeros((len(holders), len(PERCENTAGES), len(DESTINATION_OUTCOMES)))
    treatment_values = np.zeros_like(deltas)
    reference_values = np.zeros((len(holders), len(DESTINATION_OUTCOMES)))
    zero_full_outcomes_equal = 0
    random_order_sets: set[tuple[str, ...]] = set()
    max_partition_delta_sum = 0.0
    selected_loop_count = sum(
        int(row["outcomes"]["all"]["destination"]["counts"]["loop"])
        for row in selected
    )
    for holder_index, holder in enumerate(holders):
        unit_id = unit_for_holder[holder]
        reference_row = baseline[unit_id]
        reference = destination_vector(reference_row)
        reference_values[holder_index] = reference
        for fraction_index, percent in enumerate(PERCENTAGES):
            rows = treatments.get((unit_id, percent), [])
            expected_rows = 1 if percent in {0, 100} else len(RANDOM_ORDERS)
            require_equal(len(rows), expected_rows, f"{unit_id}/{percent}% rows")
            if percent in {0, 100}:
                require_equal(rows[0].get("order_id"), None, f"{unit_id}/{percent}% order")
            else:
                orders = tuple(sorted(str(row["order_id"]) for row in rows))
                require_equal(orders, RANDOM_ORDERS, f"{unit_id}/{percent}% orders")
                random_order_sets.add(orders)
            treatment = np.mean(
                np.stack([destination_vector(row) for row in rows]), axis=0
            )
            delta = treatment - reference
            treatment_values[holder_index, fraction_index] = treatment
            deltas[holder_index, fraction_index] = delta
            max_partition_delta_sum = max(
                max_partition_delta_sum, abs(float(np.sum(delta)))
            )
            if percent == 0:
                require_equal(
                    rows[0]["outcomes"],
                    reference_row["outcomes"],
                    f"{unit_id}/0% full outcome equality",
                )
                zero_full_outcomes_equal += 1

    if max_partition_delta_sum > 1e-12:
        raise DiagnosticError(
            "destination-component contrasts do not close to zero: "
            f"{max_partition_delta_sum}"
        )
    require_equal(zero_full_outcomes_equal, 200, "0% full-outcome equalities")
    require_equal(random_order_sets, {RANDOM_ORDERS}, "random-order coverage")
    require_equal(selected_loop_count, 0, "selected destination loop count")
    audit = {
        "cell_counts": {
            f"{lane}|{percent}|{strategy}": count
            for (lane, percent, strategy), count in sorted(cell_counts.items())
        },
        "destination_component_delta_max_abs_sum": max_partition_delta_sum,
        "joint_delivery_exposure_same_partition_row": True,
        "random_orders_per_intermediate_holder_cell": list(RANDOM_ORDERS),
        "selected_all_destination_loop_count": selected_loop_count,
        "zero_percent_full_outcomes_equal_holders": zero_full_outcomes_equal,
    }
    return holders, deltas, treatment_values, {"reference": reference_values, **audit}


def bootstrap_weights(
    holders: Sequence[int],
    units_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Build one common ordinary stratified selected-unit weight matrix."""

    unit_for_holder = {
        int(unit["holder_asn"]): unit for unit in units_by_id.values()
    }
    fixed_weights = np.asarray(
        [float(unit_for_holder[holder]["design_weight"]) for holder in holders]
    )
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    replicate_weights = np.zeros((REPLICATES, len(holders)), dtype=np.float64)
    holder_index = {holder: index for index, holder in enumerate(holders)}
    strata: Counter[str] = Counter()
    for stratum in EXPECTED_STRATA:
        members = [
            holder
            for holder in holders
            if unit_for_holder[holder]["holder_stratum"] == stratum
        ]
        strata[stratum] = len(members)
        require_equal(len(members), EXPECTED_STRATA[stratum], f"{stratum}/holders")
        counts = rng.multinomial(
            len(members), np.full(len(members), 1.0 / len(members)), REPLICATES
        )
        weights = {float(unit_for_holder[holder]["design_weight"]) for holder in members}
        if len(weights) != 1:
            raise DiagnosticError(f"{stratum}: inconsistent design weights")
        design_weight = weights.pop()
        for column, holder in enumerate(members):
            replicate_weights[:, holder_index[holder]] = counts[:, column] * design_weight

    totals = replicate_weights.sum(axis=1)
    if not np.allclose(totals, 691.0, rtol=0, atol=1e-10):
        raise DiagnosticError("bootstrap replicate design-weight totals are not 691")
    audit = {
        "fixed_design_weight_sum": float(fixed_weights.sum()),
        "replicate_design_weight_sum_max": float(np.max(totals)),
        "replicate_design_weight_sum_min": float(np.min(totals)),
        "strata": dict(sorted(strata.items())),
    }
    return fixed_weights, replicate_weights, audit


def summarize_curve(
    holders: Sequence[int],
    deltas: np.ndarray,
    treatment_values: np.ndarray,
    assembly_audit: Mapping[str, Any],
    units_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compute eight weighted points and marginal percentile intervals."""

    fixed_weights, replicate_weights, bootstrap_audit = bootstrap_weights(
        holders, units_by_id
    )
    denominator = float(fixed_weights.sum())
    replicate_denominator = replicate_weights.sum(axis=1)
    reference_values = np.asarray(assembly_audit["reference"], dtype=np.float64)
    delivery_index = DESTINATION_OUTCOMES.index("delegate")
    exposure_index = DESTINATION_OUTCOMES.index("attacker")
    summaries: list[dict[str, Any]] = []
    for fraction_index, percent in enumerate(PERCENTAGES):
        delta_delivery = deltas[:, fraction_index, delivery_index]
        delta_exposure = deltas[:, fraction_index, exposure_index]
        point_delivery = float(np.dot(fixed_weights, delta_delivery) / denominator)
        point_exposure = float(np.dot(fixed_weights, delta_exposure) / denominator)
        bootstrap_delivery = (
            replicate_weights @ delta_delivery
        ) / replicate_denominator
        bootstrap_exposure = (
            replicate_weights @ delta_exposure
        ) / replicate_denominator
        delivery_lower, delivery_upper = np.percentile(
            bootstrap_delivery, (2.5, 97.5), method="linear"
        ).tolist()
        exposure_lower, exposure_upper = np.percentile(
            bootstrap_exposure, (2.5, 97.5), method="linear"
        ).tolist()

        treatment_delivery = float(
            np.dot(
                fixed_weights, treatment_values[:, fraction_index, delivery_index]
            )
            / denominator
        )
        treatment_exposure = float(
            np.dot(
                fixed_weights, treatment_values[:, fraction_index, exposure_index]
            )
            / denominator
        )
        reference_delivery = float(
            np.dot(fixed_weights, reference_values[:, delivery_index]) / denominator
        )
        reference_exposure = float(
            np.dot(fixed_weights, reference_values[:, exposure_index]) / denominator
        )
        summaries.append(
            {
                "bootstrap_interval95_percentage_points": {
                    "delta_delegate_delivery": [
                        float(delivery_lower * 100),
                        float(delivery_upper * 100),
                    ],
                    "delta_attacker_exposure": [
                        float(exposure_lower * 100),
                        float(exposure_upper * 100),
                    ],
                },
                "deployment_count": EXPECTED_DEPLOYMENT_COUNTS[percent],
                "deployment_percent_target": percent,
                "joint_point_estimate_percentage_points": [
                    point_delivery * 100,
                    point_exposure * 100,
                ],
                "joint_point_estimate_proportion": [
                    point_delivery,
                    point_exposure,
                ],
                "reference_stratum_standardized_proportion": {
                    "delegate_delivery": reference_delivery,
                    "attacker_exposure": reference_exposure,
                },
                "selected_units": len(holders),
                "treatment_stratum_standardized_proportion": {
                    "delegate_delivery": treatment_delivery,
                    "attacker_exposure": treatment_exposure,
                },
            }
        )
    return summaries, bootstrap_audit


def build_payload() -> dict[str, Any]:
    """Validate frozen inputs and return the deterministic diagnostic payload."""

    analysis_manifest = load_json(ANALYSIS_MANIFEST_PATH)
    inputs = verify_frozen_hashes(analysis_manifest)
    manifest = load_json(MANIFEST_PATH)
    units_by_id, plan_by_id, orders, manifest_audit = load_manifest_contract(manifest)
    selected, raw_audit = read_and_validate_raw(
        manifest, units_by_id, plan_by_id, orders
    )
    holders, deltas, treatment_values, assembly_audit = assemble_holder_curve(
        selected, units_by_id
    )
    curve, bootstrap_audit = summarize_curve(
        holders, deltas, treatment_values, assembly_audit, units_by_id
    )
    reference_values = assembly_audit["reference"]
    assembly_output = {
        key: value for key, value in assembly_audit.items() if key != "reference"
    }
    return {
        "analysis_program": {
            "path": relative_path(Path(__file__)),
            "sha256": sha256_file(Path(__file__)),
        },
        "bootstrap_contract": {
            "coverage": "marginal pointwise per coordinate and deployment fraction",
            "finite_population_correction": False,
            "interval_type": (
                "ordinary_stratified_paired_percentile_selected_unit_stability"
            ),
            "percentile_method": "numpy_linear",
            "replicates": REPLICATES,
            "seed": BOOTSTRAP_SEED,
            "simultaneous_joint_interval": False,
            "unit": "selected holder_asn",
            "within_stratum_draw": (
                "Multinomial(n_h; 1/n_h, ..., 1/n_h), independently by stratum"
            ),
        },
        "claim_boundary": {
            "description": (
                "Post-hoc legacy diagnostic on the frozen Phase-7 simulation; "
                "not a redesigned E4 production result or real-Internet estimate."
            ),
            "joint_endpoint_meaning": (
                "Delegate delivery and attacker exposure are co-extracted from "
                "the same all-AS destination partition in each competition run."
            ),
            "not_redesigned_e4": True,
            "post_hoc_legacy_diagnostic": True,
        },
        "estimand": {
            "baseline": (
                "B1_competition, uniform attacker, aggregate-only ROV reference"
            ),
            "formula": (
                "J_f=[sum_h w_h*(mean_o L_T,hfo-L_B,h)/sum_h w_h, "
                "sum_h w_h*(mean_o E_T,hfo-E_B,h)/sum_h w_h]"
            ),
            "intermediate_order_reduction": (
                "mean random_01..random_05 within holder before weighting"
            ),
            "joint_vector_order": [
                "delta_delegate_delivery",
                "delta_attacker_exposure",
            ],
            "population": "all ASes in the frozen topology",
            "treatment": (
                "A1_open_competition, uniform attacker, shared endpoints and "
                "random deployment at intermediate fractions"
            ),
        },
        "inputs": inputs,
        "integrity": {
            "assembly": assembly_output,
            "bootstrap": bootstrap_audit,
            "checks": {
                "all_raw_partitions_complete_and_additive": True,
                "all_rows_attempt_1_success": True,
                "all_rows_match_manifest_trial_and_unit_metadata": True,
                "deployment_floor_rule_and_policy_counts_valid": True,
                "deployment_order_hashes_and_prefix_sets_valid": True,
                "frozen_input_hashes_match": True,
                "manifest_self_hash_and_scenario_digest_valid": True,
                "random_orders_averaged_within_holder_first": True,
                "scenario_ids_exact_and_unique": True,
                "selected_joint_cells_complete": True,
                "zero_percent_announcement_matched_full_outcomes_equal": True,
            },
            "manifest": manifest_audit,
            "raw": raw_audit,
        },
        "point_estimates": curve,
        "runtime": {
            "implementation": platform.python_implementation(),
            "numpy": np.__version__,
            "python": platform.python_version(),
        },
        "schema_version": 1,
        "status": "VERIFIED_LEGACY_DIAGNOSTIC",
        "version": VERSION,
        "weighted_reference_proportion": {
            "attacker_exposure": float(
                np.average(
                    reference_values[:, DESTINATION_OUTCOMES.index("attacker")],
                    weights=np.asarray(
                        [
                            float(
                                next(
                                    unit
                                    for unit in units_by_id.values()
                                    if int(unit["holder_asn"]) == holder
                                )["design_weight"]
                            )
                            for holder in holders
                        ]
                    ),
                )
            ),
            "delegate_delivery": float(
                np.average(
                    reference_values[:, DESTINATION_OUTCOMES.index("delegate")],
                    weights=np.asarray(
                        [
                            float(
                                next(
                                    unit
                                    for unit in units_by_id.values()
                                    if int(unit["holder_asn"]) == holder
                                )["design_weight"]
                            )
                            for holder in holders
                        ]
                    ),
                )
            ),
        },
    }


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    """Write only the explicit output path, atomically and deterministically."""

    resolved = path.resolve()
    protected = {
        MANIFEST_PATH.resolve(),
        RAW_PATH.resolve(),
        ANALYSIS_MANIFEST_PATH.resolve(),
        Path(__file__).resolve(),
    }
    if resolved in protected:
        raise DiagnosticError(f"refusing to overwrite protected input {resolved}")
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the single mutable target allowed by this analysis."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="JSON output path; frozen input paths are intentionally not configurable",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed diagnostic and write its JSON result."""

    args = parse_args(argv)
    payload = build_payload()
    write_json_atomic(args.output, payload)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "point_estimates": len(payload["point_estimates"]),
                "status": payload["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
