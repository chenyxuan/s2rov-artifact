#!/usr/bin/env python3
"""Validate and analyze the routing-model deployment-grid extension.

The extension adds only the missing random-order cells needed for the regular
0, 10, ..., 100 percent V.C grid.  It does not replace or mutate the frozen
Routing-model campaign.  This analyzer validates the 14,000 extension scenarios,
selects the frozen 0/10/50/100 cells, and joins the two sources.

The sampled holder/root-origin unit remains the independent unit.  The five
fixed random deployment orders are retained first as order-level values and
then averaged within unit.  They are never treated as five independent units.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from experiments.routing_model.campaign import analyze_paper_campaign as base


CONTRACT_VERSION = "routing_model-deployment-grid-extension-analysis-v1"
SCHEMA_VERSION = 1
EXPECTED_UNITS = 200
EXPECTED_EXTENSION_ROWS = 14_000
DEFAULT_BOOTSTRAP_REPLICATES = 10_000
DEFAULT_BOOTSTRAP_SEED = 20260804
STRATUM_BOOTSTRAP_ORDER = ("S1", "S2", "S3", "S4")

EXTENSION_PERCENTAGES = (20, 30, 40, 60, 70, 80, 90)
FROZEN_PERCENTAGES = (0, 10, 50, 100)
FULL_PERCENTAGES = tuple(range(0, 101, 10))
RANDOM_ORDERS = tuple(f"random_{seed:02d}" for seed in range(1, 6))

D1 = base.D1_OPEN_DELEGATE
A1 = base.A1_OPEN_COMPETITION
B1_DELEGATE = base.B1_DELEGATE
B1_COMPETITION = base.B1_COMPETITION

EXPECTED_FROZEN_MANIFEST_SELF_SHA256 = (
    "1394b5aab7020cd0ae7a8cc9d8866ecc86eb06d1bb49e5e2ec85127bb1c3f277"
)
EXPECTED_FROZEN_MANIFEST_FILE_SHA256 = (
    "a674b87afd90716521f19673c4ddbd1153c1b911ec5021a99e0eabe579bcbeae"
)
EXPECTED_FROZEN_RESULTS_SHA256 = (
    "fb9ec8fa80d41b5a98b4bc956d82ebfec0514eaab27fd183f86683dfed6925b7"
)
EXPECTED_FROZEN_CELL_SUMMARY_SHA256 = (
    "4de8618bd35fe21a4731033cab8a51d766eeb1d03d7aed5cc782fcef6ae86969"
)
EXPECTED_FROZEN_COMPETITION_CELLS_SHA256 = (
    "176547af20b4b661ddbbdf647fc62233602838eaa086ed20237854f7007a170d"
)


class GridExtensionAnalysisError(ValueError):
    """Raised when the extension or the frozen join violates its contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GridExtensionAnalysisError(f"{path}: expected a JSON object")
    return value


def load_jsonl(paths: Sequence[Path]) -> list[dict[str, Any]]:
    try:
        return base.load_jsonl(paths)
    except base.CampaignAnalysisError as exc:
        raise GridExtensionAnalysisError(str(exc)) from exc


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _expected_ids_digest(ids: Iterable[str]) -> str:
    return hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest()


def _order_id(item: Mapping[str, Any]) -> str:
    explicit = item.get("order_id", item.get("deployment_order"))
    if explicit not in (None, ""):
        return str(explicit)
    strategy = str(item.get("deployment_strategy", ""))
    seed = item.get("deployment_seed")
    if strategy != "random" or isinstance(seed, bool) or not isinstance(seed, int):
        raise GridExtensionAnalysisError(
            f"{item.get('scenario_id', '<row>')}: cannot resolve random order"
        )
    return f"random_{seed:02d}"


def _attacker_class(item: Mapping[str, Any]) -> str | None:
    value = item.get("attacker_class")
    return None if value in (None, "", "none", "na", "not_applicable") else str(value)


def _unit_id(item: Mapping[str, Any]) -> str:
    value = item.get("unit_id")
    if not isinstance(value, str) or not value:
        raise GridExtensionAnalysisError("row has no nonempty unit_id")
    return value


def _scenario_id(
    unit_id: str, lane: str, attacker_class: str | None, order: str, percent: int
) -> str:
    seed = int(order.removeprefix("random_"))
    attacker = "none" if attacker_class is None else attacker_class
    return (
        f"{unit_id}__{lane}__atk-{attacker}__random__seed-{seed:02d}"
        f"__pct-{percent:03d}"
    )


def _source_expected_units(source: Mapping[str, Any]) -> int:
    for key in ("expected_units", "selected_units", "expected_selected_units"):
        value = source.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    raise GridExtensionAnalysisError(
        "extension source_campaign has no integer expected_units contract"
    )


def validate_frozen_binding(
    extension_manifest: Mapping[str, Any],
    frozen_manifest: Mapping[str, Any],
    *,
    frozen_manifest_path: Path,
    frozen_results_path: Path,
    expected_manifest_self_sha256: str = EXPECTED_FROZEN_MANIFEST_SELF_SHA256,
    expected_manifest_file_sha256: str = EXPECTED_FROZEN_MANIFEST_FILE_SHA256,
    expected_results_sha256: str = EXPECTED_FROZEN_RESULTS_SHA256,
) -> dict[str, str]:
    """Bind the join to the accepted frozen manifest and raw result bytes."""

    observed = {
        "frozen_manifest_file_sha256": sha256_file(frozen_manifest_path),
        "frozen_results_sha256": sha256_file(frozen_results_path),
    }
    frozen_self = frozen_manifest.get("manifest_sha256")
    if frozen_self != base.canonical_manifest_sha256(frozen_manifest):
        raise GridExtensionAnalysisError("frozen manifest self-SHA256 mismatch")
    if frozen_self != expected_manifest_self_sha256:
        raise GridExtensionAnalysisError("unexpected frozen manifest identity")
    if observed["frozen_manifest_file_sha256"] != expected_manifest_file_sha256:
        raise GridExtensionAnalysisError("frozen manifest file SHA256 mismatch")
    if observed["frozen_results_sha256"] != expected_results_sha256:
        raise GridExtensionAnalysisError("frozen raw-results SHA256 mismatch")

    source = extension_manifest.get("source_campaign")
    if not isinstance(source, Mapping):
        raise GridExtensionAnalysisError("extension manifest has no source_campaign")
    if source.get("manifest_sha256") != frozen_self:
        raise GridExtensionAnalysisError(
            "extension source_campaign manifest identity differs from frozen source"
        )
    if source.get("file_sha256") != observed["frozen_manifest_file_sha256"]:
        raise GridExtensionAnalysisError(
            "extension source_campaign file SHA256 differs from frozen source"
        )
    if _source_expected_units(source) != EXPECTED_UNITS:
        raise GridExtensionAnalysisError("extension source_campaign unit count is not 200")
    return observed


def _units_by_id(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    units = manifest.get("selected_units")
    if not isinstance(units, list) or any(not isinstance(item, Mapping) for item in units):
        raise GridExtensionAnalysisError("manifest selected_units must be a list of objects")
    result: dict[str, Mapping[str, Any]] = {}
    for item in units:
        unit_id = str(item.get("unit_id", ""))
        if not unit_id or unit_id in result:
            raise GridExtensionAnalysisError("selected unit IDs are missing or duplicated")
        result[unit_id] = item
    return result


def validate_extension_manifest(
    extension_manifest: Mapping[str, Any], frozen_manifest: Mapping[str, Any]
) -> tuple[tuple[str, ...], dict[str, Mapping[str, Any]]]:
    """Validate the immutable extension plan before reading result values."""

    if extension_manifest.get("schema_version") != SCHEMA_VERSION:
        raise GridExtensionAnalysisError("unsupported extension manifest schema")
    if extension_manifest.get("manifest_sha256") != base.canonical_manifest_sha256(
        extension_manifest
    ):
        raise GridExtensionAnalysisError("extension manifest self-SHA256 mismatch")

    design = extension_manifest.get("design")
    if not isinstance(design, Mapping) or tuple(
        int(value) for value in design.get("deployment_percentages", [])
    ) != EXTENSION_PERCENTAGES:
        raise GridExtensionAnalysisError("extension percentages are not the frozen seven")

    extension_units = _units_by_id(extension_manifest)
    frozen_units = _units_by_id(frozen_manifest)
    if len(extension_units) != EXPECTED_UNITS or set(extension_units) != set(frozen_units):
        raise GridExtensionAnalysisError("extension selected-unit IDs differ from frozen source")
    for unit_id in extension_units:
        if _canonical_json(extension_units[unit_id]) != _canonical_json(frozen_units[unit_id]):
            raise GridExtensionAnalysisError(
                f"extension selected unit {unit_id} differs from frozen source"
            )

    frozen_orders = {
        str(item["order_id"]): item
        for item in frozen_manifest.get("deployment_orders", [])
        if str(item.get("order_id", "")).startswith("random_")
    }
    extension_orders = extension_manifest.get("deployment_orders")
    if not isinstance(extension_orders, list):
        raise GridExtensionAnalysisError("extension has no deployment_orders list")
    extension_by_order = {str(item.get("order_id")): item for item in extension_orders}
    if set(extension_by_order) != set(RANDOM_ORDERS) or set(frozen_orders) != set(
        RANDOM_ORDERS
    ):
        raise GridExtensionAnalysisError("extension must use the five frozen random orders")
    for order in RANDOM_ORDERS:
        extension_item = extension_by_order[order]
        frozen_item = frozen_orders[order]
        for field in ("strategy", "seed", "asns", "order_sha256"):
            if extension_item.get(field) != frozen_item.get(field):
                raise GridExtensionAnalysisError(
                    f"extension order {order} field {field} differs from frozen source"
                )
        counts = extension_item.get("deployment_counts")
        if not isinstance(counts, Mapping):
            raise GridExtensionAnalysisError(f"extension order {order} has no counts")
        rov_count = len(extension_item["asns"])
        for percent in EXTENSION_PERCENTAGES:
            expected = int(rov_count * percent / 100)
            if int(counts.get(str(percent), -1)) != expected:
                raise GridExtensionAnalysisError(
                    f"extension order {order}/{percent}% has an invalid floor count"
                )

    plan = extension_manifest.get("trial_plan")
    if not isinstance(plan, list) or len(plan) != EXPECTED_EXTENSION_ROWS:
        raise GridExtensionAnalysisError(
            f"extension trial_plan must contain {EXPECTED_EXTENSION_ROWS:,} rows"
        )
    expected_ids: list[str] = []
    observed_cells: set[tuple[str, str, str | None, str, int]] = set()
    for item in plan:
        if not isinstance(item, Mapping):
            raise GridExtensionAnalysisError("extension trial plan has a non-object row")
        unit_id = _unit_id(item)
        lane = str(item.get("lane", ""))
        attacker = _attacker_class(item)
        percent = int(item.get("deployment_percent_target", -1))
        order = _order_id(item)
        if lane == D1 and attacker is None:
            pass
        elif lane == A1 and attacker == "uniform":
            pass
        else:
            raise GridExtensionAnalysisError(
                f"{item.get('scenario_id')}: extension lane/attacker is out of scope"
            )
        if unit_id not in extension_units or percent not in EXTENSION_PERCENTAGES:
            raise GridExtensionAnalysisError(
                f"{item.get('scenario_id')}: invalid extension unit or percentage"
            )
        if order not in RANDOM_ORDERS:
            raise GridExtensionAnalysisError(
                f"{item.get('scenario_id')}: invalid extension random order"
            )
        expected_id = _scenario_id(unit_id, lane, attacker, order, percent)
        if item.get("scenario_id") != expected_id:
            raise GridExtensionAnalysisError(
                f"{item.get('scenario_id')}: scenario ID is not canonical"
            )
        cell = (unit_id, lane, attacker, order, percent)
        if cell in observed_cells:
            raise GridExtensionAnalysisError(f"duplicate extension cell {cell!r}")
        observed_cells.add(cell)
        expected_ids.append(expected_id)

    expected_cells = {
        (unit_id, lane, attacker, order, percent)
        for unit_id in extension_units
        for lane, attacker in ((D1, None), (A1, "uniform"))
        for order in RANDOM_ORDERS
        for percent in EXTENSION_PERCENTAGES
    }
    if observed_cells != expected_cells:
        raise GridExtensionAnalysisError("extension trial plan is not the exact 14,000-cell grid")

    ids_contract = extension_manifest.get("expected_scenario_ids")
    if not isinstance(ids_contract, Mapping):
        raise GridExtensionAnalysisError("extension has no expected_scenario_ids contract")
    if int(ids_contract.get("count", -1)) != EXPECTED_EXTENSION_ROWS or ids_contract.get(
        "sorted_newline_sha256"
    ) != _expected_ids_digest(expected_ids):
        raise GridExtensionAnalysisError("extension scenario-ID digest contract mismatch")
    if len(set(expected_ids)) != EXPECTED_EXTENSION_ROWS:
        raise GridExtensionAnalysisError("extension scenario IDs are not unique")
    return tuple(expected_ids), extension_units


def validate_extension_rows(
    rows: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
    expected_ids: Sequence[str],
) -> None:
    """Fail closed on IDs, plan metadata, partitions, and deployment hashes."""

    if len(rows) != EXPECTED_EXTENSION_ROWS:
        raise GridExtensionAnalysisError(
            f"extension raw data has {len(rows):,} rows, expected 14,000"
        )
    design = base.AnalysisDesign(
        percentages=EXTENSION_PERCENTAGES,
        orders=RANDOM_ORDERS,
        attacker_classes=("uniform",),
        populations=base.POPULATIONS,
    )
    try:
        base.validate_expected_scenario_ids(rows, expected_ids)
        base.validate_rows_against_trial_plan(rows, extension_manifest)
        base.validate_execution_contract(rows, extension_manifest, design=design)
        base.validate_partitions(rows, populations=base.POPULATIONS)
    except base.CampaignAnalysisError as exc:
        raise GridExtensionAnalysisError(str(exc)) from exc

    cells = Counter(
        (
            _unit_id(row),
            str(row.get("lane", "")),
            _attacker_class(row),
            _order_id(row),
            int(row.get("deployment_percent_target", -1)),
        )
        for row in rows
    )
    if any(count != 1 for count in cells.values()) or len(cells) != EXPECTED_EXTENSION_ROWS:
        raise GridExtensionAnalysisError("extension raw rows are not one per planned cell")


def _selected_frozen_rows(
    rows: Sequence[Mapping[str, Any]], unit_ids: set[str]
) -> tuple[
    dict[tuple[str, str, str | None], Mapping[str, Any]],
    dict[tuple[str, str, str | None, int, str], Mapping[str, Any]],
]:
    """Select only baselines and 0/10/50/100 random-curve rows."""

    baselines: dict[tuple[str, str, str | None], Mapping[str, Any]] = {}
    treatments: dict[tuple[str, str, str | None, int, str], Mapping[str, Any]] = {}
    for row in rows:
        unit_id = _unit_id(row)
        if unit_id not in unit_ids:
            continue
        lane = str(row.get("lane", ""))
        attacker = _attacker_class(row)
        percent = int(row.get("deployment_percent_target", -1))
        strategy = str(row.get("deployment_strategy", ""))
        if lane == B1_DELEGATE and attacker is None:
            key = (unit_id, lane, attacker)
            if key in baselines:
                raise GridExtensionAnalysisError(f"duplicate frozen baseline {key!r}")
            baselines[key] = row
        elif lane == B1_COMPETITION and attacker == "uniform":
            key = (unit_id, lane, attacker)
            if key in baselines:
                raise GridExtensionAnalysisError(f"duplicate frozen baseline {key!r}")
            baselines[key] = row
        elif lane in {D1, A1} and (
            (lane == D1 and attacker is None) or (lane == A1 and attacker == "uniform")
        ):
            if percent not in FROZEN_PERCENTAGES:
                continue
            if percent in {0, 100}:
                if strategy != "shared":
                    continue
                order = "shared"
            else:
                if strategy != "random":
                    continue
                order = _order_id(row)
                if order not in RANDOM_ORDERS:
                    continue
            key = (unit_id, lane, attacker, percent, order)
            if key in treatments:
                raise GridExtensionAnalysisError(f"duplicate frozen treatment {key!r}")
            treatments[key] = row

    expected_baselines = {
        (unit_id, B1_DELEGATE, None) for unit_id in unit_ids
    } | {(unit_id, B1_COMPETITION, "uniform") for unit_id in unit_ids}
    expected_treatments = {
        (unit_id, lane, attacker, percent, order)
        for unit_id in unit_ids
        for lane, attacker in ((D1, None), (A1, "uniform"))
        for percent in FROZEN_PERCENTAGES
        for order in (("shared",) if percent in {0, 100} else RANDOM_ORDERS)
    }
    if set(baselines) != expected_baselines:
        raise GridExtensionAnalysisError("frozen aggregate-only baselines are incomplete")
    if set(treatments) != expected_treatments:
        raise GridExtensionAnalysisError("frozen 0/10/50/100 treatment cells are incomplete")
    try:
        base.validate_partitions(
            [*baselines.values(), *treatments.values()], populations=base.POPULATIONS
        )
    except base.CampaignAnalysisError as exc:
        raise GridExtensionAnalysisError(str(exc)) from exc
    return baselines, treatments


def _extension_treatments(
    rows: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, str | None, int, str], Mapping[str, Any]]:
    result: dict[tuple[str, str, str | None, int, str], Mapping[str, Any]] = {}
    for row in rows:
        key = (
            _unit_id(row),
            str(row["lane"]),
            _attacker_class(row),
            int(row["deployment_percent_target"]),
            _order_id(row),
        )
        if key in result:
            raise GridExtensionAnalysisError(f"duplicate extension treatment {key!r}")
        result[key] = row
    return result


def _fraction(row: Mapping[str, Any], outcome: str) -> float:
    try:
        value = float(row["outcomes"]["all"]["destination"]["fractions"][outcome])
    except (KeyError, TypeError, ValueError) as exc:
        raise GridExtensionAnalysisError(
            f"{row.get('scenario_id')}: missing all/destination/{outcome} fraction"
        ) from exc
    if not np.isfinite(value) or not 0 <= value <= 1:
        raise GridExtensionAnalysisError(
            f"{row.get('scenario_id')}: invalid outcome fraction {value}"
        )
    return value


def build_order_level_contrasts(
    frozen_rows: Sequence[Mapping[str, Any]],
    extension_rows: Sequence[Mapping[str, Any]],
    holder_design: Mapping[int, base.HolderDesign],
    unit_to_holder: Mapping[str, int],
) -> list[dict[str, Any]]:
    """Return five complete order trajectories for every unit and estimand."""

    unit_ids = set(unit_to_holder)
    baselines, frozen_treatments = _selected_frozen_rows(frozen_rows, unit_ids)
    extension_treatments = _extension_treatments(extension_rows)
    result: list[dict[str, Any]] = []
    for unit_id in sorted(unit_ids):
        holder = unit_to_holder[unit_id]
        design = holder_design[holder]
        for lane, attacker, baseline_lane, outcome, estimand, interval_target in (
            (
                D1,
                None,
                B1_DELEGATE,
                "delegate",
                "Delta_R",
                "finite_frozen_eligible_holder_frame",
            ),
            (
                A1,
                "uniform",
                B1_COMPETITION,
                "attacker",
                "Delta_E_rov",
                "selected_unit_stability",
            ),
        ):
            reference = baselines[(unit_id, baseline_lane, attacker)]
            reference_fraction = _fraction(reference, outcome)
            for percent in FULL_PERCENTAGES:
                for order in RANDOM_ORDERS:
                    if percent in {0, 100}:
                        treatment = frozen_treatments[
                            (unit_id, lane, attacker, percent, "shared")
                        ]
                        source_order = "shared"
                        endpoint_reused = True
                        source_campaign = "frozen"
                    elif percent in {10, 50}:
                        treatment = frozen_treatments[
                            (unit_id, lane, attacker, percent, order)
                        ]
                        source_order = order
                        endpoint_reused = False
                        source_campaign = "frozen"
                    else:
                        treatment = extension_treatments[
                            (unit_id, lane, attacker, percent, order)
                        ]
                        source_order = order
                        endpoint_reused = False
                        source_campaign = "extension"
                    treatment_fraction = _fraction(treatment, outcome)
                    result.append(
                        {
                            "unit_id": unit_id,
                            "holder_asn": holder,
                            "stratum": design.stratum,
                            "design_weight": design.design_weight,
                            "lane": lane,
                            "attacker_class": attacker,
                            "estimand": estimand,
                            "metric_level": "destination",
                            "population": "all",
                            "outcome": outcome,
                            "deployment_percent_target": percent,
                            "deployment_count": (
                                int(treatment["deployment_count"])
                            ),
                            "deployment_order": order,
                            "source_deployment_order": source_order,
                            "shared_endpoint_reused_for_trajectory": endpoint_reused,
                            "source_campaign": source_campaign,
                            "treatment_scenario_id": str(treatment["scenario_id"]),
                            "reference_scenario_id": str(reference["scenario_id"]),
                            "treatment_fraction": treatment_fraction,
                            "reference_fraction": reference_fraction,
                            "delta": treatment_fraction - reference_fraction,
                            "interval_target": interval_target,
                        }
                    )
    expected = len(unit_ids) * 2 * len(FULL_PERCENTAGES) * len(RANDOM_ORDERS)
    if len(result) != expected:
        raise GridExtensionAnalysisError(
            f"built {len(result)} order-level contrasts, expected {expected}"
        )
    return result


def average_orders_within_unit(
    order_level: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Average the five fixed orders only after retaining their unit values."""

    key_fields = (
        "unit_id",
        "holder_asn",
        "stratum",
        "design_weight",
        "lane",
        "attacker_class",
        "estimand",
        "metric_level",
        "population",
        "outcome",
        "deployment_percent_target",
        "deployment_count",
        "interval_target",
    )
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in order_level:
        grouped[tuple(row[field] for field in key_fields)].append(row)
    result: list[dict[str, Any]] = []
    for key, rows in sorted(grouped.items(), key=lambda item: tuple(map(str, item[0]))):
        orders = {str(row["deployment_order"]) for row in rows}
        if len(rows) != len(RANDOM_ORDERS) or orders != set(RANDOM_ORDERS):
            raise GridExtensionAnalysisError(
                f"unit cell {key!r} does not contain exactly five orders"
            )
        base_row = dict(zip(key_fields, key, strict=True))
        result.append(
            {
                **base_row,
                "independent_unit": "holder/root-origin unit",
                "random_orders_averaged_within_unit": len(RANDOM_ORDERS),
                "n_random_orders_as_independent_units": 0,
                "treatment_fraction": float(
                    np.mean([float(row["treatment_fraction"]) for row in rows])
                ),
                "reference_fraction": float(
                    np.mean([float(row["reference_fraction"]) for row in rows])
                ),
                "delta": float(np.mean([float(row["delta"]) for row in rows])),
                "order_delta_min_within_unit": min(float(row["delta"]) for row in rows),
                "order_delta_max_within_unit": max(float(row["delta"]) for row in rows),
            }
        )
    return result


def _ordinary_stratified_bootstrap_weights(
    holders: Sequence[int],
    holder_design: Mapping[int, base.HolderDesign],
    *,
    replicates: int,
    seed: int,
) -> np.ndarray:
    """reanalysis selected-unit stability weights, with no finite correction."""

    if replicates <= 0:
        raise GridExtensionAnalysisError("bootstrap replicates must be positive")
    rng = np.random.default_rng(seed)
    matrix = np.zeros((replicates, len(holders)), dtype=float)
    positions = {holder: index for index, holder in enumerate(holders)}
    observed_strata = {holder_design[holder].stratum for holder in holders}
    if observed_strata != set(STRATUM_BOOTSTRAP_ORDER):
        raise GridExtensionAnalysisError(
            f"ordinary bootstrap strata {sorted(observed_strata)} differ from "
            f"the frozen order {list(STRATUM_BOOTSTRAP_ORDER)}"
        )
    # This explicit sequence is part of the reanalysis numerical contract.  RNG
    # draws are assigned in this order, so replacing it with set iteration can
    # change interval endpoints even when all point estimates are unchanged.
    for stratum in STRATUM_BOOTSTRAP_ORDER:
        members = [holder for holder in holders if holder_design[holder].stratum == stratum]
        if len(members) < 2:
            raise GridExtensionAnalysisError(
                f"ordinary bootstrap stratum {stratum} needs at least two units"
            )
        counts = rng.multinomial(
            len(members), np.full(len(members), 1 / len(members)), size=replicates
        )
        weights = {holder_design[holder].design_weight for holder in members}
        if len(weights) != 1:
            raise GridExtensionAnalysisError(
                f"ordinary bootstrap stratum {stratum} has inconsistent weights"
            )
        matrix[:, [positions[holder] for holder in members]] = counts * weights.pop()
    return matrix


def summarize_curves(
    unit_contrasts: Sequence[Mapping[str, Any]],
    order_level: Sequence[Mapping[str, Any]],
    holder_design: Mapping[int, base.HolderDesign],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compute the two 11-point curves and five descriptive trajectories."""

    holders = sorted(holder_design)
    position = {holder: index for index, holder in enumerate(holders)}
    finite_weights = base._bootstrap_weight_matrix(
        holders,
        holder_design,
        replicates=bootstrap_replicates,
        seed=bootstrap_seed,
    )
    selected_weights = _ordinary_stratified_bootstrap_weights(
        holders,
        holder_design,
        replicates=bootstrap_replicates,
        seed=bootstrap_seed,
    )

    order_groups: dict[tuple[str, int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in order_level:
        order_groups[
            (
                str(row["estimand"]),
                int(row["deployment_percent_target"]),
                str(row["deployment_order"]),
            )
        ].append(row)

    order_trajectories: list[dict[str, Any]] = []
    for key, rows in sorted(order_groups.items()):
        if len(rows) != len(holders):
            raise GridExtensionAnalysisError(f"order trajectory {key!r} is not unit-complete")
        values = {int(row["holder_asn"]): row for row in rows}
        if set(values) != set(holders):
            raise GridExtensionAnalysisError(f"order trajectory {key!r} changes unit set")
        fixed = np.asarray([holder_design[h].design_weight for h in holders])
        delta = np.asarray([float(values[h]["delta"]) for h in holders])
        treatment = np.asarray([float(values[h]["treatment_fraction"]) for h in holders])
        reference = np.asarray([float(values[h]["reference_fraction"]) for h in holders])
        deployment_counts = {int(row["deployment_count"]) for row in rows}
        if len(deployment_counts) != 1:
            raise GridExtensionAnalysisError(f"order trajectory {key!r} changes deployment count")
        order_trajectories.append(
            {
                "estimand": key[0],
                "deployment_percent_target": key[1],
                "deployment_count": deployment_counts.pop(),
                "deployment_order": key[2],
                "independent_unit": "holder/root-origin unit",
                "n_units": len(holders),
                "n_random_orders_as_independent_units": 0,
                "treatment_design_weighted_mean": float(np.average(treatment, weights=fixed)),
                "reference_design_weighted_mean": float(np.average(reference, weights=fixed)),
                "paired_delta_design_weighted_mean": float(np.average(delta, weights=fixed)),
                "paired_delta_pp": float(np.average(delta, weights=fixed) * 100),
            }
        )

    trajectory_index = {
        (
            str(row["estimand"]),
            int(row["deployment_percent_target"]),
            str(row["deployment_order"]),
        ): row
        for row in order_trajectories
    }
    unit_groups: dict[tuple[str, int], list[Mapping[str, Any]]] = defaultdict(list)
    for row in unit_contrasts:
        unit_groups[(str(row["estimand"]), int(row["deployment_percent_target"]))].append(
            row
        )

    summary: list[dict[str, Any]] = []
    for (estimand, percent), rows in sorted(unit_groups.items()):
        if len(rows) != len(holders):
            raise GridExtensionAnalysisError(
                f"summary cell {(estimand, percent)!r} is not unit-complete"
            )
        by_holder = {int(row["holder_asn"]): row for row in rows}
        if set(by_holder) != set(holders):
            raise GridExtensionAnalysisError(
                f"summary cell {(estimand, percent)!r} changes unit set"
            )
        delta = np.asarray([float(by_holder[h]["delta"]) for h in holders])
        treatment = np.asarray(
            [float(by_holder[h]["treatment_fraction"]) for h in holders]
        )
        reference = np.asarray(
            [float(by_holder[h]["reference_fraction"]) for h in holders]
        )
        fixed = np.asarray([holder_design[h].design_weight for h in holders])
        if estimand == "Delta_R":
            replicate_weights = finite_weights
            interval_type = (
                "pointwise_stratified_paired_rescaled_percentile_srswor_fpc"
            )
            inference_target = "finite frozen eligible-holder frame"
            finite_population_correction = True
        elif estimand == "Delta_E_rov":
            replicate_weights = selected_weights
            interval_type = (
                "ordinary_stratified_paired_percentile_selected_unit_stability"
            )
            inference_target = "selected units; descriptive stability interval"
            finite_population_correction = False
        else:
            raise GridExtensionAnalysisError(f"unknown curve estimand {estimand}")
        replicate_means = (replicate_weights @ delta) / replicate_weights.sum(axis=1)
        lower, upper = np.percentile(
            replicate_means, (2.5, 97.5), method="linear"
        ).tolist()
        order_values = {
            order: float(
                trajectory_index[(estimand, percent, order)][
                    "paired_delta_design_weighted_mean"
                ]
            )
            for order in RANDOM_ORDERS
        }
        deployment_counts = {int(row["deployment_count"]) for row in rows}
        if len(deployment_counts) != 1:
            raise GridExtensionAnalysisError(
                f"summary cell {(estimand, percent)!r} changes deployment count"
            )
        point = float(np.average(delta, weights=fixed))
        summary.append(
            {
                "estimand": estimand,
                "metric_level": "destination",
                "population": "all",
                "attacker_class": None if estimand == "Delta_R" else "uniform",
                "deployment_strategy": "random_five_order_average",
                "deployment_percent_target": percent,
                "deployment_count": deployment_counts.pop(),
                "independent_unit": "holder/root-origin unit",
                "n_units": len(holders),
                "random_orders_averaged_within_unit": len(RANDOM_ORDERS),
                "n_random_orders_as_independent_units": 0,
                "treatment_design_weighted_mean": float(
                    np.average(treatment, weights=fixed)
                ),
                "reference_design_weighted_mean": float(
                    np.average(reference, weights=fixed)
                ),
                "paired_delta_design_weighted_mean": point,
                "paired_delta_pp": point * 100,
                "pointwise_interval95_lower": float(lower),
                "pointwise_interval95_upper": float(upper),
                "pointwise_interval95_lower_pp": float(lower * 100),
                "pointwise_interval95_upper_pp": float(upper * 100),
                "interval_type": interval_type,
                "inference_target": inference_target,
                "finite_population_correction": finite_population_correction,
                "random_order_design_weighted_deltas": order_values,
                "random_order_delta_min": min(order_values.values()),
                "random_order_delta_max": max(order_values.values()),
                "random_order_delta_range": max(order_values.values())
                - min(order_values.values()),
                "random_order_delta_min_pp": min(order_values.values()) * 100,
                "random_order_delta_max_pp": max(order_values.values()) * 100,
                "bootstrap_replicates": bootstrap_replicates,
                "bootstrap_seed": bootstrap_seed,
            }
        )

    if len(summary) != 22 or len(order_trajectories) != 110:
        raise GridExtensionAnalysisError(
            f"unexpected output shape: {len(summary)} cells, "
            f"{len(order_trajectories)} order points"
        )
    return summary, order_trajectories


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def validate_and_anchor_frozen_intersections(
    summary: Sequence[dict[str, Any]],
    *,
    frozen_cell_summary_path: Path,
    frozen_competition_cells_path: Path,
    tolerance: float = 1e-12,
) -> dict[str, Any]:
    """Reproduce and then retain the accepted 0/10/50/100 numerical values.

    Raw-to-summary recomputation is required to agree within floating-point
    tolerance.  The accepted decimal values are then copied into the merged
    table, making the four intersections numerically identical to the frozen
    Routing-model D1 and reanalysis A1 tables rather than merely close by a few ulps.
    """

    observed_hashes = {
        "frozen_routing_model_cell_summary_sha256": sha256_file(
            frozen_cell_summary_path
        ),
        "frozen_reanalysis_competition_cells_sha256": sha256_file(
            frozen_competition_cells_path
        ),
    }
    if (
        observed_hashes["frozen_routing_model_cell_summary_sha256"]
        != EXPECTED_FROZEN_CELL_SUMMARY_SHA256
    ):
        raise GridExtensionAnalysisError("frozen routing-model cell-summary hash mismatch")
    if (
        observed_hashes["frozen_reanalysis_competition_cells_sha256"]
        != EXPECTED_FROZEN_COMPETITION_CELLS_SHA256
    ):
        raise GridExtensionAnalysisError(
            "frozen reanalysis competition-cells hash mismatch"
        )

    routing_model_matches = [
        row
        for row in _read_csv(frozen_cell_summary_path)
        if row.get("estimand") == "Delta_R"
        and row.get("metric_level") == "destination"
        and row.get("population") == "all"
        and row.get("attacker_class", "") == ""
        and row.get("deployment_strategy") == "random"
        and int(row.get("deployment_percent_target", -1)) in FROZEN_PERCENTAGES
    ]
    reanalysis_matches = [
        row
        for row in _read_csv(frozen_competition_cells_path)
        if row.get("estimand") == "Delta_E_rov"
        and row.get("metric_level") == "destination"
        and row.get("population") == "all"
        and row.get("attacker_class") == "uniform"
        and row.get("deployment_strategy") == "random"
        and int(row.get("deployment_percent_target", -1)) in FROZEN_PERCENTAGES
    ]
    if len(routing_model_matches) != 4 or len(reanalysis_matches) != 4:
        raise GridExtensionAnalysisError(
            "frozen intersection tables do not each contain four expected rows"
        )
    accepted: dict[tuple[str, int], dict[str, float]] = {}
    for row in routing_model_matches:
        accepted[("Delta_R", int(row["deployment_percent_target"]))] = {
            "point": float(row["paired_delta_design_weighted_mean"]),
            "treatment": float(row["raw_treatment_design_weighted_mean"]),
            "reference": float(row["raw_reference_design_weighted_mean"]),
            "lower": float(row["pointwise_ci95_lower"]),
            "upper": float(row["pointwise_ci95_upper"]),
        }
    for row in reanalysis_matches:
        accepted[("Delta_E_rov", int(row["deployment_percent_target"]))] = {
            "point": float(row["stratum_standardized_selected_unit_mean"]),
            "treatment": float(row["raw_treatment_stratum_standardized_mean"]),
            "reference": float(row["raw_reference_stratum_standardized_mean"]),
            "lower": float(row["resampling_interval95_lower"]),
            "upper": float(row["resampling_interval95_upper"]),
        }

    by_key = {
        (str(row["estimand"]), int(row["deployment_percent_target"])): row
        for row in summary
    }
    field_pairs = {
        "point": "paired_delta_design_weighted_mean",
        "treatment": "treatment_design_weighted_mean",
        "reference": "reference_design_weighted_mean",
        "lower": "pointwise_interval95_lower",
        "upper": "pointwise_interval95_upper",
    }
    pre_anchor_errors: dict[str, float] = {}
    for key, expected in accepted.items():
        actual = by_key.get(key)
        if actual is None:
            raise GridExtensionAnalysisError(f"merged summary lacks frozen cell {key!r}")
        for label, output_field in field_pairs.items():
            error = abs(float(actual[output_field]) - expected[label])
            pre_anchor_errors[f"{key[0]}@{key[1]}:{label}"] = error
            if error > tolerance:
                raise GridExtensionAnalysisError(
                    f"frozen intersection {key!r}/{label} differs by {error}"
                )
        actual["paired_delta_design_weighted_mean"] = expected["point"]
        actual["paired_delta_pp"] = expected["point"] * 100
        actual["treatment_design_weighted_mean"] = expected["treatment"]
        actual["reference_design_weighted_mean"] = expected["reference"]
        actual["pointwise_interval95_lower"] = expected["lower"]
        actual["pointwise_interval95_upper"] = expected["upper"]
        actual["pointwise_interval95_lower_pp"] = expected["lower"] * 100
        actual["pointwise_interval95_upper_pp"] = expected["upper"] * 100
        actual["frozen_intersection_anchored"] = True

    exact_after_anchor = all(
        float(by_key[key][output_field]) == values[label]
        for key, values in accepted.items()
        for label, output_field in field_pairs.items()
    )
    if not exact_after_anchor:
        raise GridExtensionAnalysisError(
            "frozen intersection values are not exactly equal after anchoring"
        )
    return {
        **observed_hashes,
        "stratum_bootstrap_order": list(STRATUM_BOOTSTRAP_ORDER),
        "frozen_intersection_cells": len(accepted),
        "maximum_pre_anchor_absolute_error": max(pre_anchor_errors.values()),
        "tolerance": tolerance,
        "point_and_interval_values_exact_after_anchor": True,
    }


def analyze_grid_extension(
    extension_rows: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
    frozen_rows: Sequence[Mapping[str, Any]],
    frozen_manifest: Mapping[str, Any],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Analyze already hash-bound inputs after the fail-closed validations."""

    expected_ids, extension_units = validate_extension_manifest(
        extension_manifest, frozen_manifest
    )
    validate_extension_rows(extension_rows, extension_manifest, expected_ids)
    try:
        holder_design = base.load_holder_design(frozen_manifest)
    except base.CampaignAnalysisError as exc:
        raise GridExtensionAnalysisError(str(exc)) from exc
    unit_to_holder = {
        unit_id: int(item["holder_asn"]) for unit_id, item in extension_units.items()
    }
    if set(unit_to_holder.values()) != set(holder_design):
        raise GridExtensionAnalysisError("extension unit-to-holder mapping differs from source")
    order_level = build_order_level_contrasts(
        frozen_rows, extension_rows, holder_design, unit_to_holder
    )
    unit_contrasts = average_orders_within_unit(order_level)
    if len(unit_contrasts) != EXPECTED_UNITS * 2 * len(FULL_PERCENTAGES):
        raise GridExtensionAnalysisError("unit-average output is not the 4,400-row grid")
    summary, order_trajectories = summarize_curves(
        unit_contrasts,
        order_level,
        holder_design,
        bootstrap_replicates=bootstrap_replicates,
        bootstrap_seed=bootstrap_seed,
    )
    return order_level, unit_contrasts, summary, order_trajectories


def _csv_safe(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
        for key, value in row.items()
    }


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        raise GridExtensionAnalysisError(f"refusing to write empty {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(_csv_safe(row) for row in rows)


def write_outputs(
    output_dir: Path,
    order_level: Sequence[Mapping[str, Any]],
    unit_contrasts: Sequence[Mapping[str, Any]],
    summary: Sequence[Mapping[str, Any]],
    order_trajectories: Sequence[Mapping[str, Any]],
    validation: Mapping[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "order_level_unit_contrasts": output_dir / "order_level_unit_contrasts.jsonl",
        "unit_contrasts": output_dir / "unit_contrasts.jsonl",
        "cell_summary_json": output_dir / "cell_summary.json",
        "cell_summary_csv": output_dir / "cell_summary.csv",
        "order_trajectories_json": output_dir / "order_trajectories.json",
        "order_trajectories_csv": output_dir / "order_trajectories.csv",
    }
    _write_jsonl(paths["order_level_unit_contrasts"], order_level)
    _write_jsonl(paths["unit_contrasts"], unit_contrasts)
    paths["cell_summary_json"].write_text(
        json.dumps(list(summary), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_csv(paths["cell_summary_csv"], summary)
    paths["order_trajectories_json"].write_text(
        json.dumps(list(order_trajectories), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_csv(paths["order_trajectories_csv"], order_trajectories)
    output_hashes = {key: sha256_file(path) for key, path in paths.items()}
    document = {**dict(validation), "outputs_sha256": output_hashes}
    (output_dir / "analysis_manifest.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension-manifest", type=Path, required=True)
    parser.add_argument("--extension-results", type=Path, nargs="+", required=True)
    parser.add_argument("--frozen-manifest", type=Path, required=True)
    parser.add_argument("--frozen-results", type=Path, required=True)
    parser.add_argument("--frozen-cell-summary", type=Path, required=True)
    parser.add_argument("--frozen-competition-cells", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--bootstrap-replicates", type=int, default=DEFAULT_BOOTSTRAP_REPLICATES
    )
    parser.add_argument("--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    extension_manifest = load_json(args.extension_manifest)
    frozen_manifest = load_json(args.frozen_manifest)
    frozen_hashes = validate_frozen_binding(
        extension_manifest,
        frozen_manifest,
        frozen_manifest_path=args.frozen_manifest,
        frozen_results_path=args.frozen_results,
    )
    extension_rows = load_jsonl(args.extension_results)
    frozen_rows = load_jsonl([args.frozen_results])
    order_level, unit_contrasts, summary, order_trajectories = analyze_grid_extension(
        extension_rows,
        extension_manifest,
        frozen_rows,
        frozen_manifest,
        bootstrap_replicates=args.bootstrap_replicates,
        bootstrap_seed=args.bootstrap_seed,
    )
    frozen_intersection_audit = validate_and_anchor_frozen_intersections(
        summary,
        frozen_cell_summary_path=args.frozen_cell_summary,
        frozen_competition_cells_path=args.frozen_competition_cells,
    )
    validation = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "status": "VERIFIED",
        "checks": {
            "extension_manifest_self_hash_valid": True,
            "frozen_manifest_and_raw_hashes_valid": True,
            "extension_source_bound_to_frozen_manifest": True,
            "extension_scenario_ids_exact_and_unique": True,
            "extension_14000_cell_grid_complete": True,
            "extension_rows_match_trial_plan": True,
            "deployment_order_prefix_hashes_valid": True,
            "policy_assignment_counts_valid": True,
            "outcome_partitions_complete_and_additive": True,
            "frozen_0_10_50_100_cells_complete": True,
            "frozen_intersection_points_and_intervals_exact": True,
            "full_0_to_100_by_10_grid_complete": True,
            "random_orders_retained_before_unit_average": True,
            "random_orders_not_independent_units": True,
        },
        "counts": {
            "extension_scenarios": len(extension_rows),
            "extension_scenarios_expected": EXPECTED_EXTENSION_ROWS,
            "selected_units": EXPECTED_UNITS,
            "random_orders": len(RANDOM_ORDERS),
            "full_grid_percentages": list(FULL_PERCENTAGES),
            "order_level_unit_contrasts": len(order_level),
            "unit_averaged_contrasts": len(unit_contrasts),
            "summary_cells": len(summary),
            "order_trajectory_points": len(order_trajectories),
            "n_random_orders_as_independent_units": 0,
        },
        "inference": {
            "independent_unit": "holder/root-origin unit",
            "D1_Delta_R_interval": (
                "pointwise stratified paired rescaled percentile interval for "
                "the finite frozen eligible-holder frame, with sampling without replacement FPC"
            ),
            "A1_Delta_E_rov_interval": (
                "descriptive ordinary stratified paired selected-unit stability "
                "interval, without FPC"
            ),
            "random_orders": (
                "five fixed within-unit deployment blocks; retained descriptively "
                "and averaged within unit before interval calculation"
            ),
            "ordinary_bootstrap_stratum_order": list(STRATUM_BOOTSTRAP_ORDER),
        },
        "frozen_intersection_audit": frozen_intersection_audit,
        "inputs": {
            "extension_manifest": {
                "path": str(args.extension_manifest),
                "file_sha256": sha256_file(args.extension_manifest),
                "manifest_sha256": extension_manifest["manifest_sha256"],
            },
            "extension_results": [
                {"path": str(path), "file_sha256": sha256_file(path)}
                for path in sorted(args.extension_results)
            ],
            "frozen_manifest": {
                "path": str(args.frozen_manifest),
                "file_sha256": frozen_hashes["frozen_manifest_file_sha256"],
                "manifest_sha256": frozen_manifest["manifest_sha256"],
            },
            "frozen_results": {
                "path": str(args.frozen_results),
                "file_sha256": frozen_hashes["frozen_results_sha256"],
            },
            "frozen_cell_summary": {
                "path": str(args.frozen_cell_summary),
                "file_sha256": frozen_intersection_audit[
                    "frozen_routing_model_cell_summary_sha256"
                ],
            },
            "frozen_competition_cells": {
                "path": str(args.frozen_competition_cells),
                "file_sha256": frozen_intersection_audit[
                    "frozen_reanalysis_competition_cells_sha256"
                ],
            },
            "analyzer": {
                "path": str(Path(__file__).resolve()),
                "file_sha256": sha256_file(Path(__file__).resolve()),
            },
        },
        "bootstrap": {
            "replicates": args.bootstrap_replicates,
            "seed": args.bootstrap_seed,
        },
    }
    write_outputs(
        args.output_dir,
        order_level,
        unit_contrasts,
        summary,
        order_trajectories,
        validation,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
