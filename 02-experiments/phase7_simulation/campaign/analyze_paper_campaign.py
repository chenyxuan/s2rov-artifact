"""Validate and summarize the frozen Phase-7 BGPy paper campaign.

The independent unit is the sampled holder ASN.  In particular, neither the
ASes inside one propagation result nor the five random deployment orders are
replicates.  Random-order outcomes are averaged within holder and deployment
cell before any across-holder statistic or bootstrap is calculated.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


CONTRACT_VERSION = "phase7-paper-campaign-v1"
SCHEMA_VERSION = 1
DEFAULT_BOOTSTRAP_REPLICATES = 10_000
DEFAULT_BOOTSTRAP_SEED = 20260804
EXPECTED_HOLDERS = 200

STRATUM_FRAME_SIZES = {"S1": 161, "S2": 177, "S3": 179, "S4": 174}
STRATUM_SAMPLE_SIZES = {key: 50 for key in STRATUM_FRAME_SIZES}
DEPLOYMENT_PERCENTAGES = (0, 1, 5, 10, 25, 50, 75, 100)
INTERMEDIATE_PERCENTAGES = frozenset(DEPLOYMENT_PERCENTAGES[1:-1])
DEPLOYMENT_ORDERS = (
    "degree",
    "customer_cone",
    "random_01",
    "random_02",
    "random_03",
    "random_04",
    "random_05",
)
RANDOM_ORDERS = tuple(
    order for order in DEPLOYMENT_ORDERS if order.startswith("random_")
)
ATTACKER_CLASSES = ("uniform", "edge", "high_degree")
POPULATIONS = ("all", "rov", "non_rov")

B1_DELEGATE = "B1_delegate_only"
B2_DELEGATE = "B2_exact_delegate_only"
B1_COMPETITION = "B1_competition"
B2_COMPETITION = "B2_exact_competition"
D1_OPEN_DELEGATE = "D1_open_delegate_only"
A1_OPEN_COMPETITION = "A1_open_competition"
KNOWN_LANES = frozenset(
    {
        B1_DELEGATE,
        B2_DELEGATE,
        B1_COMPETITION,
        B2_COMPETITION,
        D1_OPEN_DELEGATE,
        A1_OPEN_COMPETITION,
    }
)

CHILD_OUTCOMES = ("delegate", "attacker", "absent")
DESTINATION_OUTCOMES = (
    "delegate",
    "attacker",
    "holder_fallback",
    "disconnected",
    "loop",
)


class CampaignAnalysisError(ValueError):
    """Raised when campaign artifacts violate the frozen contract."""


@dataclass(frozen=True)
class HolderDesign:
    """Sampling-design metadata for one independent holder unit."""

    holder_asn: int
    stratum: str
    frame_size: int
    sample_size: int
    design_weight: float


@dataclass(frozen=True)
class AnalysisDesign:
    """Analysis dimensions, with production defaults from the frozen contract."""

    percentages: tuple[int, ...] = DEPLOYMENT_PERCENTAGES
    orders: tuple[str, ...] = DEPLOYMENT_ORDERS
    attacker_classes: tuple[str, ...] = ATTACKER_CLASSES
    populations: tuple[str, ...] = POPULATIONS

    @property
    def random_orders(self) -> tuple[str, ...]:
        return tuple(order for order in self.orders if order.startswith("random_"))

    @property
    def intermediate_percentages(self) -> frozenset[int]:
        return frozenset(self.percentages[1:-1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Recompute the runner's self-hash over canonical JSON."""

    core = dict(manifest)
    core.pop("manifest_sha256", None)
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _asn_set_sha256(asns: Iterable[int]) -> str:
    """Match the runner's canonical unordered-AS-set hash."""

    return hashlib.sha256(
        ("\n".join(str(asn) for asn in sorted(asns)) + "\n").encode()
    ).hexdigest()


def load_jsonl(paths: Sequence[Path]) -> list[dict[str, Any]]:
    """Load append-only result shards in deterministic path/line order."""

    rows: list[dict[str, Any]] = []
    for path in sorted(paths):
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CampaignAnalysisError(
                        f"{path}:{line_number}: invalid JSON"
                    ) from exc
                if not isinstance(item, dict):
                    raise CampaignAnalysisError(
                        f"{path}:{line_number}: result must be a JSON object"
                    )
                rows.append(item)
    if not rows:
        raise CampaignAnalysisError("no campaign result rows were loaded")
    return rows


def manifest_trial_plan(
    manifest: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    """Return the frozen trial plan, which is the sole scenario enumeration."""

    plan = manifest.get("trial_plan")
    if isinstance(plan, list):
        items = plan
    elif isinstance(plan, dict) and isinstance(plan.get("trials"), list):
        items = plan["trials"]
    else:
        raise CampaignAnalysisError("manifest must contain a complete trial_plan")
    if not items or any(not isinstance(item, Mapping) for item in items):
        raise CampaignAnalysisError("trial_plan entries must be JSON objects")
    return tuple(items)


def expected_scenario_ids(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    """Read IDs from the runner's frozen plan without guessing missing rows."""

    values = [item.get("scenario_id") for item in manifest_trial_plan(manifest)]
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise CampaignAnalysisError("expected scenario IDs must be non-empty strings")
    duplicates = [value for value, count in Counter(values).items() if count > 1]
    if duplicates:
        raise CampaignAnalysisError(
            f"manifest contains duplicate expected scenario IDs: {duplicates[:3]}"
        )
    return tuple(values)


def expected_trials_per_holder(design: AnalysisDesign) -> int:
    """Return the frozen physical matrix size (184 under production design)."""

    lanes_per_cell = 1 + len(design.attacker_classes)
    fixed_references = 2 + 2 * len(design.attacker_classes)
    shared_endpoints = 2 * lanes_per_cell
    intermediate = (
        len(design.intermediate_percentages) * len(design.orders) * lanes_per_cell
    )
    return fixed_references + shared_endpoints + intermediate


def validate_expected_scenario_ids(
    rows: Sequence[Mapping[str, Any]], expected_ids: Sequence[str]
) -> None:
    actual: list[str] = []
    for row in rows:
        scenario_id = row.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise CampaignAnalysisError("every result row needs a scenario_id")
        actual.append(scenario_id)
    duplicates = [value for value, count in Counter(actual).items() if count > 1]
    if duplicates:
        raise CampaignAnalysisError(f"duplicate result scenario IDs: {duplicates[:3]}")
    actual_set = set(actual)
    expected_set = set(expected_ids)
    missing = sorted(expected_set - actual_set)
    unexpected = sorted(actual_set - expected_set)
    if missing or unexpected:
        raise CampaignAnalysisError(
            "scenario-ID mismatch: "
            f"missing={missing[:3]} ({len(missing)} total), "
            f"unexpected={unexpected[:3]} ({len(unexpected)} total)"
        )


def _manifest_units(manifest: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    for key in ("selected_units", "units"):
        value = manifest.get(key)
        if isinstance(value, list):
            return value
    sample = manifest.get("sample")
    if isinstance(sample, dict) and isinstance(sample.get("units"), list):
        return sample["units"]
    selection = manifest.get("selection")
    if isinstance(selection, dict) and isinstance(
        selection.get("selected_units"), list
    ):
        return selection["selected_units"]
    raise CampaignAnalysisError("manifest does not contain selected holder units")


def load_holder_design(
    manifest: Mapping[str, Any],
    *,
    expected_holders: int = EXPECTED_HOLDERS,
    strict_production_strata: bool = True,
) -> dict[int, HolderDesign]:
    """Load and verify four-stratum holder weights from the frozen manifest."""

    units = _manifest_units(manifest)
    if len(units) != expected_holders:
        raise CampaignAnalysisError(
            f"expected {expected_holders} selected holders, found {len(units)}"
        )
    result: dict[int, HolderDesign] = {}
    for item in units:
        if not isinstance(item, Mapping):
            raise CampaignAnalysisError("selected unit must be an object")
        holder = int(item["holder_asn"])
        stratum = str(item.get("stratum", item.get("holder_stratum", "")))
        if stratum not in STRATUM_FRAME_SIZES:
            raise CampaignAnalysisError(
                f"holder AS{holder} has invalid stratum {stratum!r}"
            )
        frame_size = int(
            item.get(
                "stratum_frame_size",
                item.get(
                    "stratum_population_N_h",
                    item.get("N_h", STRATUM_FRAME_SIZES[stratum]),
                ),
            )
        )
        sample_size = int(
            item.get(
                "stratum_sample_size",
                item.get(
                    "stratum_sample_n_h",
                    item.get("n_h", STRATUM_SAMPLE_SIZES[stratum]),
                ),
            )
        )
        expected_weight = frame_size / sample_size
        weight = float(item.get("design_weight", expected_weight))
        if not np.isclose(weight, expected_weight, rtol=0, atol=1e-12):
            raise CampaignAnalysisError(
                f"holder AS{holder} design weight {weight} != {expected_weight}"
            )
        if holder in result:
            raise CampaignAnalysisError(f"duplicate selected holder AS{holder}")
        result[holder] = HolderDesign(
            holder_asn=holder,
            stratum=stratum,
            frame_size=frame_size,
            sample_size=sample_size,
            design_weight=weight,
        )

    counts = Counter(unit.stratum for unit in result.values())
    for stratum in STRATUM_FRAME_SIZES:
        declared = {
            unit.sample_size for unit in result.values() if unit.stratum == stratum
        }
        if declared != {counts[stratum]}:
            raise CampaignAnalysisError(
                f"{stratum} declares sample size {sorted(declared)}, observed {counts[stratum]}"
            )
        frames = {
            unit.frame_size for unit in result.values() if unit.stratum == stratum
        }
        if len(frames) != 1:
            raise CampaignAnalysisError(f"{stratum} has inconsistent frame sizes")
        if strict_production_strata and (
            counts[stratum] != STRATUM_SAMPLE_SIZES[stratum]
            or frames != {STRATUM_FRAME_SIZES[stratum]}
        ):
            raise CampaignAnalysisError(
                f"{stratum} does not match frozen frame/sample sizes"
            )
    return result


def validate_selected_unit_assignments(manifest: Mapping[str, Any]) -> None:
    """Independently verify frozen root and attacker assignment invariants."""

    units = _manifest_units(manifest)
    roots = [str(item["root_prefix"]) for item in units]
    if len(roots) != len(set(roots)):
        raise CampaignAnalysisError("selected units contain repeated root prefixes")
    excluded = {
        int(item[field]) for item in units for field in ("holder_asn", "delegate_asn")
    }
    attackers_by_class: dict[str, list[int]] = {
        attacker_class: [] for attacker_class in ATTACKER_CLASSES
    }
    for item in units:
        unit_id = str(item.get("unit_id", item.get("holder_asn")))
        assigned: list[int] = []
        for attacker_class in ATTACKER_CLASSES:
            key = f"{attacker_class}_attacker_asn"
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, int):
                raise CampaignAnalysisError(
                    f"{unit_id}: missing integer {attacker_class} attacker assignment"
                )
            if value in excluded:
                raise CampaignAnalysisError(
                    f"{unit_id}: attacker AS{value} is a selected holder/delegate"
                )
            attackers_by_class[attacker_class].append(value)
            assigned.append(value)
        if len(set(assigned)) != len(ATTACKER_CLASSES):
            raise CampaignAnalysisError(
                f"{unit_id}: attacker classes are not distinct within unit"
            )
    for attacker_class, assigned in attackers_by_class.items():
        if len(assigned) != len(set(assigned)):
            raise CampaignAnalysisError(
                f"{attacker_class} attackers were not sampled without replacement"
            )


def _population_sections(row: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    outcomes = row.get("outcomes")
    if not isinstance(outcomes, Mapping):
        outcomes = row.get("outcomes_by_population")
    if not isinstance(outcomes, Mapping):
        raise CampaignAnalysisError(f"{row.get('scenario_id')}: missing outcomes")
    if all(key in outcomes for key in POPULATIONS):
        return outcomes  # type: ignore[return-value]
    if "denominator_asns" in outcomes:
        return {"all": outcomes}  # compatibility with the resource-gate schema
    raise CampaignAnalysisError(
        f"{row.get('scenario_id')}: outcomes need all/rov/non_rov populations"
    )


def _counts(section: Mapping[str, Any], partition: str) -> Mapping[str, Any]:
    value = section.get(partition)
    if not isinstance(value, Mapping) or not isinstance(value.get("counts"), Mapping):
        raise CampaignAnalysisError(f"missing {partition} counts")
    return value["counts"]


def validate_partitions(
    rows: Sequence[Mapping[str, Any]],
    *,
    populations: Sequence[str] = POPULATIONS,
) -> None:
    """Validate complete count partitions and all = ROV + non-ROV."""

    fixed_denominators: dict[str, int] = {}
    for row in rows:
        scenario_id = str(row.get("scenario_id"))
        sections = _population_sections(row)
        for population in populations:
            if population not in sections:
                raise CampaignAnalysisError(
                    f"{scenario_id}: missing {population} population"
                )
            section = sections[population]
            denominator = section.get("denominator_asns")
            if (
                isinstance(denominator, bool)
                or not isinstance(denominator, int)
                or denominator <= 0
            ):
                raise CampaignAnalysisError(
                    f"{scenario_id}/{population}: invalid denominator"
                )
            previous_denominator = fixed_denominators.setdefault(
                population, denominator
            )
            if denominator != previous_denominator:
                raise CampaignAnalysisError(
                    f"{scenario_id}/{population}: denominator {denominator} differs "
                    f"from campaign-fixed {previous_denominator}"
                )
            for partition, expected_outcomes in (
                ("child", CHILD_OUTCOMES),
                ("destination", DESTINATION_OUTCOMES),
            ):
                counts = _counts(section, partition)
                if set(counts) != set(expected_outcomes):
                    raise CampaignAnalysisError(
                        f"{scenario_id}/{population}/{partition}: incomplete outcomes"
                    )
                if any(
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                    for value in counts.values()
                ):
                    raise CampaignAnalysisError(
                        f"{scenario_id}/{population}/{partition}: invalid count"
                    )
                if sum(counts.values()) != denominator:
                    raise CampaignAnalysisError(
                        f"{scenario_id}/{population}/{partition}: partition sums to "
                        f"{sum(counts.values())}, expected {denominator}"
                    )
                fractions = section[partition].get("fractions")
                if fractions is not None:
                    if not isinstance(fractions, Mapping) or set(fractions) != set(
                        counts
                    ):
                        raise CampaignAnalysisError(
                            f"{scenario_id}/{population}/{partition}: bad fractions"
                        )
                    for outcome, count in counts.items():
                        if not np.isclose(
                            float(fractions[outcome]),
                            count / denominator,
                            rtol=0,
                            atol=1e-12,
                        ):
                            raise CampaignAnalysisError(
                                f"{scenario_id}/{population}/{partition}/{outcome}: "
                                "fraction does not match count"
                            )
        if {"all", "rov", "non_rov"}.issubset(sections):
            if sections["all"]["denominator_asns"] != (
                sections["rov"]["denominator_asns"]
                + sections["non_rov"]["denominator_asns"]
            ):
                raise CampaignAnalysisError(
                    f"{scenario_id}: population denominators are not additive"
                )
            for partition in ("child", "destination"):
                all_counts = _counts(sections["all"], partition)
                rov_counts = _counts(sections["rov"], partition)
                non_counts = _counts(sections["non_rov"], partition)
                if any(
                    all_counts[key] != rov_counts[key] + non_counts[key]
                    for key in all_counts
                ):
                    raise CampaignAnalysisError(
                        f"{scenario_id}/{partition}: all != rov + non_rov"
                    )


def _outcome_fingerprint(row: Mapping[str, Any]) -> tuple[Any, ...]:
    sections = _population_sections(row)
    result: list[Any] = []
    for population in sorted(sections):
        section = sections[population]
        result.append((population, int(section["denominator_asns"])))
        for partition in ("child", "destination"):
            counts = _counts(section, partition)
            result.append(
                (
                    partition,
                    tuple(
                        sorted((str(key), int(value)) for key, value in counts.items())
                    ),
                )
            )
    return tuple(result)


def _holder(row: Mapping[str, Any]) -> int:
    return int(row["holder_asn"])


def _attacker_class(row: Mapping[str, Any]) -> str | None:
    value = row.get("attacker_class")
    return None if value in (None, "", "none", "na", "not_applicable") else str(value)


def validate_zero_equivalence(rows: Sequence[Mapping[str, Any]]) -> None:
    """Enforce exact outcome equality for announcement-matched zero cells."""

    baselines: dict[tuple[int, str, str | None], Mapping[str, Any]] = {}
    staged_zero: list[Mapping[str, Any]] = []
    for row in rows:
        key = (_holder(row), str(row["lane"]), _attacker_class(row))
        if row["lane"] in {B1_DELEGATE, B1_COMPETITION}:
            if key in baselines:
                raise CampaignAnalysisError(f"duplicate baseline key {key}")
            baselines[key] = row
        if (
            row["lane"] in {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}
            and int(row["deployment_percent_target"]) == 0
        ):
            staged_zero.append(row)

    for row in staged_zero:
        holder = _holder(row)
        if row["lane"] == D1_OPEN_DELEGATE:
            key = (holder, B1_DELEGATE, None)
        else:
            key = (holder, B1_COMPETITION, _attacker_class(row))
        baseline = baselines.get(key)
        if baseline is None:
            raise CampaignAnalysisError(f"zero cell has no matched baseline {key}")
        if _outcome_fingerprint(row) != _outcome_fingerprint(baseline):
            raise CampaignAnalysisError(
                f"{row['scenario_id']}: zero cell differs from {baseline['scenario_id']}"
            )


def _order(row: Mapping[str, Any]) -> str:
    explicit = row.get("deployment_order")
    if explicit not in (None, ""):
        return str(explicit)
    strategy = str(row.get("deployment_strategy", ""))
    if strategy == "cone":
        return "customer_cone"
    if strategy == "random":
        seed = row.get("deployment_seed")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed <= 0:
            raise CampaignAnalysisError(
                "random deployment row needs a positive integer seed"
            )
        return f"random_{seed:02d}"
    return strategy


def _strategy(order: str) -> str:
    if order.startswith("random_"):
        return "random"
    if order in {"degree", "customer_cone"}:
        return order
    if order in {"shared", "endpoint", "fixed"}:
        return "shared"
    raise CampaignAnalysisError(f"unknown deployment order {order!r}")


def _deployment_signature(item: Mapping[str, Any]) -> tuple[str, int | None]:
    """Normalize runner plan/result deployment metadata for exact comparison."""

    explicit_order = item.get("deployment_order")
    if explicit_order not in (None, ""):
        order = str(explicit_order)
        if order.startswith("random_"):
            try:
                return "random", int(order.removeprefix("random_"))
            except ValueError as exc:
                raise CampaignAnalysisError(
                    f"invalid random deployment order {order!r}"
                ) from exc
        strategy = "customer_cone" if order == "cone" else order
        return strategy, None

    strategy = str(item.get("deployment_strategy", ""))
    strategy = "customer_cone" if strategy == "cone" else strategy
    seed = item.get("deployment_seed")
    if seed in (None, "", "na", "none"):
        normalized_seed = None
    elif isinstance(seed, bool):
        raise CampaignAnalysisError("deployment seed cannot be boolean")
    else:
        try:
            normalized_seed = int(seed)
        except (TypeError, ValueError) as exc:
            raise CampaignAnalysisError(f"invalid deployment seed {seed!r}") from exc
    if strategy == "random":
        if normalized_seed is None or normalized_seed <= 0:
            raise CampaignAnalysisError(
                "random deployment needs a positive integer seed"
            )
    elif normalized_seed is not None:
        raise CampaignAnalysisError(
            f"non-random deployment {strategy!r} cannot carry a seed"
        )
    return strategy, normalized_seed


def validate_rows_against_trial_plan(
    rows: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any]
) -> None:
    """Bind every result row to immutable plan metadata by scenario ID."""

    plan_by_id = {
        str(item["scenario_id"]): item for item in manifest_trial_plan(manifest)
    }
    units_by_id = {
        str(item["unit_id"]): item
        for item in _manifest_units(manifest)
        if "unit_id" in item
    }
    for row in rows:
        scenario_id = str(row["scenario_id"])
        lane = str(row.get("lane", ""))
        if lane not in KNOWN_LANES:
            raise CampaignAnalysisError(
                f"{scenario_id}: unknown campaign lane {lane!r}"
            )
        planned = plan_by_id[scenario_id]
        planned_lane = str(planned.get("lane", ""))
        if planned_lane not in KNOWN_LANES:
            raise CampaignAnalysisError(
                f"{scenario_id}: trial plan has unknown lane {planned_lane!r}"
            )
        unit_id = str(planned.get("unit_id", ""))
        planned_unit = units_by_id.get(unit_id)
        if planned_unit is None:
            raise CampaignAnalysisError(
                f"{scenario_id}: plan cannot be joined to selected unit {unit_id!r}"
            )
        planned_holder = planned_unit["holder_asn"]
        actual_metadata = (
            lane,
            _holder(row),
            _attacker_class(row),
            _deployment_signature(row),
            int(row["deployment_percent_target"]),
        )
        planned_metadata = (
            planned_lane,
            int(planned_holder),
            _attacker_class(planned),
            _deployment_signature(planned),
            int(planned["deployment_percent_target"]),
        )
        if actual_metadata != planned_metadata:
            raise CampaignAnalysisError(
                f"{scenario_id}: result metadata {actual_metadata!r} differs "
                f"from frozen plan {planned_metadata!r}"
            )

        immutable_fields = {
            "unit_id": unit_id,
            "pair_index": int(planned_unit["pair_index"]),
            "root_prefix": str(planned_unit["root_prefix"]),
            "leaf_prefix": str(planned_unit["leaf_prefix"]),
            "holder_asn": int(planned_unit["holder_asn"]),
            "delegate_asn": int(planned_unit["delegate_asn"]),
        }
        for field, expected in immutable_fields.items():
            if field not in row:
                raise CampaignAnalysisError(
                    f"{scenario_id}: result is missing immutable field {field}"
                )
            actual = int(row[field]) if isinstance(expected, int) else str(row[field])
            if actual != expected:
                raise CampaignAnalysisError(
                    f"{scenario_id}: result {field}={actual!r} differs from "
                    f"selected-unit value {expected!r}"
                )
        if int(planned.get("pair_index", planned_unit["pair_index"])) != int(
            planned_unit["pair_index"]
        ):
            raise CampaignAnalysisError(
                f"{scenario_id}: trial-plan pair_index differs from selected unit"
            )

        attacker_class = _attacker_class(planned)
        competition_lanes = {
            B1_COMPETITION,
            B2_COMPETITION,
            A1_OPEN_COMPETITION,
        }
        if "attacker_asn" not in row:
            raise CampaignAnalysisError(
                f"{scenario_id}: result is missing immutable field attacker_asn"
            )
        if planned_lane in competition_lanes:
            if attacker_class is None:
                raise CampaignAnalysisError(
                    f"{scenario_id}: competition lane has no attacker class"
                )
            attacker_key = f"{attacker_class}_attacker_asn"
            if attacker_key not in planned_unit:
                raise CampaignAnalysisError(
                    f"{scenario_id}: selected unit lacks {attacker_key}"
                )
            expected_attacker = int(planned_unit[attacker_key])
            if (
                row.get("attacker_asn") is None
                or int(row["attacker_asn"]) != expected_attacker
            ):
                raise CampaignAnalysisError(
                    f"{scenario_id}: attacker ASN does not match selected "
                    f"{attacker_class} assignment AS{expected_attacker}"
                )
        elif row.get("attacker_asn") is not None:
            raise CampaignAnalysisError(
                f"{scenario_id}: delegate-only lane must have null attacker_asn"
            )


def validate_execution_contract(
    rows: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    *,
    design: AnalysisDesign,
) -> None:
    """Independently verify manifest, deployment sets, and policy assignments."""

    manifest_schema = manifest.get("schema_version")
    if manifest_schema != SCHEMA_VERSION:
        raise CampaignAnalysisError(
            f"manifest schema {manifest_schema!r} != supported {SCHEMA_VERSION}"
        )
    manifest_digest = manifest.get("manifest_sha256")
    if not isinstance(manifest_digest, str) or (
        manifest_digest != canonical_manifest_sha256(manifest)
    ):
        raise CampaignAnalysisError("manifest self-SHA256 mismatch")

    plan = manifest_trial_plan(manifest)
    ids = sorted(str(item["scenario_id"]) for item in plan)
    ids_contract = manifest.get("expected_scenario_ids")
    expected_ids_digest = hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest()
    if not isinstance(ids_contract, Mapping) or (
        int(ids_contract.get("count", -1)) != len(ids)
        or ids_contract.get("sorted_newline_sha256") != expected_ids_digest
    ):
        raise CampaignAnalysisError("manifest scenario-ID digest contract mismatch")

    topology = manifest.get("topology")
    if not isinstance(topology, Mapping):
        raise CampaignAnalysisError("manifest has no topology contract")
    topology_asns = int(topology["asns"])
    fixed_rov = tuple(int(asn) for asn in topology["fixed_rov_asns"])
    fixed_rov_set = frozenset(fixed_rov)
    fixed_rov_count = int(topology["fixed_rov_count"])
    if (
        len(fixed_rov) != fixed_rov_count
        or len(fixed_rov_set) != fixed_rov_count
        or fixed_rov_count <= 0
        or topology_asns <= fixed_rov_count
    ):
        raise CampaignAnalysisError("manifest fixed-ROV topology contract is invalid")

    raw_orders = manifest.get("deployment_orders")
    if not isinstance(raw_orders, list):
        raise CampaignAnalysisError("manifest has no deployment_orders list")
    orders: dict[str, Mapping[str, Any]] = {}
    for raw in raw_orders:
        if not isinstance(raw, Mapping):
            raise CampaignAnalysisError("deployment order must be an object")
        order_id = str(raw["order_id"])
        if order_id in orders:
            raise CampaignAnalysisError(f"duplicate deployment order {order_id}")
        if order_id.startswith("random_"):
            expected_strategy = "random"
            expected_seed = int(order_id.removeprefix("random_"))
        else:
            expected_strategy = order_id
            expected_seed = None
        if raw.get("strategy") != expected_strategy or raw.get("seed") != expected_seed:
            raise CampaignAnalysisError(
                f"deployment order {order_id} strategy/seed mismatch"
            )
        asns = tuple(int(asn) for asn in raw["asns"])
        if len(asns) != fixed_rov_count or frozenset(asns) != fixed_rov_set:
            raise CampaignAnalysisError(
                f"deployment order {order_id} is not the fixed ROV permutation"
            )
        order_digest = hashlib.sha256(
            "\n".join(str(asn) for asn in asns).encode()
        ).hexdigest()
        if raw.get("order_sha256") != order_digest:
            raise CampaignAnalysisError(f"deployment order {order_id} SHA256 mismatch")
        declared_counts = raw.get("deployment_counts")
        if not isinstance(declared_counts, Mapping):
            raise CampaignAnalysisError(
                f"deployment order {order_id} has no floor-count contract"
            )
        for percent in design.percentages:
            count = (
                fixed_rov_count
                if percent == 100
                else int(fixed_rov_count * percent / 100)
            )
            if int(declared_counts.get(str(percent), -1)) != count:
                raise CampaignAnalysisError(
                    f"deployment order {order_id}/{percent}% count mismatch"
                )
        orders[order_id] = raw

    if set(orders) != set(design.orders):
        raise CampaignAnalysisError(
            f"deployment order IDs {sorted(orders)} != {sorted(design.orders)}"
        )

    plan_by_id = {str(item["scenario_id"]): item for item in plan}
    staged_lanes = {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}
    required_fields = {
        "schema_version",
        "status",
        "manifest_sha256",
        "deployment_count",
        "deployment_fraction_actual",
        "order_id",
        "order_sha256",
        "deployment_set_sha256",
        "fixed_rov_count",
        "policy_assignment_counts",
    }
    for row in rows:
        scenario_id = str(row["scenario_id"])
        missing = sorted(required_fields - set(row))
        if missing:
            raise CampaignAnalysisError(
                f"{scenario_id}: result is missing execution fields {missing}"
            )
        if row["schema_version"] != manifest_schema or row["status"] != "success":
            raise CampaignAnalysisError(
                f"{scenario_id}: result schema/status is not successful"
            )
        if row["manifest_sha256"] != manifest_digest:
            raise CampaignAnalysisError(
                f"{scenario_id}: result manifest SHA256 mismatch"
            )
        planned = plan_by_id[scenario_id]
        if row["order_id"] != planned.get("order_id"):
            raise CampaignAnalysisError(
                f"{scenario_id}: result order_id differs from plan"
            )
        percent = int(planned["deployment_percent_target"])
        expected_count = (
            fixed_rov_count if percent == 100 else int(fixed_rov_count * percent / 100)
        )
        if planned["lane"] not in staged_lanes:
            expected_count = 0
        if int(row["deployment_count"]) != expected_count:
            raise CampaignAnalysisError(
                f"{scenario_id}: deployment_count differs from frozen floor rule"
            )
        if not np.isclose(
            float(row["deployment_fraction_actual"]),
            expected_count / fixed_rov_count,
            rtol=0,
            atol=1e-12,
        ):
            raise CampaignAnalysisError(
                f"{scenario_id}: deployment_fraction_actual is inconsistent"
            )
        order_id = planned.get("order_id")
        if order_id is None:
            expected_order_hash = None
        else:
            if str(order_id) not in orders:
                raise CampaignAnalysisError(
                    f"{scenario_id}: plan refers to unknown order {order_id!r}"
                )
            strategy, seed = _deployment_signature(planned)
            expected_order_id = (
                f"random_{seed:02d}" if strategy == "random" else strategy
            )
            if str(order_id) != expected_order_id:
                raise CampaignAnalysisError(
                    f"{scenario_id}: plan strategy/seed does not match order_id"
                )
            expected_order_hash = orders[str(order_id)]["order_sha256"]
        if row["order_sha256"] != expected_order_hash:
            raise CampaignAnalysisError(
                f"{scenario_id}: result order SHA256 differs from manifest"
            )

        if expected_count == 0:
            expected_da_asns: Iterable[int] = ()
        elif percent == 100:
            expected_da_asns = fixed_rov_set
        else:
            assert order_id is not None
            expected_da_asns = orders[str(order_id)]["asns"][:expected_count]
        if row["deployment_set_sha256"] != _asn_set_sha256(expected_da_asns):
            raise CampaignAnalysisError(
                f"{scenario_id}: deployment set is not the manifest order prefix"
            )
        if int(row["fixed_rov_count"]) != fixed_rov_count:
            raise CampaignAnalysisError(
                f"{scenario_id}: fixed_rov_count differs from manifest"
            )

        assignments = row["policy_assignment_counts"]
        if not isinstance(assignments, Mapping) or set(assignments) != {
            "bgp",
            "rov",
            "darov",
        }:
            raise CampaignAnalysisError(
                f"{scenario_id}: invalid policy_assignment_counts"
            )
        bgp = int(assignments["bgp"])
        rov = int(assignments["rov"])
        darov = int(assignments["darov"])
        if (
            bgp + rov + darov != topology_asns
            or rov + darov != fixed_rov_count
            or darov != expected_count
        ):
            raise CampaignAnalysisError(
                f"{scenario_id}: policy assignments violate topology/deployment"
            )

        sections = _population_sections(row)
        expected_denominators = {
            "all": topology_asns,
            "rov": fixed_rov_count,
            "non_rov": topology_asns - fixed_rov_count,
        }
        for population, denominator in expected_denominators.items():
            if int(sections[population]["denominator_asns"]) != denominator:
                raise CampaignAnalysisError(
                    f"{scenario_id}/{population}: denominator differs from manifest"
                )


def expected_physical_cells(design: AnalysisDesign) -> frozenset[tuple[Any, ...]]:
    """Construct the exact 184-cell physical matrix for one holder."""

    cells: set[tuple[Any, ...]] = {
        (B1_DELEGATE, None, "reference", None, 0),
        (B2_DELEGATE, None, "reference", None, 0),
    }
    for attacker_class in design.attacker_classes:
        cells.add((B1_COMPETITION, attacker_class, "reference", None, 0))
        cells.add((B2_COMPETITION, attacker_class, "reference", None, 0))

    for percent in (design.percentages[0], design.percentages[-1]):
        cells.add((D1_OPEN_DELEGATE, None, "shared", None, percent))
        for attacker_class in design.attacker_classes:
            cells.add(
                (
                    A1_OPEN_COMPETITION,
                    attacker_class,
                    "shared",
                    None,
                    percent,
                )
            )

    for percent in design.intermediate_percentages:
        for order in design.orders:
            if order.startswith("random_"):
                strategy, seed = "random", int(order.removeprefix("random_"))
            else:
                strategy, seed = (
                    "customer_cone" if order == "cone" else order,
                    None,
                )
            cells.add((D1_OPEN_DELEGATE, None, strategy, seed, percent))
            for attacker_class in design.attacker_classes:
                cells.add(
                    (
                        A1_OPEN_COMPETITION,
                        attacker_class,
                        strategy,
                        seed,
                        percent,
                    )
                )
    return frozenset(cells)


def validate_complete_cell_grid(
    rows: Sequence[Mapping[str, Any]],
    holders: Iterable[int],
    *,
    design: AnalysisDesign,
) -> None:
    """Reject a missing, substituted, duplicated, or unexpected physical cell."""

    expected = expected_physical_cells(design)
    grouped: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[_holder(row)].append(row)
    for holder in holders:
        actual = [
            (
                str(row["lane"]),
                _attacker_class(row),
                *_deployment_signature(row),
                int(row["deployment_percent_target"]),
            )
            for row in grouped.get(holder, [])
        ]
        counts = Counter(actual)
        duplicates = sorted(
            (cell for cell, count in counts.items() if count > 1), key=repr
        )
        actual_set = set(actual)
        missing = sorted(expected - actual_set, key=repr)
        unexpected = sorted(actual_set - expected, key=repr)
        if duplicates or missing or unexpected or len(actual) != len(expected):
            raise CampaignAnalysisError(
                f"holder AS{holder} physical cell grid mismatch: "
                f"duplicates={duplicates[:2]}, missing={missing[:2]}, "
                f"unexpected={unexpected[:2]}, rows={len(actual)}, "
                f"expected={len(expected)}"
            )


def expected_summary_cells(design: AnalysisDesign) -> int:
    """Return destination-primary plus child-mechanism analysis cells."""

    strategies = {_strategy(order) for order in design.orders}
    estimand_attacker_blocks = 2 + 2 * len(design.attacker_classes)
    return (
        estimand_attacker_blocks
        * 2
        * len(design.populations)
        * len(strategies)
        * len(design.percentages)
    )


def _fraction(
    row: Mapping[str, Any], population: str, partition: str, outcome: str
) -> float:
    section = _population_sections(row)[population]
    counts = _counts(section, partition)
    return int(counts[outcome]) / int(section["denominator_asns"])


def _unique_index(
    rows: Iterable[Mapping[str, Any]],
    key_fn: Any,
    label: str,
) -> dict[Any, Mapping[str, Any]]:
    result: dict[Any, Mapping[str, Any]] = {}
    for row in rows:
        key = key_fn(row)
        if key in result:
            raise CampaignAnalysisError(f"duplicate {label} key {key}")
        result[key] = row
    return result


def validate_row_design_metadata(
    rows: Sequence[Mapping[str, Any]], holder_design: Mapping[int, HolderDesign]
) -> None:
    """Require every runner row to repeat the frozen sampling metadata exactly."""

    for row in rows:
        scenario_id = str(row.get("scenario_id"))
        holder = _holder(row)
        unit = holder_design.get(holder)
        if unit is None:
            raise CampaignAnalysisError(
                f"{scenario_id}: holder AS{holder} is outside the frozen sample"
            )
        row_frame = row.get("N_h", row.get("stratum_population_N_h"))
        row_sample = row.get("n_h", row.get("stratum_sample_n_h"))
        required_values = {
            "holder_stratum": row.get("holder_stratum"),
            "N_h": row_frame,
            "n_h": row_sample,
            "design_weight": row.get("design_weight"),
        }
        missing = [key for key, value in required_values.items() if value is None]
        if missing:
            raise CampaignAnalysisError(
                f"{scenario_id}: missing design metadata {missing}"
            )
        if (
            str(row["holder_stratum"]) != unit.stratum
            or int(row_frame) != unit.frame_size
            or int(row_sample) != unit.sample_size
            or not np.isclose(
                float(row["design_weight"]), unit.design_weight, rtol=0, atol=1e-12
            )
        ):
            raise CampaignAnalysisError(
                f"{scenario_id}: row design metadata differs from manifest"
            )


def build_holder_contrasts(
    rows: Sequence[Mapping[str, Any]],
    holder_design: Mapping[int, HolderDesign],
    *,
    design: AnalysisDesign = AnalysisDesign(),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build seed-level and holder-averaged paired contrasts.

    The returned first list is the analysis table: exactly one record per
    holder/cell.  The second retains the five random-order estimates only for
    descriptive seed-range reporting.
    """

    row_holders = {_holder(row) for row in rows}
    if row_holders != set(holder_design):
        raise CampaignAnalysisError(
            "result holders differ from frozen sample: "
            f"missing={sorted(set(holder_design) - row_holders)[:3]}, "
            f"unexpected={sorted(row_holders - set(holder_design))[:3]}"
        )
    validate_row_design_metadata(rows, holder_design)

    b1_delegate = _unique_index(
        (row for row in rows if row["lane"] == B1_DELEGATE),
        lambda row: _holder(row),
        B1_DELEGATE,
    )
    b2_delegate = _unique_index(
        (row for row in rows if row["lane"] == B2_DELEGATE),
        lambda row: _holder(row),
        B2_DELEGATE,
    )
    b1_competition = _unique_index(
        (row for row in rows if row["lane"] == B1_COMPETITION),
        lambda row: (_holder(row), _attacker_class(row)),
        B1_COMPETITION,
    )
    b2_competition = _unique_index(
        (row for row in rows if row["lane"] == B2_COMPETITION),
        lambda row: (_holder(row), _attacker_class(row)),
        B2_COMPETITION,
    )
    if set(b1_delegate) != set(holder_design):
        raise CampaignAnalysisError("B1 delegate baseline is incomplete")
    if set(b2_delegate) != set(holder_design):
        raise CampaignAnalysisError("B2 delegate baseline is incomplete")
    expected_competition = {
        (holder, attacker_class)
        for holder in holder_design
        for attacker_class in design.attacker_classes
    }
    if set(b1_competition) != expected_competition:
        raise CampaignAnalysisError("B1 competition baselines are incomplete")
    if set(b2_competition) != expected_competition:
        raise CampaignAnalysisError("B2 competition baselines are incomplete")

    seed_level: list[dict[str, Any]] = []
    for row in rows:
        lane = str(row["lane"])
        if lane not in {D1_OPEN_DELEGATE, A1_OPEN_COMPETITION}:
            continue
        holder = _holder(row)
        percent = int(row["deployment_percent_target"])
        if percent not in design.percentages:
            raise CampaignAnalysisError(f"unexpected deployment percentage {percent}")
        order = _order(row)
        if percent in {design.percentages[0], design.percentages[-1]}:
            if _strategy(order) != "shared":
                raise CampaignAnalysisError(
                    f"{row['scenario_id']}: endpoint must use shared order"
                )
            output_strategies = ("degree", "customer_cone", "random")
        else:
            if order not in design.orders:
                raise CampaignAnalysisError(f"unexpected deployment order {order!r}")
            output_strategies = (_strategy(order),)

        attacker_class = _attacker_class(row)
        if lane == D1_OPEN_DELEGATE:
            if attacker_class is not None:
                raise CampaignAnalysisError("D1 rows must not carry an attacker class")
            references = (
                ("Delta_R", b1_delegate[holder], "delegate"),
                ("Delta_R_exact", b2_delegate[holder], "delegate"),
            )
        else:
            if attacker_class not in design.attacker_classes:
                raise CampaignAnalysisError(
                    f"A1 row has invalid attacker class {attacker_class!r}"
                )
            references = (
                ("Delta_E_rov", b1_competition[(holder, attacker_class)], "attacker"),
                ("Delta_E_exact", b2_competition[(holder, attacker_class)], "attacker"),
            )

        unit = holder_design[holder]
        for population in design.populations:
            for estimand, reference, outcome in references:
                for metric_level in ("destination", "child"):
                    treatment = _fraction(row, population, metric_level, outcome)
                    reference_value = _fraction(
                        reference, population, metric_level, outcome
                    )
                    for strategy in output_strategies:
                        seed_level.append(
                            {
                                "holder_asn": holder,
                                "stratum": unit.stratum,
                                "design_weight": unit.design_weight,
                                "estimand": estimand,
                                "metric_level": metric_level,
                                "population": population,
                                "attacker_class": attacker_class,
                                "deployment_strategy": strategy,
                                "deployment_percent_target": percent,
                                "deployment_order": order,
                                "treatment_fraction": treatment,
                                "reference_fraction": reference_value,
                                "delta": treatment - reference_value,
                            }
                        )

    group_fields = (
        "holder_asn",
        "stratum",
        "design_weight",
        "estimand",
        "metric_level",
        "population",
        "attacker_class",
        "deployment_strategy",
        "deployment_percent_target",
    )
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in seed_level:
        grouped[tuple(item[key] for key in group_fields)].append(item)

    averaged: list[dict[str, Any]] = []
    for key, group in grouped.items():
        base = dict(zip(group_fields, key, strict=True))
        strategy = str(base["deployment_strategy"])
        percent = int(base["deployment_percent_target"])
        orders = {str(item["deployment_order"]) for item in group}
        if strategy == "random" and percent in design.intermediate_percentages:
            if orders != set(design.random_orders) or len(group) != len(
                design.random_orders
            ):
                raise CampaignAnalysisError(
                    "random cell must contain exactly the five frozen orders: "
                    f"holder={base['holder_asn']}, percent={percent}, orders={sorted(orders)}"
                )
        elif len(group) != 1:
            raise CampaignAnalysisError(
                f"non-random/shared cell has {len(group)} rows for key {key}"
            )
        averaged.append(
            {
                **base,
                "random_orders_averaged": (
                    len(group)
                    if strategy == "random"
                    and percent in design.intermediate_percentages
                    else 0
                ),
                "treatment_fraction": float(
                    np.mean([float(item["treatment_fraction"]) for item in group])
                ),
                "reference_fraction": float(
                    np.mean([float(item["reference_fraction"]) for item in group])
                ),
                "delta": float(np.mean([float(item["delta"]) for item in group])),
            }
        )

    cell_groups: dict[tuple[Any, ...], set[int]] = defaultdict(set)
    for item in averaged:
        cell = tuple(item[key] for key in group_fields[3:])
        holder = int(item["holder_asn"])
        if holder in cell_groups[cell]:
            raise CampaignAnalysisError(f"duplicate holder observation in cell {cell}")
        cell_groups[cell].add(holder)
    for cell, holders in cell_groups.items():
        if holders != set(holder_design):
            raise CampaignAnalysisError(
                f"cell {cell} has {len(holders)} holders, expected {len(holder_design)}"
            )
    return averaged, seed_level


def weighted_quantile(
    values: Sequence[float], weights: Sequence[float], quantile: float
) -> float:
    """Return the left-continuous weighted empirical quantile."""

    if not 0 <= quantile <= 1:
        raise ValueError("quantile must lie in [0, 1]")
    value_array = np.asarray(values, dtype=float)
    weight_array = np.asarray(weights, dtype=float)
    if value_array.size == 0 or value_array.shape != weight_array.shape:
        raise ValueError("values and weights must be non-empty and aligned")
    if np.any(~np.isfinite(value_array)) or np.any(~np.isfinite(weight_array)):
        raise ValueError("values and weights must be finite")
    if np.any(weight_array <= 0):
        raise ValueError("weights must be positive")
    order = np.argsort(value_array, kind="stable")
    sorted_values = value_array[order]
    cumulative = np.cumsum(weight_array[order])
    target = quantile * cumulative[-1]
    index = int(np.searchsorted(cumulative, target, side="left"))
    return float(sorted_values[min(index, len(sorted_values) - 1)])


def _bootstrap_weight_matrix(
    holders: Sequence[int],
    holder_design: Mapping[int, HolderDesign],
    *,
    replicates: int,
    seed: int,
) -> np.ndarray:
    """Build paired SRSWOR-rescaled replicate weights within each stratum.

    Let ``m_hi`` be the ordinary multinomial count from drawing ``n_h``
    sampled holders with replacement inside stratum ``h``.  We transform that
    count around one,

    ``c_hi = 1 + a_h (m_hi - 1)``, where
    ``a_h = sqrt(n_h (1 - n_h / N_h) / (n_h - 1))``.

    Thus every replicate still has ``sum_i c_hi = n_h`` and, for a stratum
    mean, its conditional replicate variance is exactly the usual unbiased
    SRSWOR variance estimate ``(1 - n_h/N_h) s_h^2 / n_h``.  Multiplication by
    the frozen ``N_h/n_h`` design weight then keeps every stratum's replicate
    weight total equal to ``N_h``.  The same returned matrix is used for every
    analysis cell, preserving the complete paired holder vector.
    """

    if replicates <= 0:
        raise ValueError("bootstrap replicates must be positive")
    rng = np.random.default_rng(seed)
    matrix = np.zeros((replicates, len(holders)), dtype=float)
    positions = {holder: index for index, holder in enumerate(holders)}
    for stratum in STRATUM_FRAME_SIZES:
        members = [
            holder for holder in holders if holder_design[holder].stratum == stratum
        ]
        if not members:
            raise CampaignAnalysisError(f"bootstrap stratum {stratum} is empty")
        sample_size = len(members)
        declared_sample_sizes = {
            holder_design[holder].sample_size for holder in members
        }
        frame_sizes = {holder_design[holder].frame_size for holder in members}
        design_weights = {holder_design[holder].design_weight for holder in members}
        if declared_sample_sizes != {sample_size}:
            raise CampaignAnalysisError(
                f"bootstrap stratum {stratum} sample-size metadata differs "
                f"from its {sample_size} holders"
            )
        if len(frame_sizes) != 1 or len(design_weights) != 1:
            raise CampaignAnalysisError(
                f"bootstrap stratum {stratum} has inconsistent design metadata"
            )
        frame_size = next(iter(frame_sizes))
        if sample_size <= 1:
            raise CampaignAnalysisError(
                f"bootstrap stratum {stratum} needs at least two sampled holders"
            )
        if frame_size < sample_size:
            raise CampaignAnalysisError(
                f"bootstrap stratum {stratum} has n_h={sample_size} > N_h={frame_size}"
            )
        counts = rng.multinomial(
            sample_size,
            np.full(sample_size, 1 / sample_size),
            size=replicates,
        )
        sampling_fraction = sample_size / frame_size
        rescale = np.sqrt(sample_size * (1.0 - sampling_fraction) / (sample_size - 1))
        rescaled_counts = 1.0 + rescale * (counts.astype(float) - 1.0)
        design_weight = next(iter(design_weights))
        matrix[:, [positions[holder] for holder in members]] = (
            rescaled_counts * design_weight
        )
    return matrix


def summarize_cells(
    holder_contrasts: Sequence[Mapping[str, Any]],
    seed_level: Sequence[Mapping[str, Any]],
    holder_design: Mapping[int, HolderDesign],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> list[dict[str, Any]]:
    """Return design-weighted cell estimates and stratified paired intervals."""

    cell_fields = (
        "estimand",
        "metric_level",
        "population",
        "attacker_class",
        "deployment_strategy",
        "deployment_percent_target",
    )
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for item in holder_contrasts:
        grouped[tuple(item[key] for key in cell_fields)].append(item)

    holders = sorted(holder_design)
    holder_position = {holder: index for index, holder in enumerate(holders)}
    cells = sorted(
        grouped, key=lambda key: tuple("" if value is None else value for value in key)
    )
    delta_matrix = np.empty((len(holders), len(cells)), dtype=float)
    for column, cell in enumerate(cells):
        group = grouped[cell]
        if len(group) != len(holders):
            raise CampaignAnalysisError(f"cell {cell} is not holder-complete")
        for item in group:
            delta_matrix[holder_position[int(item["holder_asn"])], column] = float(
                item["delta"]
            )

    bootstrap_weights = _bootstrap_weight_matrix(
        holders,
        holder_design,
        replicates=bootstrap_replicates,
        seed=bootstrap_seed,
    )
    bootstrap_means = bootstrap_weights @ delta_matrix
    bootstrap_means /= bootstrap_weights.sum(axis=1, keepdims=True)
    intervals = np.percentile(bootstrap_means, (2.5, 97.5), axis=0, method="linear")

    seed_groups: dict[tuple[Any, ...], dict[str, list[Mapping[str, Any]]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for item in seed_level:
        if item["deployment_strategy"] != "random" or not str(
            item["deployment_order"]
        ).startswith("random_"):
            continue
        cell = tuple(item[key] for key in cell_fields)
        seed_groups[cell][str(item["deployment_order"])].append(item)

    summary: list[dict[str, Any]] = []
    for column, cell in enumerate(cells):
        group = grouped[cell]
        values = np.asarray([float(item["delta"]) for item in group])
        treatment = np.asarray([float(item["treatment_fraction"]) for item in group])
        reference = np.asarray([float(item["reference_fraction"]) for item in group])
        weights = np.asarray([float(item["design_weight"]) for item in group])
        weighted_mean = float(np.average(values, weights=weights))
        q25 = weighted_quantile(values, weights, 0.25)
        median = weighted_quantile(values, weights, 0.5)
        q75 = weighted_quantile(values, weights, 0.75)

        per_seed: dict[str, float] = {}
        for order, order_group in sorted(seed_groups.get(cell, {}).items()):
            if len(order_group) != len(holders):
                raise CampaignAnalysisError(
                    f"random order {order} in cell {cell} is not holder-complete"
                )
            per_seed[order] = float(
                np.average(
                    [float(item["delta"]) for item in order_group],
                    weights=[float(item["design_weight"]) for item in order_group],
                )
            )
        seed_min = min(per_seed.values()) if per_seed else None
        seed_max = max(per_seed.values()) if per_seed else None
        summary.append(
            {
                **dict(zip(cell_fields, cell, strict=True)),
                "independent_unit": "holder_asn",
                "n_holders": len(holders),
                "n_ases_as_independent_units": 0,
                "n_random_orders_as_independent_units": 0,
                "design_population_holders": sum(STRATUM_FRAME_SIZES.values())
                if len(holders) == EXPECTED_HOLDERS
                else float(weights.sum()),
                "design_weight_sum": float(weights.sum()),
                "raw_treatment_design_weighted_mean": float(
                    np.average(treatment, weights=weights)
                ),
                "raw_reference_design_weighted_mean": float(
                    np.average(reference, weights=weights)
                ),
                "paired_delta_design_weighted_mean": weighted_mean,
                "absolute_paired_delta_design_weighted_mean": abs(weighted_mean),
                "pointwise_ci95_lower": float(intervals[0, column]),
                "pointwise_ci95_upper": float(intervals[1, column]),
                "paired_delta_weighted_q25": q25,
                "paired_delta_weighted_median": median,
                "paired_delta_weighted_q75": q75,
                "paired_delta_weighted_iqr": q75 - q25,
                "random_seed_count": len(per_seed),
                "random_seed_design_weighted_deltas": per_seed,
                "random_seed_delta_min": seed_min,
                "random_seed_delta_max": seed_max,
                "random_seed_delta_range": (
                    seed_max - seed_min
                    if seed_min is not None and seed_max is not None
                    else None
                ),
                "bootstrap_replicates": bootstrap_replicates,
                "bootstrap_seed": bootstrap_seed,
                "ci_type": (
                    "pointwise_stratified_paired_rescaled_percentile_srswor_fpc"
                ),
            }
        )
    return summary


def analyze_campaign(
    rows: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
    expected_holders: int = EXPECTED_HOLDERS,
    strict_production_strata: bool = True,
    design: AnalysisDesign = AnalysisDesign(),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Run all fail-closed validations and return analysis artifacts."""

    expected_ids = expected_scenario_ids(manifest)
    validate_expected_scenario_ids(rows, expected_ids)
    holder_design = load_holder_design(
        manifest,
        expected_holders=expected_holders,
        strict_production_strata=strict_production_strata,
    )
    validate_selected_unit_assignments(manifest)
    expected_trial_count = len(holder_design) * expected_trials_per_holder(design)
    if len(expected_ids) != expected_trial_count:
        raise CampaignAnalysisError(
            f"trial plan has {len(expected_ids)} rows, expected {expected_trial_count} "
            f"({expected_trials_per_holder(design)} per holder)"
        )
    validate_rows_against_trial_plan(rows, manifest)
    validate_execution_contract(rows, manifest, design=design)
    validate_complete_cell_grid(rows, holder_design, design=design)
    validate_partitions(rows, populations=design.populations)
    validate_zero_equivalence(rows)
    holder_contrasts, seed_level = build_holder_contrasts(
        rows, holder_design, design=design
    )
    cell_summary = summarize_cells(
        holder_contrasts,
        seed_level,
        holder_design,
        bootstrap_replicates=bootstrap_replicates,
        bootstrap_seed=bootstrap_seed,
    )
    expected_summary_count = expected_summary_cells(design)
    if len(cell_summary) != expected_summary_count:
        raise CampaignAnalysisError(
            f"analysis produced {len(cell_summary)} summary cells, "
            f"expected {expected_summary_count}"
        )
    expected_contrast_count = len(holder_design) * expected_summary_count
    if len(holder_contrasts) != expected_contrast_count:
        raise CampaignAnalysisError(
            f"analysis produced {len(holder_contrasts)} holder contrasts, "
            f"expected {expected_contrast_count}"
        )
    validation = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "status": "VERIFIED",
        "checks": {
            "expected_scenario_ids_exact": True,
            "scenario_ids_unique": True,
            "result_metadata_matches_trial_plan": True,
            "scenario_identity_matches_selected_unit": True,
            "attacker_assignment_matches_selected_unit": True,
            "manifest_self_hash_and_scenario_digest_valid": True,
            "deployment_order_prefix_sets_valid": True,
            "policy_assignment_counts_valid": True,
            "selected_roots_and_attacker_assignments_valid": True,
            "physical_cell_grid_complete": True,
            "partitions_complete": True,
            "population_partitions_additive": True,
            "population_denominators_fixed_across_scenarios": True,
            "zero_upgrade_announcement_matched": True,
            "four_stratum_holder_design": True,
            "srswor_finite_population_rescaling": True,
            "random_orders_averaged_within_holder_first": True,
            "child_route_mechanism_summarized_separately": True,
            "summary_cell_grid_complete": True,
        },
        "scenario_rows": len(rows),
        "expected_scenario_rows": len(expected_ids),
        "expected_scenarios_per_holder": expected_trials_per_holder(design),
        "independent_unit": "holder_asn",
        "n_independent_holders": len(holder_design),
        "n_ases_as_independent_units": 0,
        "n_random_orders_as_independent_units": 0,
        "holder_contrast_rows": len(holder_contrasts),
        "summary_cells": len(cell_summary),
        "expected_summary_cells": expected_summary_count,
        "metric_levels": {
            "primary": "destination",
            "secondary_mechanism": "child",
        },
        "bootstrap": {
            "method": (
                "stratified paired holder rescaled bootstrap for SRSWOR with "
                "finite-population correction"
            ),
            "rescaled_count_formula": (
                "c_hi=1+a_h*(m_hi-1), "
                "a_h=sqrt(n_h*(1-n_h/N_h)/(n_h-1)), "
                "m_h~Multinomial(n_h;1/n_h,...,1/n_h)"
            ),
            "replicate_weight_totals": (
                "each stratum sums to N_h after applying design weight N_h/n_h"
            ),
            "replicates": bootstrap_replicates,
            "seed": bootstrap_seed,
            "interval": "pointwise rescaled-bootstrap percentile 95%",
            "inference_target": (
                "finite frozen eligible-holder frame, conditional on topology, "
                "ROV set, sampled within-holder scenario, attacker assignments, "
                "and five frozen random deployment orders"
            ),
        },
    }
    return holder_contrasts, cell_summary, validation


def _json_safe_csv_row(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: json.dumps(value, sort_keys=True)
        if isinstance(value, (dict, list))
        else value
        for key, value in item.items()
    }


def write_outputs(
    output_dir: Path,
    holder_contrasts: Sequence[Mapping[str, Any]],
    cell_summary: Sequence[Mapping[str, Any]],
    validation: Mapping[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    contrasts_path = output_dir / "holder_contrasts.jsonl"
    contrasts_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in holder_contrasts),
        encoding="utf-8",
    )
    (output_dir / "raw_cell_summary.json").write_text(
        json.dumps(list(cell_summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if cell_summary:
        with (output_dir / "raw_cell_summary.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=list(cell_summary[0]))
            writer.writeheader()
            writer.writerows(_json_safe_csv_row(item) for item in cell_summary)
    (output_dir / "analysis_manifest.json").write_text(
        json.dumps(dict(validation), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--results",
        type=Path,
        nargs="+",
        required=True,
        help="one or more campaign JSONL shards",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--bootstrap-replicates", type=int, default=DEFAULT_BOOTSTRAP_REPLICATES
    )
    parser.add_argument("--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise CampaignAnalysisError("manifest must be a JSON object")
    rows = load_jsonl(args.results)
    holder_contrasts, cell_summary, validation = analyze_campaign(
        rows,
        manifest,
        bootstrap_replicates=args.bootstrap_replicates,
        bootstrap_seed=args.bootstrap_seed,
    )
    validation = {
        **validation,
        "inputs": {
            "manifest": str(args.manifest),
            "manifest_sha256": sha256_file(args.manifest),
            "result_shards": [
                {"path": str(path), "sha256": sha256_file(path)}
                for path in sorted(args.results)
            ],
        },
    }
    write_outputs(args.output_dir, holder_contrasts, cell_summary, validation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
