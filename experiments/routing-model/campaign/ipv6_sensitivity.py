"""Independent IPv6 sensitivity campaign for the fixed BGPy model.

This module deliberately does not modify the frozen IPv4 paper campaign.  It
reads the retained visibility-candidate table, keeps IPv6 rows whose two
observed origins occur in the fixed AS graph, collapses repeated prefixes for
the same root/holder/delegate tuple, and freezes a compact 210-scenario plan.

The campaign is a dual-stack portability and sensitivity check.  The AS graph
and measured ROV set are the same family-neutral inputs used by Phase 7; the
experiment therefore does not claim to be an IPv6-specific topology study.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import statistics
import sys
import tempfile
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import version
from ipaddress import IPv6Network, ip_network
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable, Mapping, Sequence

from bgpy.simulation_engine import SimulationEngine

from phase4_encoding.scripts.utils.daroa import (
    DAROA,
    Stripe,
    ValidationState,
    is_eligible_delegated_origin,
)
from phase7_simulation.campaign.full_graph_gate import (
    A1_OPEN_COMPETITION,
    B1_COMPETITION,
    B1_DELEGATE,
    B2_COMPETITION,
    B2_DELEGATE,
    D1_OPEN_DELEGATE,
    PAIR_TABLE_PATH,
    PHASE4_ORACLE_PATH,
    POLICY_PATH,
    ROV_JSON_PATH,
    TOPOLOGY_PATH,
    PairSpec,
    PeakRSSMonitor,
    build_fixed_graph,
    check_policy_boundaries,
    current_rss_bytes,
    load_rov_asns,
    run_trial,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = Path(__file__).resolve()
SOURCE_CANDIDATES_PATH = (
    REPOSITORY_ROOT
    / "phase1_empirical"
    / "allocation_tree"
    / "visibility_experiment"
    / "outputs_depth"
    / "visibility_candidates.csv"
)
DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "phase7_simulation" / "results" / "ipv6_sensitivity"
)
DEFAULT_SMOKE_DIR = (
    REPOSITORY_ROOT
    / "phase7_simulation"
    / "results"
    / "ipv6_sensitivity_smoke"
)

SCHEMA_VERSION = 1
SELECTION_SEED = 20260828
COMPETITOR_SEED = 20260829
DEPLOYMENT_SEED = 20260830
DEPLOYMENT_PERCENTAGES = (0, 50, 100)
EXPECTED_IPV6_ROWS = 83
EXPECTED_TOPOLOGY_ROWS = 42
EXPECTED_UNIQUE_PAIRS = 21
EXPECTED_UNIQUE_ROOTS = 8
EXPECTED_TRIALS = 210

EXPECTED_SOURCE_HEADER = (
    "family",
    "root_prefix",
    "root_status",
    "root_org_handle",
    "endpoint_prefix",
    "endpoint_status",
    "endpoint_org_handle",
    "root_origins",
    "endpoint_origins",
    "path_classification",
    "confirming_hop_range",
    "confirming_hop_status",
    "confirming_hop_org_handle",
    "org_confirmed_abc",
)

LANE_ORDER = (
    B1_DELEGATE,
    B2_DELEGATE,
    B1_COMPETITION,
    B2_COMPETITION,
    D1_OPEN_DELEGATE,
    A1_OPEN_COMPETITION,
)


class IPv6CampaignError(ValueError):
    """Raised when an IPv6 campaign input or artifact fails closed."""


@dataclass(frozen=True)
class IPv6Candidate:
    """One topology-eligible IPv6 origin-divergence row."""

    source_row: int
    root_prefix: str
    holder_asn: int
    endpoint_prefix: str
    endpoint_asn: int


@dataclass(frozen=True)
class IPv6Unit:
    """One unique root/holder/endpoint-origin simulation unit."""

    unit_id: str
    pair_index: int
    root_prefix: str
    holder_asn: int
    endpoint_prefix: str
    endpoint_asn: int
    selected_source_row: int
    source_rows: tuple[int, ...]
    member_endpoint_prefixes: tuple[str, ...]
    holder_degree: int
    endpoint_degree: int
    competitor_asn: int = 0
    competitor_degree: int = 0

    def to_pair_spec(self) -> PairSpec:
        if self.competitor_asn <= 0:
            raise IPv6CampaignError(f"{self.unit_id} has no competitor assignment")
        return PairSpec(
            pair_index=self.pair_index,
            source_row=self.selected_source_row,
            root_prefix=self.root_prefix,
            holder_asn=self.holder_asn,
            leaf_prefix=self.endpoint_prefix,
            delegate_asn=self.endpoint_asn,
            holder_degree=self.holder_degree,
            delegate_degree=self.endpoint_degree,
            degree_bin=0,
            attacker_asn=self.competitor_asn,
            attacker_class="uniform_unlisted",
            attacker_degree=self.competitor_degree,
        )


@dataclass(frozen=True)
class IPv6Trial:
    """One physical scenario in the compact IPv6 matrix."""

    scenario_id: str
    unit_id: str
    pair_index: int
    lane: str
    announcement_set: str
    policy_reference: str
    deployment_percent_target: int
    deployment_count: int
    deployment_strategy: str
    deployment_seed: int | None


@dataclass(frozen=True)
class ExecutionSpec:
    """Duck-typed trial specification consumed by the frozen gate helper."""

    pair: PairSpec
    lane: str
    deployment_percent: int
    deployment_strategy: str
    scenario_id: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_sha256(seed: int, domain: str, *parts: object) -> str:
    payload = "\0".join((str(seed), domain, *(str(part) for part in parts)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_document_sha256(document: Mapping[str, Any]) -> str:
    core = dict(document)
    core.pop("manifest_sha256", None)
    payload = json.dumps(
        core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()


def file_record(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": relative_path(path),
        "bytes": len(raw),
        "physical_lines": raw.count(b"\n") + (0 if raw.endswith(b"\n") else 1),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def load_topology_degrees(
    path: Path = TOPOLOGY_PATH,
) -> tuple[dict[int, int], dict[str, Any]]:
    """Read the frozen relationship file without constructing a BGPy graph."""

    degrees: Counter[int] = Counter()
    relationship_counts: Counter[str] = Counter()
    relationships = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            fields = raw.rstrip("\n").split("|")
            if len(fields) != 3:
                raise IPv6CampaignError(
                    f"{path}:{line_number}: expected asn1|asn2|relationship"
                )
            try:
                asn1, asn2 = int(fields[0]), int(fields[1])
            except ValueError as exc:
                raise IPv6CampaignError(
                    f"{path}:{line_number}: non-integer ASN"
                ) from exc
            if asn1 <= 0 or asn2 <= 0 or asn1 == asn2:
                raise IPv6CampaignError(f"{path}:{line_number}: invalid AS pair")
            if fields[2] not in {"-1", "0"}:
                raise IPv6CampaignError(
                    f"{path}:{line_number}: unsupported relationship {fields[2]!r}"
                )
            degrees[asn1] += 1
            degrees[asn2] += 1
            relationship_counts[fields[2]] += 1
            relationships += 1
    if not degrees:
        raise IPv6CampaignError("topology is empty")
    return dict(degrees), {
        "asns": len(degrees),
        "relationships": relationships,
        "relationship_code_counts": dict(sorted(relationship_counts.items())),
    }


def _parse_origin_set(value: str, context: str) -> tuple[int, ...]:
    tokens = value.split(";") if value else []
    if not tokens or any(not token.isdigit() for token in tokens):
        raise IPv6CampaignError(f"{context}: invalid origin set {value!r}")
    origins = tuple(int(token) for token in tokens)
    if any(asn <= 0 or asn > 0xFFFFFFFF for asn in origins):
        raise IPv6CampaignError(f"{context}: origin outside 32-bit ASN range")
    if len(set(origins)) != len(origins):
        raise IPv6CampaignError(f"{context}: duplicate origin ASN")
    return origins


def load_ipv6_candidates(
    topology_asns: set[int],
    path: Path = SOURCE_CANDIDATES_PATH,
) -> tuple[tuple[IPv6Candidate, ...], dict[str, Any]]:
    """Validate and filter the retained visibility candidates."""

    retained: list[IPv6Candidate] = []
    family_counts: Counter[str] = Counter()
    topology_categories: Counter[str] = Counter()
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or tuple(reader.fieldnames) != EXPECTED_SOURCE_HEADER:
            raise IPv6CampaignError(
                f"{path}: unexpected header {reader.fieldnames!r}"
            )
        for source_row, row in enumerate(reader, start=2):
            family = row["family"]
            family_counts[family] += 1
            if family != "IPv6":
                continue
            if row["root_status"] != "ALLOCATED-BY-RIR":
                raise IPv6CampaignError(
                    f"{path}:{source_row}: unexpected IPv6 root status"
                )
            if row["endpoint_status"] != "ASSIGNED":
                raise IPv6CampaignError(
                    f"{path}:{source_row}: unexpected IPv6 endpoint status"
                )
            if row["path_classification"] != "registry_indirect":
                raise IPv6CampaignError(
                    f"{path}:{source_row}: expected registry_indirect"
                )
            root = ip_network(row["root_prefix"], strict=True)
            endpoint = ip_network(row["endpoint_prefix"], strict=True)
            if not isinstance(root, IPv6Network) or not isinstance(endpoint, IPv6Network):
                raise IPv6CampaignError(
                    f"{path}:{source_row}: family label is not IPv6"
                )
            if str(root) != row["root_prefix"] or str(endpoint) != row["endpoint_prefix"]:
                raise IPv6CampaignError(
                    f"{path}:{source_row}: prefix is not canonical"
                )
            if endpoint == root or not endpoint.subnet_of(root):
                raise IPv6CampaignError(
                    f"{path}:{source_row}: endpoint is not a proper descendant"
                )
            holders = _parse_origin_set(
                row["root_origins"], f"{path}:{source_row}:root_origins"
            )
            endpoints = _parse_origin_set(
                row["endpoint_origins"],
                f"{path}:{source_row}:endpoint_origins",
            )
            if len(holders) != 1 or len(endpoints) != 1:
                raise IPv6CampaignError(
                    f"{path}:{source_row}: campaign requires singleton origins"
                )
            holder_asn, endpoint_asn = holders[0], endpoints[0]
            if holder_asn == endpoint_asn:
                raise IPv6CampaignError(
                    f"{path}:{source_row}: origin sets are not disjoint"
                )
            if not all(
                is_eligible_delegated_origin(asn)
                for asn in (holder_asn, endpoint_asn)
            ):
                raise IPv6CampaignError(
                    f"{path}:{source_row}: origin is not public-AS eligible"
                )

            holder_present = holder_asn in topology_asns
            endpoint_present = endpoint_asn in topology_asns
            if holder_present and endpoint_present:
                category = "both_present"
            elif not holder_present and endpoint_present:
                category = "holder_absent"
            elif holder_present and not endpoint_present:
                category = "endpoint_absent"
            else:
                category = "both_absent"
            topology_categories[category] += 1
            if category != "both_present":
                continue
            retained.append(
                IPv6Candidate(
                    source_row=source_row,
                    root_prefix=str(root),
                    holder_asn=holder_asn,
                    endpoint_prefix=str(endpoint),
                    endpoint_asn=endpoint_asn,
                )
            )

    ipv6_rows = family_counts["IPv6"]
    if ipv6_rows != EXPECTED_IPV6_ROWS:
        raise IPv6CampaignError(
            f"IPv6 source-row drift: {ipv6_rows}, expected {EXPECTED_IPV6_ROWS}"
        )
    if len(retained) != EXPECTED_TOPOLOGY_ROWS:
        raise IPv6CampaignError(
            f"topology-eligible row drift: {len(retained)}, "
            f"expected {EXPECTED_TOPOLOGY_ROWS}"
        )
    return tuple(retained), {
        "source_family_rows": dict(sorted(family_counts.items())),
        "ipv6_rows": ipv6_rows,
        "topology_membership_categories": dict(
            sorted(topology_categories.items())
        ),
        "retained_rows": len(retained),
        "filter_rule": (
            "IPv6 registry-indirect rows with canonical proper descendants, "
            "singleton disjoint eligible origins, and both origins in the "
            "fixed AS graph"
        ),
    }


def collapse_candidate_pairs(
    candidates: Iterable[IPv6Candidate],
    degrees: Mapping[int, int],
) -> tuple[IPv6Unit, ...]:
    """Collapse repeated prefixes for the same root/holder/endpoint pair."""

    grouped: dict[tuple[str, int, int], list[IPv6Candidate]] = defaultdict(list)
    for candidate in candidates:
        grouped[
            (candidate.root_prefix, candidate.holder_asn, candidate.endpoint_asn)
        ].append(candidate)
    units: list[IPv6Unit] = []
    for pair_index, key in enumerate(sorted(grouped), start=1):
        members = sorted(
            grouped[key],
            key=lambda item: (item.source_row, item.endpoint_prefix),
        )
        selected = members[0]
        units.append(
            IPv6Unit(
                unit_id=f"ipv6-unit{pair_index:03d}",
                pair_index=pair_index,
                root_prefix=selected.root_prefix,
                holder_asn=selected.holder_asn,
                endpoint_prefix=selected.endpoint_prefix,
                endpoint_asn=selected.endpoint_asn,
                selected_source_row=selected.source_row,
                source_rows=tuple(member.source_row for member in members),
                member_endpoint_prefixes=tuple(
                    member.endpoint_prefix for member in members
                ),
                holder_degree=degrees[selected.holder_asn],
                endpoint_degree=degrees[selected.endpoint_asn],
            )
        )
    roots = {unit.root_prefix for unit in units}
    if len(units) != EXPECTED_UNIQUE_PAIRS:
        raise IPv6CampaignError(
            f"unique-pair drift: {len(units)}, expected {EXPECTED_UNIQUE_PAIRS}"
        )
    if len(roots) != EXPECTED_UNIQUE_ROOTS:
        raise IPv6CampaignError(
            f"unique-root drift: {len(roots)}, expected {EXPECTED_UNIQUE_ROOTS}"
        )
    return tuple(units)


def attach_uniform_competitors(
    units: Sequence[IPv6Unit],
    degrees: Mapping[int, int],
    *,
    seed: int = COMPETITOR_SEED,
) -> tuple[tuple[IPv6Unit, ...], dict[str, Any]]:
    """Assign one eligible unlisted origin per unit without replacement."""

    endpoints = {
        asn for unit in units for asn in (unit.holder_asn, unit.endpoint_asn)
    }
    pool = [
        asn
        for asn in degrees
        if asn not in endpoints and is_eligible_delegated_origin(asn)
    ]
    ranked = sorted(
        pool,
        key=lambda asn: (
            stable_sha256(seed, "ipv6-unlisted-origin", asn),
            asn,
        ),
    )
    if len(ranked) < len(units):
        raise IPv6CampaignError("competitor pool is smaller than the unit frame")
    selected = ranked[: len(units)]
    attached = tuple(
        replace(
            unit,
            competitor_asn=competitor,
            competitor_degree=degrees[competitor],
        )
        for unit, competitor in zip(units, selected, strict=True)
    )
    if len({unit.competitor_asn for unit in attached}) != len(attached):
        raise IPv6CampaignError("competitor assignments are not unique")
    if any(
        unit.competitor_asn in {unit.holder_asn, unit.endpoint_asn}
        for unit in attached
    ):
        raise IPv6CampaignError("a competitor equals a route endpoint")
    return attached, {
        "seed": seed,
        "selection": "global SHA-256 rank without replacement",
        "eligible_pool_after_endpoint_exclusion": len(pool),
        "excluded_endpoint_asns": len(endpoints),
        "selected": len(selected),
        "selected_asns_sha256": hashlib.sha256(
            ("\n".join(str(asn) for asn in selected) + "\n").encode("ascii")
        ).hexdigest(),
    }


def build_deployment_order(
    rov_asns: frozenset[int],
    *,
    seed: int = DEPLOYMENT_SEED,
) -> tuple[tuple[int, ...], dict[str, Any]]:
    if len(rov_asns) != 589:
        raise IPv6CampaignError(f"expected 589 fixed ROV ASes, got {len(rov_asns)}")
    values = sorted(rov_asns)
    random.Random(seed).shuffle(values)
    order = tuple(values)
    return order, {
        "strategy": "random",
        "seed": seed,
        "asns": list(order),
        "order_sha256": hashlib.sha256(
            ("\n".join(str(asn) for asn in order) + "\n").encode("ascii")
        ).hexdigest(),
        "deployment_counts": {
            str(percent): deployment_count(percent, len(order))
            for percent in DEPLOYMENT_PERCENTAGES
        },
    }


def deployment_count(percent: int, rov_count: int = 589) -> int:
    if percent not in DEPLOYMENT_PERCENTAGES:
        raise IPv6CampaignError(f"unsupported deployment percentage {percent}")
    return rov_count if percent == 100 else int(rov_count * percent / 100)


def _scenario_id(unit: IPv6Unit, lane: str, percent: int) -> str:
    return f"{unit.unit_id}__{lane}__random-{DEPLOYMENT_SEED}__pct-{percent:03d}"


def build_trial_plan(units: Sequence[IPv6Unit]) -> tuple[IPv6Trial, ...]:
    """Build ten physical trials per unique IPv6 origin pair."""

    trials: list[IPv6Trial] = []
    for unit in units:
        for lane, announcement_set, reference in (
            (B1_DELEGATE, "intended_only", "aggregate_only"),
            (B2_DELEGATE, "intended_only", "exact_endpoint"),
            (B1_COMPETITION, "competition", "aggregate_only"),
            (B2_COMPETITION, "competition", "exact_endpoint"),
        ):
            trials.append(
                IPv6Trial(
                    scenario_id=_scenario_id(unit, lane, 0),
                    unit_id=unit.unit_id,
                    pair_index=unit.pair_index,
                    lane=lane,
                    announcement_set=announcement_set,
                    policy_reference=reference,
                    deployment_percent_target=0,
                    deployment_count=0,
                    deployment_strategy="reference",
                    deployment_seed=None,
                )
            )
        for lane, announcement_set in (
            (D1_OPEN_DELEGATE, "intended_only"),
            (A1_OPEN_COMPETITION, "competition"),
        ):
            for percent in DEPLOYMENT_PERCENTAGES:
                trials.append(
                    IPv6Trial(
                        scenario_id=_scenario_id(unit, lane, percent),
                        unit_id=unit.unit_id,
                        pair_index=unit.pair_index,
                        lane=lane,
                        announcement_set=announcement_set,
                        policy_reference="open_staged",
                        deployment_percent_target=percent,
                        deployment_count=deployment_count(percent),
                        deployment_strategy="random",
                        deployment_seed=DEPLOYMENT_SEED,
                    )
                )
    if len(trials) != EXPECTED_TRIALS:
        raise IPv6CampaignError(
            f"trial-plan size {len(trials)}, expected {EXPECTED_TRIALS}"
        )
    ids = [trial.scenario_id for trial in trials]
    if len(ids) != len(set(ids)):
        raise IPv6CampaignError("trial plan contains duplicate scenario IDs")
    expected_lane_counts = {
        B1_DELEGATE: 21,
        B2_DELEGATE: 21,
        B1_COMPETITION: 21,
        B2_COMPETITION: 21,
        D1_OPEN_DELEGATE: 63,
        A1_OPEN_COMPETITION: 63,
    }
    if Counter(trial.lane for trial in trials) != Counter(expected_lane_counts):
        raise IPv6CampaignError("trial-plan lane counts differ from the contract")
    return tuple(trials)


def _phase4_ipv6_interface_check() -> dict[str, Any]:
    policy = DAROA(
        base_prefix="2001:db8::/32",
        max_length=48,
        holder_asn=3257,
        stripes=[Stripe("2001:db8::/32", {3257}, True)],
    )
    state = policy.validate_route("2001:db8:1::/48", 25973)
    if state != ValidationState.DELEGATED:
        raise IPv6CampaignError(
            f"Phase-4 IPv6 interface returned {state}, expected Delegated"
        )
    encoded = policy.serialize()
    if DAROA.deserialize(encoded) != policy:
        raise IPv6CampaignError("Phase-4 IPv6 encoding did not round-trip")
    return {
        "class": "phase4_encoding.scripts.utils.daroa.DAROA",
        "ip_version": policy.ip_version,
        "delegated_state": state.value,
        "round_trip": True,
        "sample_wire_bytes": len(encoded),
    }


def selected_units_csv(units: Sequence[IPv6Unit]) -> str:
    fieldnames = (
        "unit_id",
        "pair_index",
        "root_prefix",
        "holder_asn",
        "endpoint_prefix",
        "endpoint_asn",
        "selected_source_row",
        "source_rows",
        "member_endpoint_prefixes",
        "holder_degree",
        "endpoint_degree",
        "competitor_asn",
        "competitor_degree",
    )
    import io

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for unit in units:
        row = asdict(unit)
        row["source_rows"] = ";".join(str(value) for value in unit.source_rows)
        row["member_endpoint_prefixes"] = ";".join(unit.member_endpoint_prefixes)
        writer.writerow(row)
    return buffer.getvalue()


def build_manifest_document() -> dict[str, Any]:
    """Build the complete deterministic 210-scenario plan in memory."""

    degrees, topology_summary = load_topology_degrees()
    candidates, filter_audit = load_ipv6_candidates(set(degrees))
    units = collapse_candidate_pairs(candidates, degrees)
    units, competitor_provenance = attach_uniform_competitors(units, degrees)
    rov_asns = load_rov_asns()
    order, order_document = build_deployment_order(rov_asns)
    trials = build_trial_plan(units)
    units_csv = selected_units_csv(units)

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": utc_now(),
        "status": "planned_not_executed",
        "interpretation": (
            "IPv6 portability and sensitivity on the fixed family-neutral "
            "Phase-7 AS graph; not an IPv6-specific topology estimate"
        ),
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "bgpy_version": version("bgpy-pkg"),
        },
        "sources": {
            "visibility_candidates": file_record(SOURCE_CANDIDATES_PATH),
            "as_relationship_topology": file_record(TOPOLOGY_PATH),
            "rov_asns": file_record(ROV_JSON_PATH),
            "phase4_oracle": file_record(PHASE4_ORACLE_PATH),
            "frozen_graph_helper": file_record(
                REPOSITORY_ROOT
                / "phase7_simulation"
                / "campaign"
                / "full_graph_gate.py"
            ),
            "darov_adapter": file_record(POLICY_PATH),
            "ipv6_runner": file_record(RUNNER_PATH),
        },
        "unused_frozen_input_note": {
            "path": relative_path(PAIR_TABLE_PATH),
            "reason": "the IPv6 frame is derived from visibility_candidates.csv",
        },
        "phase4_ipv6_interface": _phase4_ipv6_interface_check(),
        "topology": topology_summary,
        "filter_audit": {
            **filter_audit,
            "topology_eligible_rows_before_pair_collapse": len(candidates),
            "unique_pairs_after_collapse": len(units),
            "rows_collapsed_as_repeated_pair_prefixes": len(candidates) - len(units),
            "unique_roots_after_collapse": len(
                {unit.root_prefix for unit in units}
            ),
            "unique_endpoint_asns_after_collapse": len(
                {unit.endpoint_asn for unit in units}
            ),
            "unique_all_endpoint_asns_after_collapse": len(
                {
                    asn
                    for unit in units
                    for asn in (unit.holder_asn, unit.endpoint_asn)
                }
            ),
            "pair_key": "(root_prefix, holder_asn, endpoint_asn)",
            "representative_rule": "lowest source_row within each pair key",
        },
        "competitor_assignment": competitor_provenance,
        "deployment_order": order_document,
        "design": {
            "units": len(units),
            "root_clusters": len({unit.root_prefix for unit in units}),
            "deployment_percentages": list(DEPLOYMENT_PERCENTAGES),
            "trials_per_unit": 10,
            "planned_trials": len(trials),
            "inference": (
                "descriptive pair-level results with root-balanced summaries; "
                "no population confidence interval"
            ),
            "competition_origin": "one fixed eligible unlisted ASN per unit",
        },
        "selected_units": [asdict(unit) for unit in units],
        "selected_units_csv_sha256": hashlib.sha256(
            units_csv.encode("utf-8")
        ).hexdigest(),
        "trial_plan": [asdict(trial) for trial in trials],
        "expected_scenario_ids_sha256": hashlib.sha256(
            ("\n".join(sorted(trial.scenario_id for trial in trials)) + "\n").encode(
                "utf-8"
            )
        ).hexdigest(),
        "deployment_order_length": len(order),
    }
    document["manifest_sha256"] = canonical_document_sha256(document)
    return document


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _json_text(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def plan_campaign(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise IPv6CampaignError(f"planning directory is not empty: {output_dir}")
    manifest = build_manifest_document()
    units = tuple(IPv6Unit(**item) for item in manifest["selected_units"])
    _atomic_write_text(output_dir / "selected_units.csv", selected_units_csv(units))
    _atomic_write_text(output_dir / "manifest.json", _json_text(manifest))
    return manifest


def load_manifest(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "manifest.json"
    if not path.is_file():
        raise IPv6CampaignError(f"missing manifest: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != SCHEMA_VERSION:
        raise IPv6CampaignError("unsupported IPv6 manifest schema")
    recorded_hash = document.get("manifest_sha256")
    if recorded_hash != canonical_document_sha256(document):
        raise IPv6CampaignError("manifest canonical hash mismatch")
    if len(document.get("selected_units", ())) != EXPECTED_UNIQUE_PAIRS:
        raise IPv6CampaignError("manifest unit count mismatch")
    if len(document.get("trial_plan", ())) != EXPECTED_TRIALS:
        raise IPv6CampaignError("manifest trial count mismatch")
    for record in document.get("sources", {}).values():
        source = REPOSITORY_ROOT / record["path"]
        if sha256_file(source) != record["sha256"]:
            raise IPv6CampaignError(f"source hash changed: {record['path']}")
    return document


def _load_existing_results(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.endswith("\n"):
                raise IPv6CampaignError(
                    f"{path}:{line_number}: truncated JSONL record"
                )
            row = json.loads(raw)
            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or scenario_id in rows:
                raise IPv6CampaignError(
                    f"{path}:{line_number}: invalid or duplicate scenario ID"
                )
            rows[scenario_id] = row
    return rows


_WORKER_ENGINE: SimulationEngine | None = None
_WORKER_ROV_ASNS: frozenset[int] = frozenset()
_WORKER_DEPLOYMENT_ORDER: tuple[int, ...] = ()
_WORKER_GRAPH_BUILD_SECONDS = 0.0
_WORKER_GRAPH_BUILD_PEAK_RSS_BYTES = 0


def _worker_init(deployment_order: tuple[int, ...]) -> None:
    global _WORKER_ENGINE
    global _WORKER_ROV_ASNS
    global _WORKER_DEPLOYMENT_ORDER
    global _WORKER_GRAPH_BUILD_SECONDS
    global _WORKER_GRAPH_BUILD_PEAK_RSS_BYTES

    started = perf_counter()
    with PeakRSSMonitor() as memory:
        graph = build_fixed_graph()
        _WORKER_ENGINE = SimulationEngine(graph)
    _WORKER_ROV_ASNS = load_rov_asns()
    _WORKER_DEPLOYMENT_ORDER = deployment_order
    _WORKER_GRAPH_BUILD_SECONDS = perf_counter() - started
    _WORKER_GRAPH_BUILD_PEAK_RSS_BYTES = memory.peak_bytes


def _execute_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if _WORKER_ENGINE is None:
        raise RuntimeError("worker engine was not initialized")
    unit = IPv6Unit(**payload["unit"])
    trial = IPv6Trial(**payload["trial"])
    pair = unit.to_pair_spec()
    spec = ExecutionSpec(
        pair=pair,
        lane=trial.lane,
        deployment_percent=trial.deployment_percent_target,
        deployment_strategy=trial.deployment_strategy,
        scenario_id=trial.scenario_id,
    )
    da_asns = frozenset(_WORKER_DEPLOYMENT_ORDER[: trial.deployment_count])
    result = run_trial(
        _WORKER_ENGINE,
        spec,
        rov_asns=_WORKER_ROV_ASNS,
        da_asns=da_asns,
    )
    result.update(
        {
            "unit_id": unit.unit_id,
            "address_family": "IPv6",
            "announcement_set": trial.announcement_set,
            "policy_reference": trial.policy_reference,
            "deployment_seed": trial.deployment_seed,
            "worker_pid": os.getpid(),
            "worker_graph_build_seconds": _WORKER_GRAPH_BUILD_SECONDS,
            "worker_graph_build_peak_rss_bytes": (
                _WORKER_GRAPH_BUILD_PEAK_RSS_BYTES
            ),
        }
    )
    return result


def _write_checkpoint(
    output_dir: Path,
    *,
    manifest: Mapping[str, Any],
    completed: int,
    run_wall_seconds: float,
    workers: int,
    status: str,
) -> None:
    _atomic_write_text(
        output_dir / "checkpoint.json",
        _json_text(
            {
                "schema_version": SCHEMA_VERSION,
                "status": status,
                "manifest_sha256": manifest["manifest_sha256"],
                "planned_trials": EXPECTED_TRIALS,
                "completed_trials": completed,
                "remaining_trials": EXPECTED_TRIALS - completed,
                "workers": workers,
                "run_wall_seconds": run_wall_seconds,
                "updated_at_utc": utc_now(),
            }
        ),
    )


def run_campaign(
    output_dir: Path,
    *,
    workers: int,
    max_new_trials: int | None = None,
) -> dict[str, Any]:
    """Run pending planned trials once; failures are never retried automatically."""

    if workers < 1:
        raise IPv6CampaignError("workers must be positive")
    failure_path = output_dir / "failures.jsonl"
    if failure_path.exists() and failure_path.stat().st_size:
        raise IPv6CampaignError(
            "nonempty failure history blocks automatic retry; inspect it first"
        )
    manifest = load_manifest(output_dir)
    units = {
        item["unit_id"]: IPv6Unit(**item) for item in manifest["selected_units"]
    }
    trials = [IPv6Trial(**item) for item in manifest["trial_plan"]]
    expected_ids = {trial.scenario_id for trial in trials}
    result_path = output_dir / "raw_scenarios.jsonl"
    existing = _load_existing_results(result_path)
    unknown = set(existing).difference(expected_ids)
    if unknown:
        raise IPv6CampaignError(f"results contain unknown scenario IDs: {sorted(unknown)[:3]}")
    pending = [trial for trial in trials if trial.scenario_id not in existing]
    if max_new_trials is not None:
        if max_new_trials < 1:
            raise IPv6CampaignError("max_new_trials must be positive")
        pending = pending[:max_new_trials]
    deployment_order = tuple(manifest["deployment_order"]["asns"])
    started = perf_counter()
    _write_checkpoint(
        output_dir,
        manifest=manifest,
        completed=len(existing),
        run_wall_seconds=0.0,
        workers=workers,
        status="running" if pending else "complete",
    )
    if not pending:
        return json.loads((output_dir / "checkpoint.json").read_text())

    payloads = [
        {"unit": asdict(units[trial.unit_id]), "trial": asdict(trial)}
        for trial in pending
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with result_path.open("a", encoding="utf-8") as result_handle:
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_worker_init,
                initargs=(deployment_order,),
            ) as executor:
                future_to_id = {
                    executor.submit(_execute_payload, payload): payload["trial"][
                        "scenario_id"
                    ]
                    for payload in payloads
                }
                for future in as_completed(future_to_id):
                    scenario_id = future_to_id[future]
                    try:
                        row = future.result()
                    except Exception as exc:
                        for other in future_to_id:
                            other.cancel()
                        failure = {
                            "scenario_id": scenario_id,
                            "failed_at_utc": utc_now(),
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                            "retry_performed": False,
                        }
                        with failure_path.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(failure, sort_keys=True) + "\n")
                            handle.flush()
                            os.fsync(handle.fileno())
                        raise
                    result_handle.write(json.dumps(row, sort_keys=True) + "\n")
                    result_handle.flush()
                    os.fsync(result_handle.fileno())
                    existing[row["scenario_id"]] = row
                    _write_checkpoint(
                        output_dir,
                        manifest=manifest,
                        completed=len(existing),
                        run_wall_seconds=perf_counter() - started,
                        workers=workers,
                        status="running",
                    )
    except Exception:
        _write_checkpoint(
            output_dir,
            manifest=manifest,
            completed=len(_load_existing_results(result_path)),
            run_wall_seconds=perf_counter() - started,
            workers=workers,
            status="failed",
        )
        raise

    completed = len(_load_existing_results(result_path))
    status = "complete" if completed == EXPECTED_TRIALS else "in_progress"
    _write_checkpoint(
        output_dir,
        manifest=manifest,
        completed=completed,
        run_wall_seconds=perf_counter() - started,
        workers=workers,
        status=status,
    )
    return json.loads((output_dir / "checkpoint.json").read_text())


def campaign_status(output_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(output_dir)
    completed = len(_load_existing_results(output_dir / "raw_scenarios.jsonl"))
    checkpoint_path = output_dir / "checkpoint.json"
    checkpoint = (
        json.loads(checkpoint_path.read_text()) if checkpoint_path.exists() else {}
    )
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "planned_trials": EXPECTED_TRIALS,
        "completed_trials": completed,
        "remaining_trials": EXPECTED_TRIALS - completed,
        "checkpoint_status": checkpoint.get("status", "not_started"),
        "failure_history": (
            (output_dir / "failures.jsonl").exists()
            and (output_dir / "failures.jsonl").stat().st_size > 0
        ),
    }


def _destination_fraction(row: Mapping[str, Any], outcome: str) -> float:
    return float(row["outcomes"]["destination"]["fractions"][outcome])


def analyze_campaign(output_dir: Path) -> dict[str, Any]:
    """Validate all planned rows and emit descriptive pair/root summaries."""

    manifest = load_manifest(output_dir)
    rows = _load_existing_results(output_dir / "raw_scenarios.jsonl")
    expected_ids = {item["scenario_id"] for item in manifest["trial_plan"]}
    if set(rows) != expected_ids:
        raise IPv6CampaignError(
            f"analysis requires {len(expected_ids)} exact rows, found {len(rows)}"
        )
    by_unit_lane_percent: dict[tuple[str, str, int], dict[str, Any]] = {}
    for trial_item in manifest["trial_plan"]:
        trial = IPv6Trial(**trial_item)
        row = rows[trial.scenario_id]
        denominator = row["outcomes"]["denominator_asns"]
        for level in ("child", "destination"):
            if sum(row["outcomes"][level]["counts"].values()) != denominator:
                raise IPv6CampaignError(
                    f"{trial.scenario_id}: {level} partition mismatch"
                )
        by_unit_lane_percent[
            (trial.unit_id, trial.lane, trial.deployment_percent_target)
        ] = row

    pair_effects: list[dict[str, Any]] = []
    zero_equalities = 0
    exact_equalities = 0
    for unit_item in manifest["selected_units"]:
        unit = IPv6Unit(**unit_item)
        key = unit.unit_id
        b1_intended = by_unit_lane_percent[(key, B1_DELEGATE, 0)]
        b2_intended = by_unit_lane_percent[(key, B2_DELEGATE, 0)]
        b1_competition = by_unit_lane_percent[(key, B1_COMPETITION, 0)]
        d0 = by_unit_lane_percent[(key, D1_OPEN_DELEGATE, 0)]
        d50 = by_unit_lane_percent[(key, D1_OPEN_DELEGATE, 50)]
        d100 = by_unit_lane_percent[(key, D1_OPEN_DELEGATE, 100)]
        a0 = by_unit_lane_percent[(key, A1_OPEN_COMPETITION, 0)]
        a50 = by_unit_lane_percent[(key, A1_OPEN_COMPETITION, 50)]
        a100 = by_unit_lane_percent[(key, A1_OPEN_COMPETITION, 100)]
        if d0["outcomes"] != b1_intended["outcomes"]:
            raise IPv6CampaignError(f"{key}: D1@0 differs from intended B1")
        if a0["outcomes"] != b1_competition["outcomes"]:
            raise IPv6CampaignError(f"{key}: A1@0 differs from competition B1")
        zero_equalities += 2
        if d100["outcomes"] != b2_intended["outcomes"]:
            raise IPv6CampaignError(f"{key}: D1@100 differs from intended B2")
        exact_equalities += 1
        pair_effects.append(
            {
                "unit_id": key,
                "root_prefix": unit.root_prefix,
                "holder_asn": unit.holder_asn,
                "endpoint_asn": unit.endpoint_asn,
                "competitor_asn": unit.competitor_asn,
                "delivery_gain_50_pp": 100
                * (
                    _destination_fraction(d50, "delegate")
                    - _destination_fraction(b1_intended, "delegate")
                ),
                "delivery_gain_100_pp": 100
                * (
                    _destination_fraction(d100, "delegate")
                    - _destination_fraction(b1_intended, "delegate")
                ),
                "exposure_change_50_pp": 100
                * (
                    _destination_fraction(a50, "attacker")
                    - _destination_fraction(b1_competition, "attacker")
                ),
                "exposure_change_100_pp": 100
                * (
                    _destination_fraction(a100, "attacker")
                    - _destination_fraction(b1_competition, "attacker")
                ),
            }
        )

    roots: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in pair_effects:
        roots[row["root_prefix"]].append(row)
    metrics = (
        "delivery_gain_50_pp",
        "delivery_gain_100_pp",
        "exposure_change_50_pp",
        "exposure_change_100_pp",
    )
    summaries: dict[str, Any] = {}
    for metric in metrics:
        pair_values = [float(row[metric]) for row in pair_effects]
        root_values = [
            statistics.fmean(float(row[metric]) for row in root_rows)
            for root_rows in roots.values()
        ]
        summaries[metric] = {
            "pair_weighted_mean": statistics.fmean(pair_values),
            "pair_median": statistics.median(pair_values),
            "root_balanced_mean": statistics.fmean(root_values),
            "root_median": statistics.median(root_values),
            "root_min": min(root_values),
            "root_max": max(root_values),
        }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "VERIFIED_DESCRIPTIVE",
        "manifest_sha256": manifest["manifest_sha256"],
        "raw_rows": len(rows),
        "pairs": len(pair_effects),
        "root_clusters": len(roots),
        "zero_upgrade_equalities": zero_equalities,
        "open_100_equals_exact_intended": exact_equalities,
        "inference": "descriptive only; no population confidence interval",
        "metrics": summaries,
    }
    analysis_dir = output_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(analysis_dir / "summary.json", _json_text(summary))
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        dir=analysis_dir,
        prefix=".pair_effects.",
        delete=False,
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=tuple(pair_effects[0]))
        writer.writeheader()
        writer.writerows(pair_effects)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, analysis_dir / "pair_effects.csv")
    return summary


def run_smoke(output_dir: Path) -> dict[str, Any]:
    """Run exactly one full-graph IPv6 open-scope trial."""

    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise IPv6CampaignError(f"smoke directory is not empty: {output_dir}")
    manifest = build_manifest_document()
    unit = IPv6Unit(**manifest["selected_units"][0])
    trial = next(
        IPv6Trial(**item)
        for item in manifest["trial_plan"]
        if item["unit_id"] == unit.unit_id
        and item["lane"] == D1_OPEN_DELEGATE
        and item["deployment_percent_target"] == 100
    )
    pair = unit.to_pair_spec()
    boundary_checks = check_policy_boundaries(pair)
    graph_started = perf_counter()
    rss_before = current_rss_bytes()
    with PeakRSSMonitor() as graph_memory:
        graph = build_fixed_graph()
        engine = SimulationEngine(graph)
    graph_seconds = perf_counter() - graph_started
    rov_asns = load_rov_asns()
    spec = ExecutionSpec(
        pair=pair,
        lane=trial.lane,
        deployment_percent=trial.deployment_percent_target,
        deployment_strategy=trial.deployment_strategy,
        scenario_id=f"smoke__{trial.scenario_id}",
    )
    result = run_trial(
        engine,
        spec,
        rov_asns=rov_asns,
        da_asns=rov_asns,
    )
    if result["policy_assignment_counts"]["darov"] != len(rov_asns):
        raise IPv6CampaignError("smoke did not assign all fixed ROV ASes to DAROV")
    smoke = {
        "schema_version": SCHEMA_VERSION,
        "status": "success",
        "created_at_utc": utc_now(),
        "formal_campaign_started": False,
        "planned_formal_scenarios": EXPECTED_TRIALS,
        "manifest_snapshot_sha256": manifest["manifest_sha256"],
        "unit": asdict(unit),
        "trial": asdict(trial),
        "boundary_checks": boundary_checks,
        "graph": {
            "asns": len(graph),
            "build_seconds": graph_seconds,
            "rss_before_bytes": rss_before,
            "build_peak_rss_bytes": graph_memory.peak_bytes,
        },
        "result": result,
    }
    _atomic_write_text(output_dir / "smoke.json", _json_text(smoke))
    _atomic_write_text(
        output_dir / "manifest_snapshot.json", _json_text(manifest)
    )
    return smoke


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="freeze the 210-scenario plan")
    plan.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)

    run = subparsers.add_parser("run", help="run pending planned scenarios")
    run.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    run.add_argument("--workers", type=int, default=8)
    run.add_argument("--max-new-trials", type=int)

    status = subparsers.add_parser("status", help="report campaign progress")
    status.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)

    analyze = subparsers.add_parser("analyze", help="validate and summarize results")
    analyze.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)

    smoke = subparsers.add_parser("smoke", help="run one full-graph IPv6 trial")
    smoke.add_argument("--output-dir", type=Path, default=DEFAULT_SMOKE_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        result = plan_campaign(args.output_dir)
    elif args.command == "run":
        result = run_campaign(
            args.output_dir,
            workers=args.workers,
            max_new_trials=args.max_new_trials,
        )
    elif args.command == "status":
        result = campaign_status(args.output_dir)
    elif args.command == "analyze":
        result = analyze_campaign(args.output_dir)
    elif args.command == "smoke":
        result = run_smoke(args.output_dir)
    else:  # pragma: no cover
        raise AssertionError(args.command)
    print(_json_text(result), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
