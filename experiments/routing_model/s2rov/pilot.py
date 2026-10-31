"""Deterministic small-graph S2-ROV pilot using BGPy 13.0.10."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from importlib.metadata import version
from ipaddress import ip_network
from pathlib import Path
from time import perf_counter
from typing import Iterable, Sequence

from frozendict import frozendict
from roa_checker import ROA

from bgpy.as_graphs import (
    ASGraph,
    ASGraphInfo,
    CustomerProviderLink,
    PeerLink,
)
from bgpy.shared.enums import Relationships
from bgpy.simulation_engine import Announcement, BGP, ROV, SimulationEngine
from bgpy.simulation_framework import Scenario, ScenarioConfig

from implementation.daroa_codec.scripts.utils.daroa import DAROA, Stripe

from .policy import S2ROV


AGGREGATE = "10.0.0.0/16"
CHILD = "10.0.1.0/24"
UNRELATED = "192.0.2.0/24"

HOLDER_ASN = 100
DELEGATE_ASN = 200
ATTACKER_ASN = 300

# These four nodes model the fixed measured-ROV set in miniature.  Only this
# set is upgraded during the pilot; all other ASes remain ordinary BGP.
ROV_ASNS = frozenset({10, 11, 20, 21})
MIXED_DA_ASNS = frozenset({11, 21})
FULL_DA_ASNS = ROV_ASNS

ANNOUNCEMENT_KEYS = ("aggregate", "delegate", "attacker")


def make_open_policy() -> DAROA:
    """Return the pilot's holder-signed open policy."""

    return DAROA(
        base_prefix=AGGREGATE,
        max_length=24,
        holder_asn=HOLDER_ASN,
        stripes=[Stripe(AGGREGATE, {HOLDER_ASN}, True)],
    )


def make_policy_with_exact_overlay() -> DAROA:
    """Return an open base plus an ordinary exact child ROA."""

    return DAROA(
        base_prefix=AGGREGATE,
        max_length=24,
        holder_asn=HOLDER_ASN,
        stripes=[
            Stripe(AGGREGATE, {HOLDER_ASN}, True),
            Stripe(CHILD, {DELEGATE_ASN}, False),
        ],
    )


# Compatibility alias for archived routing-model callers.  Under the current
# conventional-ROV-first profile, the unmarked child is an exact ROA and does
# not close or shadow the covering OpenScope marker.
make_policy_with_closed_child = make_policy_with_exact_overlay


def build_pilot_graph() -> ASGraph:
    """Build a deterministic 11-AS Gao--Rexford test topology.

    AS10 and AS20 are peers.  The intended delegate and attacker are reached
    through separate two-hop provider branches, making partial DA deployment
    and equal-prefix competition visible without Internet-scale inputs.
    """

    provider_customer_pairs = (
        (10, HOLDER_ASN),
        (10, 11),
        (11, DELEGATE_ASN),
        (20, 21),
        (21, ATTACKER_ASN),
        (10, 1),
        (20, 2),
        (11, 3),
        (21, 4),
    )
    graph_info = ASGraphInfo(
        customer_provider_links=frozenset(
            CustomerProviderLink(provider_asn=provider, customer_asn=customer)
            for provider, customer in provider_customer_pairs
        ),
        peer_links=frozenset({PeerLink(10, 20)}),
        input_clique_asns=frozenset({10, 20}),
    )
    return ASGraph(graph_info, store_customer_cone_size=False)


def build_announcements(
    *,
    include_attacker: bool,
    announcement_order: Sequence[str] | None = None,
) -> tuple[Announcement, ...]:
    """Build origin announcements in an explicitly controlled seed order."""

    announcement_map = {
        "aggregate": _origin_announcement(AGGREGATE, HOLDER_ASN),
        "delegate": _origin_announcement(CHILD, DELEGATE_ASN),
        "attacker": _origin_announcement(CHILD, ATTACKER_ASN),
    }
    expected = (
        ANNOUNCEMENT_KEYS if include_attacker else ANNOUNCEMENT_KEYS[:2]
    )
    order = tuple(announcement_order) if announcement_order else expected
    if len(order) != len(expected) or set(order) != set(expected):
        raise ValueError(
            f"announcement order must contain each of {expected!r} exactly once"
        )
    return tuple(announcement_map[key] for key in order)


def _origin_announcement(prefix: str, asn: int) -> Announcement:
    return Announcement(
        prefix=prefix,
        as_path=(asn,),
        next_hop_asn=asn,
        seed_asn=asn,
        recv_relationship=Relationships.ORIGIN,
    )


def run_trial(
    *,
    da_aware_asns: Iterable[int],
    include_attacker: bool,
    announcement_order: Sequence[str] | None = None,
    enable_s2rov: bool = True,
    daroa: DAROA | None = None,
) -> dict[str, object]:
    """Run one deterministic BGPy trial and return its outcome partitions."""

    started = perf_counter()
    da_set = frozenset(da_aware_asns)
    if not da_set.issubset(ROV_ASNS):
        raise ValueError("DA-aware ASes must be a subset of the pilot ROV set")
    if da_set and not enable_s2rov:
        raise ValueError("conventional ROV baseline cannot contain DA-aware ASes")

    policy = daroa or make_open_policy()
    S2ROV.configure(policy)
    graph = build_pilot_graph()
    engine = SimulationEngine(graph)

    policy_by_asn: dict[int, type[BGP]] = {}
    for asn in ROV_ASNS:
        policy_by_asn[asn] = S2ROV if enable_s2rov and asn in da_set else ROV

    announcements = build_announcements(
        include_attacker=include_attacker,
        announcement_order=announcement_order,
    )
    aggregate_roa = ROA(
        ip_network(AGGREGATE),
        HOLDER_ASN,
        max_length=ip_network(AGGREGATE).prefixlen,
    )
    scenario_config = ScenarioConfig(
        ScenarioCls=Scenario,
        BasePolicyCls=BGP,
        AdoptPolicyCls=BGP,
        override_attacker_asns=frozenset({ATTACKER_ASN}),
        override_victim_asns=frozenset({HOLDER_ASN}),
        override_adopting_asns=frozenset(),
        override_announcements=announcements,
        override_roas=(aggregate_roa,),
        hardcoded_asn_cls_dict=frozendict(policy_by_asn),
    )
    scenario = Scenario(scenario_config=scenario_config, engine=engine)
    scenario.setup_engine(engine)
    engine.run(propagation_round=0, scenario=scenario)

    result = analyze_engine(engine)
    result.update(
        {
            "da_aware_asns": sorted(da_set),
            "legacy_rov_asns": sorted(ROV_ASNS - da_set),
            "announcement_order": list(
                announcement_order
                or (
                    ANNOUNCEMENT_KEYS
                    if include_attacker
                    else ANNOUNCEMENT_KEYS[:2]
                )
            ),
            "include_attacker": include_attacker,
            "elapsed_ms": round((perf_counter() - started) * 1000, 3),
        }
    )
    return result


def analyze_engine(engine: SimulationEngine) -> dict[str, object]:
    """Compute exact control-plane and destination-outcome partitions."""

    asns = tuple(sorted(engine.as_graph.as_dict))
    child_by_asn: dict[str, str] = {}
    child_paths: dict[str, list[int] | None] = {}
    control_counts = {
        "child_selected_delegate": 0,
        "child_selected_attacker": 0,
        "child_absent": 0,
    }

    for asn in asns:
        ann = engine.as_graph.as_dict[asn].policy.local_rib.get(CHILD)
        if ann is None:
            outcome = "child_absent"
            child_paths[str(asn)] = None
        elif ann.origin == DELEGATE_ASN:
            outcome = "child_selected_delegate"
            child_paths[str(asn)] = list(ann.as_path)
        elif ann.origin == ATTACKER_ASN:
            outcome = "child_selected_attacker"
            child_paths[str(asn)] = list(ann.as_path)
        else:
            raise RuntimeError(f"unexpected child origin AS{ann.origin} at AS{asn}")
        child_by_asn[str(asn)] = outcome
        control_counts[outcome] += 1

    destination_by_asn = {
        str(asn): _trace_destination(engine, asn) for asn in asns
    }
    destination_counts = {
        key: sum(outcome == key for outcome in destination_by_asn.values())
        for key in (
            "delegate_delivery",
            "attacker_delivery",
            "holder_fallback",
            "disconnected",
            "forwarding_loop",
        )
    }

    _assert_partition(control_counts, len(asns), "control-plane")
    _assert_partition(destination_counts, len(asns), "destination")

    policy_assignments = {
        str(asn): engine.as_graph.as_dict[asn].policy.name for asn in asns
    }
    return {
        "num_ases": len(asns),
        "policy_assignments": policy_assignments,
        "control_plane": {
            "counts": control_counts,
            "fractions": _fractions(control_counts, len(asns)),
            "per_as": child_by_asn,
            "selected_paths": child_paths,
        },
        "destination_outcomes": {
            "counts": destination_counts,
            "fractions": _fractions(destination_counts, len(asns)),
            "per_as": destination_by_asn,
        },
    }


def _trace_destination(engine: SimulationEngine, start_asn: int) -> str:
    """Follow per-hop longest-prefix forwarding for an address in ``CHILD``."""

    current = start_asn
    visited: set[int] = set()
    for _ in range(len(engine.as_graph.as_dict) + 1):
        if current in visited:
            return "forwarding_loop"
        visited.add(current)
        policy = engine.as_graph.as_dict[current].policy
        ann = policy.local_rib.get(CHILD) or policy.local_rib.get(AGGREGATE)
        if ann is None:
            return "disconnected"
        if current == ann.origin:
            if current == DELEGATE_ASN:
                return "delegate_delivery"
            if current == ATTACKER_ASN:
                return "attacker_delivery"
            if current == HOLDER_ASN:
                return "holder_fallback"
            raise RuntimeError(f"unexpected destination origin AS{current}")
        next_hop = ann.next_hop_asn
        if next_hop not in engine.as_graph.as_dict:
            return "disconnected"
        current = next_hop
    return "forwarding_loop"


def _assert_partition(counts: dict[str, int], denominator: int, label: str) -> None:
    if sum(counts.values()) != denominator:
        raise RuntimeError(
            f"{label} partition sums to {sum(counts.values())}, expected {denominator}"
        )


def _fractions(counts: dict[str, int], denominator: int) -> dict[str, float]:
    return {key: round(value / denominator, 6) for key, value in counts.items()}


def run_pilot() -> dict[str, object]:
    """Run the six small lanes used to validate the routing-model implementation."""

    started = perf_counter()
    deployment_sets = {
        "rov_0pct": frozenset(),
        "mixed_50pct": MIXED_DA_ASNS,
        "s2rov_100pct": FULL_DA_ASNS,
    }
    runs: dict[str, object] = {}
    for lane, include_attacker in (
        ("delegate_only", False),
        ("equal_prefix_competition", True),
    ):
        for deployment, da_asns in deployment_sets.items():
            runs[f"{lane}__{deployment}"] = run_trial(
                da_aware_asns=da_asns,
                include_attacker=include_attacker,
            )

    forward = run_trial(
        da_aware_asns=FULL_DA_ASNS,
        include_attacker=True,
        announcement_order=ANNOUNCEMENT_KEYS,
    )
    reverse = run_trial(
        da_aware_asns=FULL_DA_ASNS,
        include_attacker=True,
        announcement_order=tuple(reversed(ANNOUNCEMENT_KEYS)),
    )
    order_invariant = _stable_outcomes(forward) == _stable_outcomes(reverse)
    if not order_invariant:
        raise RuntimeError("announcement input order changed the pilot outcome")

    policy = make_open_policy()
    semantic_states = {
        "holder_aggregate": policy.validate_route(AGGREGATE, HOLDER_ASN).value,
        "delegate_child": policy.validate_route(CHILD, DELEGATE_ASN).value,
        "attacker_same_child": policy.validate_route(CHILD, ATTACKER_ASN).value,
        "attacker_exact_aggregate": policy.validate_route(
            AGGREGATE, ATTACKER_ASN
        ).value,
        "unrelated": policy.validate_route(UNRELATED, ATTACKER_ASN).value,
    }

    return {
        "schema_version": 1,
        "status": "success",
        "engine": {
            "name": "BGPy",
            "version": version("bgpy_pkg"),
            "vendor_modified": False,
        },
        "semantic_oracle": "implementation/daroa_codec/scripts/utils/daroa.py",
        "scenario": {
            "aggregate": AGGREGATE,
            "child": CHILD,
            "holder_asn": HOLDER_ASN,
            "delegate_asn": DELEGATE_ASN,
            "attacker_asn": ATTACKER_ASN,
            "rov_asns": sorted(ROV_ASNS),
            "mixed_da_asns": sorted(MIXED_DA_ASNS),
            "as_count": len(build_pilot_graph()),
            "semantic_states": semantic_states,
        },
        "checks": {
            "announcement_order_invariant": order_invariant,
            "control_and_destination_partitions_complete": True,
        },
        "runs": runs,
        "execution": {
            "total_elapsed_ms": round((perf_counter() - started) * 1000, 3),
            "exceptions": [],
        },
    }


def _stable_outcomes(result: dict[str, object]) -> tuple[object, object, object]:
    return (
        result["policy_assignments"],
        result["control_plane"],
        result["destination_outcomes"],
    )


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/routing_model/results/pilot/pilot.json"),
        help="JSON result path",
    )
    args = parser.parse_args(argv)
    command = shlex.join(
        [
            sys.executable,
            "-m",
            "experiments.routing_model.s2rov.pilot",
            *(argv or sys.argv[1:]),
        ]
    )
    started = perf_counter()
    try:
        payload = run_pilot()
        execution = payload["execution"]
        assert isinstance(execution, dict)
        execution["command"] = command
        execution["wall_elapsed_ms"] = round((perf_counter() - started) * 1000, 3)
        _write_json(args.output, payload)
    except Exception as exc:
        failure = {
            "schema_version": 1,
            "status": "failed",
            "execution": {
                "command": command,
                "wall_elapsed_ms": round((perf_counter() - started) * 1000, 3),
                "exceptions": [
                    {"type": type(exc).__name__, "message": str(exc)}
                ],
            },
        }
        _write_json(args.output, failure)
        raise

    print(f"wrote {args.output}")
    print(f"pilot wall time: {payload['execution']['wall_elapsed_ms']} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
