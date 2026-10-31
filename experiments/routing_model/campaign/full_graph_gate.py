"""Run the deterministic Internet-scale BGPy resource-gate pilot.

The gate deliberately uses only ten mechanically selected origin-divergence
pairs.  They are simulation inputs, not evidence of real-world delegation.
The fixed AS graph and one :class:`SimulationEngine` are built once; BGPy's
``engine.setup`` replaces every per-AS policy and clears its routing state
before each trial.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import shlex
import signal
import subprocess
import sys
import threading
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from functools import cached_property
from importlib.metadata import version
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from statistics import fmean
from time import perf_counter
from typing import Any, Iterable, Iterator, Mapping, Sequence

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

from implementation.daroa_codec.scripts.utils.daroa import (
    DAROA,
    Stripe,
    ValidationState,
    is_eligible_delegated_origin,
)
from experiments.routing_model.s2rov.policy import S2ROV


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INPUT_DIR = REPOSITORY_ROOT / "experiments" / "routing_model" / "data" / "inputs"
TOPOLOGY_PATH = INPUT_DIR / "as-rel-fixed.txt"
CANDIDATES_PATH = INPUT_DIR / "origin_divergence_candidates.csv"
PAIR_TABLE_PATH = INPUT_DIR / "holder_delegate_pairs.csv"
ROV_JSON_PATH = INPUT_DIR / "rov_ases.json"
ROV_TEXT_PATH = INPUT_DIR / "rov_ases.txt"
POLICY_PATH = REPOSITORY_ROOT / "experiments" / "routing_model" / "s2rov" / "policy.py"
DAROA_CODEC_ORACLE_PATH = (
    REPOSITORY_ROOT / "implementation" / "daroa_codec" / "scripts" / "utils" / "daroa.py"
)
VENDOR_PATH = REPOSITORY_ROOT / "experiments" / "routing_model" / "vendor" / "bgpy"

PAIR_COUNT = 10
RANDOM_SEED = 20260804
ROV_COUNT = 589
DEPLOYMENT_PERCENTAGES = (0, 5, 100)
SINGLE_TRIAL_LIMIT_SECONDS = 60.0
PEAK_RSS_LIMIT_BYTES = 8 * 1024**3

CHILD_OUTCOMES = ("delegate", "attacker", "absent")
DESTINATION_OUTCOMES = (
    "delegate",
    "attacker",
    "holder_fallback",
    "disconnected",
    "loop",
)

B1_DELEGATE = "B1_delegate_only"
B2_DELEGATE = "B2_exact_delegate_only"
B1_COMPETITION = "B1_competition"
B2_COMPETITION = "B2_exact_competition"
D1_OPEN_DELEGATE = "D1_open_delegate_only"
A1_OPEN_COMPETITION = "A1_open_competition"
BASELINE_LANES = frozenset(
    {B1_DELEGATE, B2_DELEGATE, B1_COMPETITION, B2_COMPETITION}
)
STAGED_LANES = frozenset({D1_OPEN_DELEGATE, A1_OPEN_COMPETITION})

SELECTION_RULE = (
    "Retain IPv4 candidate rows whose holder and delegate are public-AS "
    "eligible and present in the fixed graph. Collapse to unique "
    "holder-delegate pairs, choosing each pair's lowest source_row. Sort "
    "pairs by holder_degree+delegate_degree (then maximum endpoint degree, "
    "holder ASN, delegate ASN), and take the midpoint item from each of ten "
    "equal-rank bins. This stratifies topology degree; it does not infer or "
    "claim real delegation."
)
ATTACKER_RULE = (
    "Alternate five edge attackers (total degree exactly one) and five "
    "high-degree attackers (top one percent of eligible ASes by total "
    "degree). Exclude all selected holders/delegates, sample without "
    "replacement from ASN-sorted pools using random.Random(20260804), and "
    "require the DAROA-encoding public-origin eligibility gate."
)


class InputError(ValueError):
    """Raised when a pinned campaign input violates its contract."""


class ResourceGateStop(RuntimeError):
    """Raised once the declared time or memory gate is crossed."""


class TrialTimeout(ResourceGateStop):
    """Raised by the hard per-trial wall-clock alarm."""


@dataclass(frozen=True)
class CandidateRow:
    """One mechanically retained origin-divergence observation."""

    source_row: int
    root_prefix: str
    holder_asn: int
    leaf_prefix: str
    delegate_asn: int


@dataclass(frozen=True)
class PairSpec:
    """One deterministic resource-gate scenario input."""

    pair_index: int
    source_row: int
    root_prefix: str
    holder_asn: int
    leaf_prefix: str
    delegate_asn: int
    holder_degree: int
    delegate_degree: int
    degree_bin: int
    attacker_asn: int
    attacker_class: str
    attacker_degree: int


@dataclass(frozen=True)
class TrialSpec:
    """One BGPy propagation trial."""

    pair: PairSpec
    lane: str
    deployment_percent: int
    deployment_strategy: str = "degree"

    @property
    def scenario_id(self) -> str:
        return (
            f"pair{self.pair.pair_index:02d}__{self.lane}__"
            f"degree_{self.deployment_percent:03d}pct"
        )


class FixedDeploymentScenario(Scenario):
    """Scenario whose endpoints never override the explicit policy map.

    Stock BGPy makes a victim an adopter and an attacker a non-adopter.  That
    behavior would silently change the fixed 589-AS ROV baseline when an
    endpoint belongs to it, so the campaign disables both endpoint defaults.
    """

    @cached_property
    def _default_adopters(self) -> frozenset[int]:
        return frozenset()

    @cached_property
    def _default_non_adopters(self) -> frozenset[int]:
        return frozenset()

    @property
    def untracked_asns(self) -> frozenset[int]:
        return frozenset()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_value(args: Sequence[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def load_rov_asns(path: Path = ROV_JSON_PATH) -> frozenset[int]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("label") != "hlavacek_589":
        raise InputError("ROV JSON must be the prepared hlavacek_589 document")
    raw = document.get("rov_ases")
    if not isinstance(raw, list) or any(
        isinstance(asn, bool) or not isinstance(asn, int) for asn in raw
    ):
        raise InputError("rov_ases must be a JSON list of integer ASNs")
    result = frozenset(raw)
    if len(raw) != ROV_COUNT or len(result) != ROV_COUNT:
        raise InputError(f"expected {ROV_COUNT} unique ROV ASNs")
    return result


def load_candidate_rows(path: Path = CANDIDATES_PATH) -> tuple[CandidateRow, ...]:
    rows: list[CandidateRow] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "source_row",
            "root_prefix",
            "holder_asn",
            "leaf_prefix",
            "delegate_asn",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise InputError(f"candidate CSV is missing columns {sorted(required)}")
        for raw in reader:
            root = ip_network(raw["root_prefix"], strict=True)
            leaf = ip_network(raw["leaf_prefix"], strict=True)
            if not isinstance(root, IPv4Network) or not isinstance(leaf, IPv4Network):
                continue
            if leaf == root or not leaf.subnet_of(root):
                raise InputError("candidate leaf must be a proper root descendant")
            rows.append(
                CandidateRow(
                    source_row=int(raw["source_row"]),
                    root_prefix=str(root),
                    holder_asn=int(raw["holder_asn"]),
                    leaf_prefix=str(leaf),
                    delegate_asn=int(raw["delegate_asn"]),
                )
            )
    if not rows:
        raise InputError("candidate CSV contains no IPv4 rows")
    return tuple(rows)


def build_fixed_graph(path: Path = TOPOLOGY_PATH) -> ASGraph:
    """Parse the pinned three-column relationship file into one BGPy graph."""

    cp_links: set[CustomerProviderLink] = set()
    peer_links: set[PeerLink] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            fields = raw.rstrip("\n").split("|")
            if len(fields) != 3:
                raise InputError(
                    f"{path}:{line_number}: expected asn1|asn2|relationship"
                )
            try:
                asn1, asn2 = int(fields[0]), int(fields[1])
            except ValueError as exc:
                raise InputError(f"{path}:{line_number}: non-integer ASN") from exc
            if asn1 <= 0 or asn2 <= 0 or asn1 == asn2:
                raise InputError(f"{path}:{line_number}: invalid AS pair")
            if fields[2] == "-1":
                cp_links.add(
                    CustomerProviderLink(provider_asn=asn1, customer_asn=asn2)
                )
            elif fields[2] == "0":
                peer_links.add(PeerLink(asn1, asn2))
            else:
                raise InputError(
                    f"{path}:{line_number}: unsupported relationship {fields[2]!r}"
                )
    if not cp_links and not peer_links:
        raise InputError("topology contains no relationships")
    graph_info = ASGraphInfo(
        customer_provider_links=frozenset(cp_links),
        peer_links=frozenset(peer_links),
        # The pinned AMBER-format copy has no CAIDA header metadata.  BGPy's
        # propagation ranks are derived from provider/customer edges and do
        # not require this category label.
        input_clique_asns=frozenset(),
    )
    return ASGraph(graph_info, store_customer_cone_size=False)


def degree_by_asn(graph: ASGraph) -> dict[int, int]:
    return {asn: len(as_obj.neighbors) for asn, as_obj in graph.as_dict.items()}


def select_pair_specs(
    rows: Iterable[CandidateRow],
    degrees: Mapping[int, int],
    *,
    pair_count: int = PAIR_COUNT,
    seed: int = RANDOM_SEED,
) -> tuple[PairSpec, ...]:
    """Select degree-stratified pairs and fixed edge/high-degree attackers."""

    canonical: dict[tuple[int, int], CandidateRow] = {}
    for row in rows:
        if row.holder_asn not in degrees or row.delegate_asn not in degrees:
            continue
        if not all(
            is_eligible_delegated_origin(asn)
            for asn in (row.holder_asn, row.delegate_asn)
        ):
            continue
        key = (row.holder_asn, row.delegate_asn)
        if key not in canonical or row.source_row < canonical[key].source_row:
            canonical[key] = row
    ranked = sorted(
        canonical.values(),
        key=lambda row: (
            degrees[row.holder_asn] + degrees[row.delegate_asn],
            max(degrees[row.holder_asn], degrees[row.delegate_asn]),
            row.holder_asn,
            row.delegate_asn,
        ),
    )
    if len(ranked) < pair_count:
        raise InputError(f"only {len(ranked)} eligible unique pairs are available")

    chosen: list[tuple[int, CandidateRow]] = []
    for degree_bin in range(pair_count):
        start = degree_bin * len(ranked) // pair_count
        stop = (degree_bin + 1) * len(ranked) // pair_count
        index = start + (stop - start - 1) // 2
        chosen.append((degree_bin + 1, ranked[index]))

    excluded = {
        asn
        for _, row in chosen
        for asn in (row.holder_asn, row.delegate_asn)
    }
    eligible = [
        asn
        for asn in sorted(degrees)
        if asn not in excluded and is_eligible_delegated_origin(asn)
    ]
    edge_pool = [asn for asn in eligible if degrees[asn] == 1]
    high_count = max(1, math.ceil(len(eligible) * 0.01))
    high_pool = sorted(eligible, key=lambda asn: (-degrees[asn], asn))[:high_count]
    needed_edge = (pair_count + 1) // 2
    needed_high = pair_count // 2
    if len(edge_pool) < needed_edge or len(high_pool) < needed_high:
        raise InputError("attacker pools are too small for the declared selection rule")
    rng = random.Random(seed)
    edge_attackers = iter(rng.sample(edge_pool, needed_edge))
    high_attackers = iter(rng.sample(high_pool, needed_high))

    specs: list[PairSpec] = []
    for pair_index, (degree_bin, row) in enumerate(chosen, start=1):
        attacker_class = "edge" if pair_index % 2 else "high_degree"
        attacker = (
            next(edge_attackers)
            if attacker_class == "edge"
            else next(high_attackers)
        )
        specs.append(
            PairSpec(
                pair_index=pair_index,
                source_row=row.source_row,
                root_prefix=row.root_prefix,
                holder_asn=row.holder_asn,
                leaf_prefix=row.leaf_prefix,
                delegate_asn=row.delegate_asn,
                holder_degree=degrees[row.holder_asn],
                delegate_degree=degrees[row.delegate_asn],
                degree_bin=degree_bin,
                attacker_asn=attacker,
                attacker_class=attacker_class,
                attacker_degree=degrees[attacker],
            )
        )
    return tuple(specs)


def degree_deployment_sets(
    rov_asns: frozenset[int],
    degrees: Mapping[int, int],
) -> dict[int, frozenset[int]]:
    if len(rov_asns) != ROV_COUNT:
        raise InputError(f"degree deployment requires exactly {ROV_COUNT} ROV ASes")
    absent = rov_asns.difference(degrees)
    if absent:
        raise InputError(f"ROV ASes absent from topology: {sorted(absent)[:10]}")
    ordered = sorted(rov_asns, key=lambda asn: (-degrees[asn], asn))
    sets: dict[int, frozenset[int]] = {}
    for percent in DEPLOYMENT_PERCENTAGES:
        count = len(ordered) if percent == 100 else int(len(ordered) * percent / 100)
        sets[percent] = frozenset(ordered[:count])
    return sets


def build_trial_plan(pairs: Sequence[PairSpec]) -> tuple[TrialSpec, ...]:
    """Return 100 trials with announcement-matched baselines per pair."""

    trials: list[TrialSpec] = []
    for pair in pairs:
        trials.extend(
            (
                TrialSpec(pair, B1_DELEGATE, 0),
                TrialSpec(pair, B2_DELEGATE, 0),
                TrialSpec(pair, B1_COMPETITION, 0),
                TrialSpec(pair, B2_COMPETITION, 0),
            )
        )
        for percent in DEPLOYMENT_PERCENTAGES:
            trials.append(TrialSpec(pair, D1_OPEN_DELEGATE, percent))
            trials.append(TrialSpec(pair, A1_OPEN_COMPETITION, percent))
    return tuple(trials)


def make_open_policy(pair: PairSpec) -> DAROA:
    leaf = ip_network(pair.leaf_prefix, strict=True)
    return DAROA(
        base_prefix=pair.root_prefix,
        max_length=leaf.prefixlen,
        holder_asn=pair.holder_asn,
        stripes=[Stripe(pair.root_prefix, {pair.holder_asn}, True)],
    )


def make_closed_child_policy(pair: PairSpec) -> DAROA:
    leaf = ip_network(pair.leaf_prefix, strict=True)
    return DAROA(
        base_prefix=pair.root_prefix,
        max_length=leaf.prefixlen,
        holder_asn=pair.holder_asn,
        stripes=[
            Stripe(pair.root_prefix, {pair.holder_asn}, True),
            Stripe(pair.leaf_prefix, {pair.delegate_asn}, False),
        ],
    )


def check_policy_boundaries(pair: PairSpec) -> dict[str, bool]:
    open_policy = make_open_policy(pair)
    closed_policy = make_closed_child_policy(pair)
    checks = {
        "delegate_is_delegated_in_open_child": open_policy.validate_route(
            pair.leaf_prefix, pair.delegate_asn
        )
        == ValidationState.DELEGATED,
        "attacker_is_delegated_in_open_child": open_policy.validate_route(
            pair.leaf_prefix, pair.attacker_asn
        )
        == ValidationState.DELEGATED,
        "attacker_rejected_at_exact_aggregate": open_policy.validate_route(
            pair.root_prefix, pair.attacker_asn
        )
        == ValidationState.INVALID,
        "delegate_explicit_in_closed_child": closed_policy.validate_route(
            pair.leaf_prefix, pair.delegate_asn
        )
        == ValidationState.EXPLICIT,
        "attacker_rejected_in_closed_child": closed_policy.validate_route(
            pair.leaf_prefix, pair.attacker_asn
        )
        == ValidationState.INVALID,
    }
    if not all(checks.values()):
        raise RuntimeError(f"DA boundary check failed for pair {pair.pair_index}")
    return checks


def origin_announcement(prefix: str, asn: int) -> Announcement:
    return Announcement(
        prefix=prefix,
        as_path=(asn,),
        next_hop_asn=asn,
        seed_asn=asn,
        recv_relationship=Relationships.ORIGIN,
    )


def build_scenario(
    spec: TrialSpec,
    *,
    rov_asns: frozenset[int],
    da_asns: frozenset[int],
    engine: SimulationEngine,
) -> FixedDeploymentScenario:
    if not da_asns.issubset(rov_asns):
        raise RuntimeError("DA-aware set is not a subset of the fixed ROV set")
    if spec.lane in BASELINE_LANES and da_asns:
        raise RuntimeError("fixed baseline lane cannot contain DA-aware ASes")
    if spec.lane not in BASELINE_LANES | STAGED_LANES:
        raise RuntimeError(f"unknown trial lane {spec.lane!r}")

    pair = spec.pair
    include_attacker = spec.lane in {
        B1_COMPETITION,
        B2_COMPETITION,
        A1_OPEN_COMPETITION,
    }
    announcements = [
        origin_announcement(pair.root_prefix, pair.holder_asn),
        origin_announcement(pair.leaf_prefix, pair.delegate_asn),
    ]
    if include_attacker:
        announcements.append(origin_announcement(pair.leaf_prefix, pair.attacker_asn))

    root = ip_network(pair.root_prefix, strict=True)
    leaf = ip_network(pair.leaf_prefix, strict=True)
    roas = [ROA(root, pair.holder_asn, max_length=root.prefixlen)]
    if spec.lane in {B2_DELEGATE, B2_COMPETITION}:
        roas.append(ROA(leaf, pair.delegate_asn, max_length=leaf.prefixlen))

    policy_map: dict[int, type[BGP]] = {asn: ROV for asn in rov_asns}
    policy_map.update({asn: S2ROV for asn in da_asns})
    config = ScenarioConfig(
        ScenarioCls=FixedDeploymentScenario,
        BasePolicyCls=BGP,
        AdoptPolicyCls=BGP,
        override_attacker_asns=frozenset({pair.attacker_asn}),
        override_victim_asns=frozenset({pair.holder_asn}),
        override_adopting_asns=frozenset(),
        override_announcements=tuple(announcements),
        override_roas=tuple(roas),
        hardcoded_asn_cls_dict=frozendict(policy_map),
    )
    return FixedDeploymentScenario(scenario_config=config, engine=engine)


def verify_policy_assignment(
    engine: SimulationEngine,
    rov_asns: frozenset[int],
    da_asns: frozenset[int],
) -> dict[str, int]:
    actual_da = {
        as_obj.asn for as_obj in engine.as_graph if type(as_obj.policy) is S2ROV
    }
    actual_rov = {
        as_obj.asn for as_obj in engine.as_graph if type(as_obj.policy) is ROV
    }
    if actual_da != set(da_asns):
        raise RuntimeError("engine DA-aware assignment differs from requested subset")
    if actual_da | actual_rov != set(rov_asns):
        raise RuntimeError("engine ROV+DA assignment differs from fixed 589-AS set")
    if actual_da.difference(rov_asns):
        raise RuntimeError("an AS outside the fixed ROV set was upgraded")
    return {
        "bgp": len(engine.as_graph) - len(actual_da) - len(actual_rov),
        "rov": len(actual_rov),
        "s2rov": len(actual_da),
    }


def analyze_trial(engine: SimulationEngine, pair: PairSpec) -> dict[str, Any]:
    child = {key: 0 for key in CHILD_OUTCOMES}
    destination = {key: 0 for key in DESTINATION_OUTCOMES}
    for as_obj in engine.as_graph:
        ann = as_obj.policy.local_rib.get(pair.leaf_prefix)
        if ann is None:
            child["absent"] += 1
        elif ann.origin == pair.delegate_asn:
            child["delegate"] += 1
        elif ann.origin == pair.attacker_asn:
            child["attacker"] += 1
        else:
            raise RuntimeError(
                f"unexpected child origin AS{ann.origin} at AS{as_obj.asn}"
            )
        destination[_trace_destination(engine, as_obj.asn, pair)] += 1

    denominator = len(engine.as_graph)
    _assert_partition(child, denominator, "child")
    _assert_partition(destination, denominator, "destination")
    return {
        "denominator_asns": denominator,
        "child": {
            "counts": child,
            "fractions": {key: child[key] / denominator for key in child},
        },
        "destination": {
            "counts": destination,
            "fractions": {
                key: destination[key] / denominator for key in destination
            },
        },
    }


def _trace_destination(
    engine: SimulationEngine, start_asn: int, pair: PairSpec
) -> str:
    current = start_asn
    visited: set[int] = set()
    for _ in range(len(engine.as_graph) + 1):
        if current in visited:
            return "loop"
        visited.add(current)
        policy = engine.as_graph.as_dict[current].policy
        ann = policy.local_rib.get(pair.leaf_prefix) or policy.local_rib.get(
            pair.root_prefix
        )
        if ann is None:
            return "disconnected"
        if current == ann.origin:
            if current == pair.delegate_asn:
                return "delegate"
            if current == pair.attacker_asn:
                return "attacker"
            if current == pair.holder_asn:
                return "holder_fallback"
            raise RuntimeError(f"unexpected destination origin AS{current}")
        next_hop = ann.next_hop_asn
        if next_hop not in engine.as_graph.as_dict:
            return "disconnected"
        current = next_hop
    return "loop"


def _assert_partition(counts: Mapping[str, int], denominator: int, label: str) -> None:
    if sum(counts.values()) != denominator:
        raise RuntimeError(
            f"{label} partition sums to {sum(counts.values())}, expected {denominator}"
        )


def current_rss_bytes() -> int:
    with Path("/proc/self/status").open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("/proc/self/status does not report VmRSS")


class PeakRSSMonitor:
    """Sample absolute process RSS while one graph build or trial runs."""

    def __init__(self, interval_seconds: float = 0.02) -> None:
        self.interval_seconds = interval_seconds
        self.peak_bytes = current_rss_bytes()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def __enter__(self) -> "PeakRSSMonitor":
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join()
        self.peak_bytes = max(self.peak_bytes, current_rss_bytes())

    def _sample(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.peak_bytes = max(self.peak_bytes, current_rss_bytes())


@contextmanager
def trial_alarm(seconds: float) -> Iterator[None]:
    """Interrupt a trial after the declared hard wall-clock limit."""

    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("trial alarm must run in the main thread")

    def timeout_handler(_signum: int, _frame: object) -> None:
        raise TrialTimeout(f"single trial exceeded {seconds:.1f} seconds")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timeout_handler)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def run_trial(
    engine: SimulationEngine,
    spec: TrialSpec,
    *,
    rov_asns: frozenset[int],
    da_asns: frozenset[int],
) -> dict[str, Any]:
    pair = spec.pair
    S2ROV.configure(make_open_policy(pair))
    started = perf_counter()
    rss_before = current_rss_bytes()
    with PeakRSSMonitor() as memory, trial_alarm(SINGLE_TRIAL_LIMIT_SECONDS):
        scenario = build_scenario(
            spec,
            rov_asns=rov_asns,
            da_asns=da_asns,
            engine=engine,
        )
        # This is the intentional graph/engine reuse boundary: setup replaces
        # all old policies and their Loc-RIB state before seeding this trial.
        engine.setup(scenario)
        assignment_counts = verify_policy_assignment(engine, rov_asns, da_asns)
        engine.run(propagation_round=0, scenario=scenario)
        outcomes = analyze_trial(engine, pair)
    elapsed = perf_counter() - started
    row: dict[str, Any] = {
        "scenario_id": spec.scenario_id,
        "pair_index": pair.pair_index,
        "source_row": pair.source_row,
        "lane": spec.lane,
        "deployment_strategy": spec.deployment_strategy,
        "deployment_percent_target": spec.deployment_percent,
        "deployment_count": len(da_asns),
        "deployment_fraction_actual": len(da_asns) / len(rov_asns),
        "root_prefix": pair.root_prefix,
        "leaf_prefix": pair.leaf_prefix,
        "holder_asn": pair.holder_asn,
        "delegate_asn": pair.delegate_asn,
        "attacker_asn": pair.attacker_asn,
        "attacker_class": pair.attacker_class,
        "holder_degree": pair.holder_degree,
        "delegate_degree": pair.delegate_degree,
        "attacker_degree": pair.attacker_degree,
        "rov_count": len(rov_asns),
        "policy_assignment_counts": assignment_counts,
        "outcomes": outcomes,
        "elapsed_seconds": elapsed,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": current_rss_bytes(),
        "peak_rss_bytes": memory.peak_bytes,
    }
    if elapsed > SINGLE_TRIAL_LIMIT_SECONDS:
        raise ResourceGateStop(
            f"{spec.scenario_id} took {elapsed:.3f}s, above the 60s gate"
        )
    if memory.peak_bytes > PEAK_RSS_LIMIT_BYTES:
        raise ResourceGateStop(
            f"{spec.scenario_id} peaked at {memory.peak_bytes / 1024**3:.3f} GiB, "
            "above the 8 GiB gate"
        )
    return row


def flatten_row(row: Mapping[str, Any]) -> dict[str, Any]:
    flat = {
        key: value
        for key, value in row.items()
        if key not in {"policy_assignment_counts", "outcomes"}
    }
    assignments = row["policy_assignment_counts"]
    outcomes = row["outcomes"]
    assert isinstance(assignments, Mapping)
    assert isinstance(outcomes, Mapping)
    for key, value in assignments.items():
        flat[f"policy_{key}_count"] = value
    for partition in ("child", "destination"):
        section = outcomes[partition]
        assert isinstance(section, Mapping)
        counts = section["counts"]
        fractions = section["fractions"]
        assert isinstance(counts, Mapping)
        assert isinstance(fractions, Mapping)
        for key, value in counts.items():
            flat[f"{partition}_{key}_count"] = value
        for key, value in fractions.items():
            flat[f"{partition}_{key}_fraction"] = value
    flat["denominator_asns"] = outcomes["denominator_asns"]
    return flat


def result_fingerprint(row: Mapping[str, Any]) -> tuple[Any, Any]:
    outcomes = row["outcomes"]
    assert isinstance(outcomes, Mapping)
    child = outcomes["child"]
    destination = outcomes["destination"]
    assert isinstance(child, Mapping) and isinstance(destination, Mapping)
    return child["counts"], destination["counts"]


def check_zero_percent_equivalence(rows: Sequence[Mapping[str, Any]]) -> bool:
    by_pair_lane = {
        (int(row["pair_index"]), str(row["lane"]), int(row["deployment_percent_target"])): row
        for row in rows
    }
    for pair_index in range(1, PAIR_COUNT + 1):
        matched_lanes = (
            (B1_DELEGATE, D1_OPEN_DELEGATE),
            (B1_COMPETITION, A1_OPEN_COMPETITION),
        )
        for baseline_lane, staged_lane in matched_lanes:
            baseline = by_pair_lane[(pair_index, baseline_lane, 0)]
            staged = by_pair_lane[(pair_index, staged_lane, 0)]
            if result_fingerprint(baseline) != result_fingerprint(staged):
                raise RuntimeError(
                    f"0% {staged_lane} is not route-outcome equivalent to "
                    f"announcement-matched {baseline_lane} for pair {pair_index}"
                )
    return True


def _outcome_fraction(
    row: Mapping[str, Any], partition: str, outcome: str
) -> float:
    nested = row["outcomes"]
    assert isinstance(nested, Mapping)
    section = nested[partition]
    assert isinstance(section, Mapping)
    fractions = section["fractions"]
    assert isinstance(fractions, Mapping)
    return float(fractions[outcome])


def paired_effects(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Calculate only comparisons whose announcement sets are identical."""

    by_pair_lane = {
        (int(row["pair_index"]), str(row["lane"]), int(row["deployment_percent_target"])): row
        for row in rows
    }
    effects: list[dict[str, Any]] = []
    for pair_index in range(1, PAIR_COUNT + 1):
        b1_delegate = by_pair_lane[(pair_index, B1_DELEGATE, 0)]
        b2_delegate = by_pair_lane[(pair_index, B2_DELEGATE, 0)]
        b1_competition = by_pair_lane[(pair_index, B1_COMPETITION, 0)]
        b2_competition = by_pair_lane[(pair_index, B2_COMPETITION, 0)]
        for percent in DEPLOYMENT_PERCENTAGES:
            d1 = by_pair_lane[(pair_index, D1_OPEN_DELEGATE, percent)]
            a1 = by_pair_lane[(pair_index, A1_OPEN_COMPETITION, percent)]
            item: dict[str, Any] = {
                "pair_index": pair_index,
                "deployment_percent_target": percent,
            }
            for partition in ("child", "destination"):
                d1_value = _outcome_fraction(d1, partition, "delegate")
                item[f"d1_{partition}_delegate_fraction"] = d1_value
                item[f"d1_minus_b1_{partition}_delegate_fraction"] = (
                    d1_value
                    - _outcome_fraction(b1_delegate, partition, "delegate")
                )
                item[f"d1_minus_b2_{partition}_delegate_fraction"] = (
                    d1_value
                    - _outcome_fraction(b2_delegate, partition, "delegate")
                )

                a1_value = _outcome_fraction(a1, partition, "attacker")
                item[f"a1_{partition}_attacker_fraction"] = a1_value
                item[f"a1_minus_b1_{partition}_attacker_fraction"] = (
                    a1_value
                    - _outcome_fraction(b1_competition, partition, "attacker")
                )
                item[f"a1_minus_b2_{partition}_attacker_fraction"] = (
                    a1_value
                    - _outcome_fraction(b2_competition, partition, "attacker")
                )
            effects.append(item)
    return effects


def summarize_effects(effects: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for item in effects:
        grouped[int(item["deployment_percent_target"])].append(item)
    summary: list[dict[str, Any]] = []
    for percent, group in sorted(grouped.items()):
        row: dict[str, Any] = {
            "deployment_percent_target": percent,
            "pairs": len(group),
        }
        metric_keys = sorted(
            key
            for key in group[0]
            if key not in {"pair_index", "deployment_percent_target"}
        )
        for key in metric_keys:
            values = [float(item[key]) for item in group]
            row[f"mean_{key}"] = fmean(values)
            row[f"min_{key}"] = min(values)
            row[f"max_{key}"] = max(values)
        summary.append(row)
    return summary


def summarize_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(str(row["lane"]), int(row["deployment_percent_target"]))].append(row)
    summaries: list[dict[str, Any]] = []
    for (lane, percent), group in sorted(groups.items()):
        item: dict[str, Any] = {
            "lane": lane,
            "deployment_percent_target": percent,
            "trials": len(group),
            "mean_elapsed_seconds": fmean(float(row["elapsed_seconds"]) for row in group),
            "max_peak_rss_bytes": max(int(row["peak_rss_bytes"]) for row in group),
        }
        for partition, outcomes in (
            ("child", CHILD_OUTCOMES),
            ("destination", DESTINATION_OUTCOMES),
        ):
            for outcome in outcomes:
                fractions = []
                for row in group:
                    nested = row["outcomes"]
                    assert isinstance(nested, Mapping)
                    section = nested[partition]
                    assert isinstance(section, Mapping)
                    values = section["fractions"]
                    assert isinstance(values, Mapping)
                    fractions.append(float(values[outcome]))
                item[f"mean_{partition}_{outcome}_fraction"] = fmean(fractions)
                item[f"min_{partition}_{outcome}_fraction"] = min(fractions)
                item[f"max_{partition}_{outcome}_fraction"] = max(fractions)
        summaries.append(item)
    return summaries


def collect_hashes() -> dict[str, Any]:
    paths = {
        "as_rel_fixed": TOPOLOGY_PATH,
        "origin_divergence_candidates": CANDIDATES_PATH,
        "holder_delegate_pairs": PAIR_TABLE_PATH,
        "rov_ases_json": ROV_JSON_PATH,
        "rov_ases_text": ROV_TEXT_PATH,
        "s2rov_policy": POLICY_PATH,
        "daroa_codec_oracle": DAROA_CODEC_ORACLE_PATH,
        "campaign_runner": Path(__file__).resolve(),
    }
    file_hashes = {name: sha256_file(path) for name, path in paths.items()}
    bundle = hashlib.sha256()
    for name, digest in sorted(file_hashes.items()):
        bundle.update(name.encode())
        bundle.update(b"\0")
        bundle.update(digest.encode())
        bundle.update(b"\n")
    return {
        "files": file_hashes,
        "bundle_sha256": bundle.hexdigest(),
    }


def write_outputs(
    output_dir: Path,
    rows: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "raw_scenarios.jsonl"
    jsonl_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    csv_rows = [flatten_row(row) for row in rows]
    csv_path = output_dir / "raw_scenarios.csv"
    if csv_rows:
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(csv_rows[0]))
            writer.writeheader()
            writer.writerows(csv_rows)
    else:
        csv_path.write_text("", encoding="utf-8")
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_gate(output_dir: Path) -> dict[str, Any]:
    command = shlex.join([sys.executable, "-m", __name__, "--output-dir", str(output_dir)])
    total_started = perf_counter()
    hashes = collect_hashes()
    repo_commit = git_value(("rev-parse", "HEAD"), REPOSITORY_ROOT)
    vendor_commit = git_value(("rev-parse", "HEAD"), VENDOR_PATH)
    repo_dirty = bool(git_value(("status", "--porcelain"), REPOSITORY_ROOT))
    vendor_dirty = bool(git_value(("status", "--porcelain"), VENDOR_PATH))

    graph_started = perf_counter()
    with PeakRSSMonitor() as graph_memory:
        graph = build_fixed_graph()
    graph_build_seconds = perf_counter() - graph_started
    if graph_memory.peak_bytes > PEAK_RSS_LIMIT_BYTES:
        raise ResourceGateStop(
            f"graph build peaked at {graph_memory.peak_bytes / 1024**3:.3f} GiB"
        )
    engine = SimulationEngine(graph)
    degrees = degree_by_asn(graph)
    rov_asns = load_rov_asns()
    pairs = select_pair_specs(load_candidate_rows(), degrees)
    deployments = degree_deployment_sets(rov_asns, degrees)
    plan = build_trial_plan(pairs)
    boundary_checks = {
        str(pair.pair_index): check_policy_boundaries(pair) for pair in pairs
    }

    metadata: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "engine": {
            "name": "BGPy",
            "version": version("bgpy_pkg"),
            "vendor_commit": vendor_commit,
            "vendor_dirty": vendor_dirty,
            "vendor_modified_by_campaign": False,
        },
        "repository_commit": repo_commit,
        "repository_dirty_at_start": repo_dirty,
        "artifact_hashes_sha256": hashes,
        "python": sys.version,
        "platform": platform.platform(),
        "command": command,
        "selection": {
            "pair_rule": SELECTION_RULE,
            "attacker_rule": ATTACKER_RULE,
            "seed": RANDOM_SEED,
            "interpretation_warning": (
                "Selected pairs are empirical origin-divergence candidates; "
                "they are not asserted to be real delegations."
            ),
            "pairs": [asdict(pair) for pair in pairs],
        },
        "topology": {
            "asns": len(graph),
            "relationship_input": str(TOPOLOGY_PATH),
            "graph_build_count": 1,
            "engine_instance_count": 1,
            "engine_setup_reset_between_trials": True,
            "input_clique_metadata_available": False,
            "build_elapsed_seconds": graph_build_seconds,
            "build_peak_rss_bytes": graph_memory.peak_bytes,
        },
        "deployment": {
            "rov_count": len(rov_asns),
            "strategy": "degree",
            "percentages": list(DEPLOYMENT_PERCENTAGES),
            "sets": {
                str(percent): {
                    "count": len(asns),
                    "actual_fraction": len(asns) / len(rov_asns),
                    "asns": sorted(asns),
                }
                for percent, asns in deployments.items()
            },
        },
        "resource_gate": {
            "single_trial_seconds": SINGLE_TRIAL_LIMIT_SECONDS,
            "peak_rss_bytes": PEAK_RSS_LIMIT_BYTES,
            "silent_retries": 0,
        },
        "checks": {
            "policy_boundaries": boundary_checks,
            "all_da_sets_subset_of_rov": all(
                asns.issubset(rov_asns) for asns in deployments.values()
            ),
            "partitions_checked_per_run": True,
            "zero_percent_equals_rov": None,
        },
        "planned_trials": len(plan),
    }

    rows: list[dict[str, Any]] = []
    try:
        for index, spec in enumerate(plan, start=1):
            da_asns = (
                frozenset()
                if spec.lane in BASELINE_LANES
                else deployments[spec.deployment_percent]
            )
            row = run_trial(
                engine,
                spec,
                rov_asns=rov_asns,
                da_asns=da_asns,
            )
            row["run_index"] = index
            row["repository_commit"] = repo_commit
            row["input_bundle_sha256"] = hashes["bundle_sha256"]
            rows.append(row)
            metadata["status"] = "running"
            metadata["completed_trials"] = len(rows)
            metadata["total_wall_seconds"] = perf_counter() - total_started
            write_outputs(output_dir, rows, metadata)
    except Exception as exc:
        metadata["status"] = "stopped" if isinstance(exc, ResourceGateStop) else "failed"
        metadata["completed_trials"] = len(rows)
        metadata["total_wall_seconds"] = perf_counter() - total_started
        metadata["exception"] = {"type": type(exc).__name__, "message": str(exc)}
        metadata["aggregate"] = summarize_rows(rows) if rows else []
        write_outputs(output_dir, rows, metadata)
        raise

    checks = metadata["checks"]
    assert isinstance(checks, dict)
    checks["zero_percent_equals_rov"] = check_zero_percent_equivalence(rows)
    metadata["aggregate"] = summarize_rows(rows)
    effects = paired_effects(rows)
    metadata["paired_effects"] = effects
    metadata["paired_effect_summary"] = summarize_effects(effects)
    metadata["completed_trials"] = len(rows)
    metadata["total_wall_seconds"] = perf_counter() - total_started
    metadata["peak_rss_bytes"] = max(
        [graph_memory.peak_bytes, *(int(row["peak_rss_bytes"]) for row in rows)]
    )
    metadata["status"] = "success"
    write_outputs(output_dir, rows, metadata)
    return metadata


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / "experiments" / "routing_model" / "results" / "full_graph_gate",
    )
    args = parser.parse_args(argv)
    summary = run_gate(args.output_dir)
    print(f"wrote {args.output_dir}")
    print(
        f"status={summary['status']} trials={summary['completed_trials']}/"
        f"{summary['planned_trials']} wall={summary['total_wall_seconds']:.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
