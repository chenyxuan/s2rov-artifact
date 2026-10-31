#!/usr/bin/env python3
"""Replay route states during partial ROA issuance.

The input rows are the origin-divergence candidates reported in Table I.  All
observed endpoint routes are announced and every retained root has an active
aggregate policy.  Matching downstream ROAs are deployed atomically for the
complete observed origin set of an endpoint prefix, while route outcomes are
counted per observed ``(prefix, origin)`` pair.  The reference classifier then
reports Explicit, OpenScope, Invalid, or NotFound at each deployment snapshot.

The main figure separates two deployment views.  The potential view holds all
root ROAs active and asks how many conflicts remain as downstream ROAs are
issued.  The observed view advances independent root and downstream issuance at
the same marginal rate, so a conflict requires an active root ROA and a missing
downstream ROA.  Every plotted point is the mean of randomized deployments over
the frozen observed route set.  It is not a curve fitted from a closed-form
expectation and does not infer Internet prevalence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import io
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, NamedTuple, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, StrMethodFormatter
import numpy as np

from figure_typography import BODY_FONT_FAMILY, configure_body_font


# Match the Times-compatible IEEEtran body while keeping SVG text editable.
configure_body_font()


REPO = Path(__file__).resolve().parents[2]
MANUSCRIPT = Path(__file__).resolve().parents[1]
REFERENCE_SCRIPTS = REPO / "implementation" / "s2rov_codec" / "scripts"
if str(REFERENCE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(REFERENCE_SCRIPTS))

from utils.s2rov import (  # noqa: E402
    S2ROV,
    Stripe,
    ValidationState,
    is_eligible_delegated_origin,
)


DEFAULT_INPUT = (
    REPO
    / "experiments" / "candidates"
    / "allocation_tree"
    / "visibility_experiment"
    / "outputs"
    / "visibility_candidates.csv"
)
DEFAULT_SOURCE_DIR = MANUSCRIPT / "figures" / "source_data"
DEFAULT_FIGURE_DIR = MANUSCRIPT / "figures"
DEFAULT_PLACEMENT_SCORES = (
    DEFAULT_SOURCE_DIR / "openscope_placement_as_scores.json"
)

EXPECTED_INPUT_SHA256 = (
    "0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918"
)
EXPECTED_PLACEMENT_SCORES_SHA256 = (
    "b6d87f20bed4ea347f417bca072a05048eea84439e86f4773cc8bc44017a8257"
)
EXPECTED_CAIDA_GRAPH_SHA256 = (
    "aabd0b2154d9dec5b4c0b63d1d9f88cbfbf381bbc4d2246fe0471dd4aacf2181"
)
EXPECTED_FAMILY_COUNTS = {"IPv4": 504, "IPv6": 83}
EXPECTED_ROOT_COUNTS = {"IPv4": 83, "IPv6": 14}
EXPECTED_ROUTE_COUNTS = {"IPv4": 506, "IPv6": 83}
CONFLICT_RATE_DENOMINATOR = sum(EXPECTED_ROUTE_COUNTS.values())
TARGET_PERCENTS = tuple(range(0, 101, 10))
POOLED_SCOPE_TARGETS = tuple(range(0, 101, 20))
STRATEGIES = ("random", "fanout-first", "fanout-last")
PLACEMENT_STRATEGIES = (
    "most-routes-first",
    "asrank-first",
    "degree-first",
    "random",
)
PLACEMENT_ROA_TARGET_PERCENT = 50
ROLLOUTS = 1000
MASTER_SEED = 20260829

GRID_FILENAME = "fig_partial_policy_grid.csv"
BUDGET_FILENAME = "fig_partial_policy_decision_budget.csv"
POOLED_FILENAME = "fig_partial_policy_pooled.csv"
CONFLICT_FILENAME = "fig_partial_policy_conflicts.csv"
DEPLOYMENT_CURVE_FILENAME = "fig_partial_policy_deployment_curves.csv"
PLACEMENT_FILENAME = "fig_openscope_placement.csv"
MANIFEST_FILENAME = "fig_partial_policy_replay.manifest.json"
FIGURE_BASENAMES = {
    "IPv4": "fig_partial_policy_ipv4",
    "IPv6": "fig_partial_policy_ipv6",
}
STRATEGY_FIGURE_BASENAMES = {
    "IPv4": "fig_partial_policy_strategy_ipv4",
    "IPv6": "fig_partial_policy_strategy_ipv6",
}
DEPLOYMENT_FIGURE_BASENAMES = {
    "potential_conflicts": "fig_partial_policy_potential",
    "observed_conflicts": "fig_partial_policy_observed",
}
DEPLOYMENT_LEGEND_BASENAME = "fig_partial_policy_legend"
PLACEMENT_FIGURE_BASENAME = "fig_openscope_placement"
ACTIVE_PANEL_FIGSIZE = (3.50, 1.75)
ACTIVE_PANEL_MARGINS = {
    "left": 0.145,
    "right": 0.94,
    "bottom": 0.27,
    "top": 0.89,
}
ACTIVE_BASE_FONTSIZE = 8.4
ACTIVE_TICK_LABELSIZE = 7.56
ACTIVE_AXIS_LABELSIZE = 8.4
ACTIVE_LEGEND_FONTSIZE = 6.96
DEPLOYMENT_PANEL_FIGSIZE = ACTIVE_PANEL_FIGSIZE
DEPLOYMENT_PANEL_ADJUST = ACTIVE_PANEL_MARGINS
DEPLOYMENT_LEGEND_FIGSIZE = (3.50, 0.34)

FIGURE_TEXT = (
    "ROA target (%)",
    "OpenScope target (%)",
    "Potential conflicts (%)",
    "Random median",
    "Random 95% range",
    "Fanout first",
    "Fanout last",
    "Configuration decisions",
    "Candidate paths covered (%)",
    "Exact",
    "Random OpenScope",
    "Random range",
    "None",
    "Random",
    "ROA issuance (%)",
    "Conflicting routes (%)",
    "Conflicting routes (%)",
    "0%",
    "20%",
    "40%",
    "60%",
    "80%",
    "100%",
    "Aggregate prefixes with S²-ROV policy",
    "Aggregate prefixes with S²-ROV policy (%)",
    "Route count",
    "ASRank",
    "AS degree",
)

CONFLICT_STATES = ("explicit", "open_scope", "invalid", "not_found")
CONFLICT_STATISTICS = ("mean", "median", "p05", "p95", "min", "max")

CONFLICT_FIELDS = (
    "family",
    "root_order",
    "downstream_roa_target_percent",
    "scope_target_percent",
    "endpoint_prefix_count",
    "route_origin_count",
    "root_count",
    "downstream_selected_prefix_count",
    "scope_selected_root_count",
    "downstream_achieved_percent",
    "scope_achieved_percent",
    *(
        f"{state}_count_{statistic}"
        for state in CONFLICT_STATES
        for statistic in CONFLICT_STATISTICS
    ),
)

DEPLOYMENT_CURVE_FIELDS = (
    "roa_issuance_percent",
    "rollout_count",
    "endpoint_prefix_count",
    "route_origin_count",
    "root_count",
    "downstream_selected_prefix_count",
    "root_roa_selected_count",
    "scope_target_percent",
    "scope_selected_root_count",
    "downstream_achieved_percent",
    "root_roa_achieved_percent",
    "scope_achieved_percent",
    "conflict_rate_denominator",
    *(f"potential_conflicts_{statistic}" for statistic in CONFLICT_STATISTICS),
    *(f"observed_conflicts_{statistic}" for statistic in CONFLICT_STATISTICS),
    *(
        f"potential_conflicts_percent_{statistic}"
        for statistic in CONFLICT_STATISTICS
    ),
    *(
        f"observed_conflicts_percent_{statistic}"
        for statistic in CONFLICT_STATISTICS
    ),
)

PLACEMENT_FIELDS = (
    "strategy",
    "roa_issuance_percent",
    "scope_target_percent",
    "rollout_count",
    "endpoint_prefix_count",
    "route_origin_count",
    "root_count",
    "downstream_selected_prefix_count",
    "scope_selected_root_count",
    "scope_achieved_percent",
    "conflict_rate_denominator",
    *(f"potential_conflicts_{statistic}" for statistic in CONFLICT_STATISTICS),
    *(
        f"potential_conflicts_percent_{statistic}"
        for statistic in CONFLICT_STATISTICS
    ),
)

GRID_FIELDS = (
    "family",
    "root_order",
    "exact_target_percent",
    "scope_target_percent",
    "candidate_count",
    "root_count",
    "exact_selected_count",
    "scope_selected_root_count",
    "exact_achieved_percent",
    "scope_achieved_percent",
    "remaining_count_mean",
    "remaining_count_median",
    "remaining_count_p025",
    "remaining_count_p05",
    "remaining_count_p95",
    "remaining_count_p975",
    "remaining_count_min",
    "remaining_count_max",
    "remaining_percent_mean",
    "remaining_percent_median",
    "remaining_percent_p025",
    "remaining_percent_p05",
    "remaining_percent_p95",
    "remaining_percent_p975",
    "remaining_percent_min",
    "remaining_percent_max",
    "avoided_count_mean",
    "avoided_count_median",
    "avoided_count_p025",
    "avoided_count_p05",
    "avoided_count_p95",
    "avoided_count_p975",
    "avoided_count_min",
    "avoided_count_max",
    "avoided_percent_mean",
    "avoided_percent_median",
    "avoided_percent_p025",
    "avoided_percent_p05",
    "avoided_percent_p95",
    "avoided_percent_p975",
    "avoided_percent_min",
    "avoided_percent_max",
    "avoided_per_scope_root_mean",
    "avoided_per_scope_root_median",
    "avoided_per_scope_root_p025",
    "avoided_per_scope_root_p05",
    "avoided_per_scope_root_p95",
    "avoided_per_scope_root_p975",
    "avoided_per_scope_root_min",
    "avoided_per_scope_root_max",
)

BUDGET_FIELDS = (
    "family",
    "root_order",
    "configuration_decisions",
    "candidate_count",
    "root_count",
    "exact_paths_covered_count",
    "exact_paths_covered_percent",
    "scope_paths_covered_count_mean",
    "scope_paths_covered_count_median",
    "scope_paths_covered_count_p025",
    "scope_paths_covered_count_p05",
    "scope_paths_covered_count_p95",
    "scope_paths_covered_count_p975",
    "scope_paths_covered_count_min",
    "scope_paths_covered_count_max",
    "scope_paths_covered_percent_mean",
    "scope_paths_covered_percent_median",
    "scope_paths_covered_percent_p025",
    "scope_paths_covered_percent_p05",
    "scope_paths_covered_percent_p95",
    "scope_paths_covered_percent_p975",
    "scope_paths_covered_percent_min",
    "scope_paths_covered_percent_max",
    "scope_paths_per_decision_mean",
    "scope_paths_per_decision_median",
    "scope_paths_per_decision_p025",
    "scope_paths_per_decision_p975",
    "scope_paths_per_decision_min",
    "scope_paths_per_decision_max",
    "scope_minus_exact_paths_mean",
    "scope_minus_exact_paths_median",
    "scope_minus_exact_paths_p025",
    "scope_minus_exact_paths_p975",
    "scope_minus_exact_paths_min",
    "scope_minus_exact_paths_max",
)


class Candidate(NamedTuple):
    row_id: int
    family: str
    root_prefix: str
    endpoint_prefix: str
    root_origins: tuple[int, ...]
    endpoint_origins: tuple[int, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def relative_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO.resolve()))
    except ValueError:
        return str(path.resolve())


def parse_origin_set(value: str) -> tuple[int, ...]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts:
        raise ValueError("empty observed origin set")
    if len(parts) != len(set(parts)):
        raise ValueError(f"duplicate origin in observed set: {value!r}")
    origins = tuple(sorted({int(part) for part in parts}))
    if any(origin <= 0 or origin > 0xFFFFFFFF for origin in origins):
        raise ValueError(f"origin outside the nonzero 32-bit range: {value!r}")
    return origins


def _oracle_origin_is_eligible(asn: int) -> bool:
    """Reproduce the public-origin eligibility rule without the classifier."""

    if asn <= 0 or asn > 0xFFFFFFFF or asn == 23456:
        return False
    if 64496 <= asn <= 131071:
        return False
    if 4200000000 <= asn <= 4294967295:
        return False
    return True


def _oracle_route_eligibility(
    candidates: Sequence[Candidate],
) -> np.ndarray:
    """Return raw-input eligibility in reference route-table order."""

    return np.asarray(
        [
            _oracle_origin_is_eligible(origin)
            for candidate in candidates
            for origin in candidate.endpoint_origins
        ],
        dtype=bool,
    )


def load_placement_scores(
    path: Path = DEFAULT_PLACEMENT_SCORES,
    expected_sha256: str = EXPECTED_PLACEMENT_SCORES_SHA256,
) -> tuple[dict[int, dict[str, int]], dict[str, Any]]:
    """Load the hash-bound ASRank and degree scores used by Figure 3."""

    observed_hash = sha256_file(path)
    if observed_hash != expected_sha256:
        raise ValueError(
            "placement-score SHA-256 mismatch: "
            f"expected {expected_sha256}, observed {observed_hash}"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("placement-score input is not valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "source",
        "derivation",
        "scores",
    }:
        raise ValueError("placement-score input has an unexpected top-level schema")
    if document["schema"] != "openscope-placement-as-scores-v1":
        raise ValueError("placement-score schema version changed")
    source = document["source"]
    derivation = document["derivation"]
    raw_scores = document["scores"]
    if not isinstance(source, dict) or source.get(
        "uncompressed_sha256"
    ) != EXPECTED_CAIDA_GRAPH_SHA256:
        raise ValueError("placement scores are not bound to the pinned CAIDA graph")
    if not isinstance(derivation, dict) or not isinstance(raw_scores, list):
        raise ValueError("placement-score metadata is malformed")

    scores: dict[int, dict[str, int]] = {}
    for index, raw in enumerate(raw_scores, start=1):
        if not isinstance(raw, dict) or set(raw) != {
            "asn",
            "customer_cone_asns",
            "total_degree",
        }:
            raise ValueError(f"placement score {index} has unexpected fields")
        asn = raw["asn"]
        cone = raw["customer_cone_asns"]
        degree = raw["total_degree"]
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (asn, cone, degree)
        ):
            raise ValueError(f"placement score {index} is not integral")
        if asn <= 0 or asn > 0xFFFFFFFF or cone < 0 or degree < 0:
            raise ValueError(f"placement score {index} is outside its valid range")
        if asn in scores:
            raise ValueError(f"placement scores repeat AS{asn}")
        scores[asn] = {
            "customer_cone_asns": cone,
            "total_degree": degree,
        }
    if len(scores) != 37:
        raise ValueError(f"expected 37 placement-score ASNs, observed {len(scores)}")

    metadata = {
        "path": relative_to_repo(path),
        "sha256": observed_hash,
        "schema": document["schema"],
        "source": source,
        "derivation": derivation,
        "asn_count": len(scores),
        "customer_cone_min": min(
            score["customer_cone_asns"] for score in scores.values()
        ),
        "customer_cone_max": max(
            score["customer_cone_asns"] for score in scores.values()
        ),
        "total_degree_min": min(
            score["total_degree"] for score in scores.values()
        ),
        "total_degree_max": max(
            score["total_degree"] for score in scores.values()
        ),
    }
    return scores, metadata


def load_candidates(
    path: Path = DEFAULT_INPUT,
    expected_sha256: str = EXPECTED_INPUT_SHA256,
) -> tuple[list[Candidate], dict[str, Any]]:
    observed_hash = sha256_file(path)
    if observed_hash != expected_sha256:
        raise ValueError(
            "candidate input SHA-256 mismatch: "
            f"expected {expected_sha256}, observed {observed_hash}"
        )

    candidates: list[Candidate] = []
    root_origin_sets: dict[tuple[str, str], tuple[int, ...]] = {}
    parsed_roots: dict[tuple[str, str], ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
    parsed_endpoints: dict[
        tuple[str, str], ipaddress.IPv4Network | ipaddress.IPv6Network
    ] = {}
    endpoint_keys: set[tuple[str, str]] = set()
    root_max_lengths: dict[tuple[str, str], int] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "family",
            "root_prefix",
            "endpoint_prefix",
            "root_origins",
            "endpoint_origins",
            "path_classification",
        }
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError("candidate input is missing required fields")
        for row_id, row in enumerate(reader, start=1):
            family = row["family"]
            if family not in EXPECTED_FAMILY_COUNTS:
                raise ValueError(f"unexpected IP family {family!r}")
            if row["path_classification"] != "registry_indirect":
                raise ValueError(f"row {row_id} is not registry-indirect")
            root_origins = parse_origin_set(row["root_origins"])
            endpoint_origins = parse_origin_set(row["endpoint_origins"])
            if set(root_origins).intersection(endpoint_origins):
                raise ValueError(f"row {row_id} does not have origin divergence")
            try:
                root_network = ipaddress.ip_network(row["root_prefix"], strict=True)
                endpoint_network = ipaddress.ip_network(
                    row["endpoint_prefix"], strict=True
                )
            except ValueError as exc:
                raise ValueError(f"row {row_id} has a noncanonical prefix") from exc
            expected_version = 4 if family == "IPv4" else 6
            if (
                root_network.version != expected_version
                or endpoint_network.version != expected_version
            ):
                raise ValueError(f"row {row_id} mixes IP versions")
            if endpoint_network == root_network or not endpoint_network.subnet_of(
                root_network
            ):
                raise ValueError(
                    f"row {row_id} endpoint is not a proper subprefix of its root"
                )
            root_key = (family, row["root_prefix"])
            previous_origins = root_origin_sets.setdefault(root_key, root_origins)
            if previous_origins != root_origins:
                raise ValueError(f"root origin set changes within {root_key}")
            parsed_roots[root_key] = root_network
            endpoint_key = (family, row["endpoint_prefix"])
            if endpoint_key in endpoint_keys:
                raise ValueError(f"endpoint prefix appears more than once: {endpoint_key}")
            endpoint_keys.add(endpoint_key)
            parsed_endpoints[endpoint_key] = endpoint_network
            root_max_lengths[root_key] = max(
                root_max_lengths.get(root_key, root_network.prefixlen),
                endpoint_network.prefixlen,
            )
            candidates.append(
                Candidate(
                    row_id=row_id,
                    family=family,
                    root_prefix=row["root_prefix"],
                    endpoint_prefix=row["endpoint_prefix"],
                    root_origins=root_origins,
                    endpoint_origins=endpoint_origins,
                )
            )

    family_counts = Counter(candidate.family for candidate in candidates)
    root_counts = {
        family: len(
            {candidate.root_prefix for candidate in candidates if candidate.family == family}
        )
        for family in EXPECTED_FAMILY_COUNTS
    }
    if dict(family_counts) != EXPECTED_FAMILY_COUNTS:
        raise ValueError(
            f"candidate counts changed: expected {EXPECTED_FAMILY_COUNTS}, "
            f"observed {dict(family_counts)}"
        )
    if root_counts != EXPECTED_ROOT_COUNTS:
        raise ValueError(
            f"root counts changed: expected {EXPECTED_ROOT_COUNTS}, observed {root_counts}"
        )

    for family in EXPECTED_FAMILY_COUNTS:
        family_roots = [
            network
            for (root_family, _), network in parsed_roots.items()
            if root_family == family
        ]
        for index, left in enumerate(family_roots):
            for right in family_roots[index + 1 :]:
                if left.subnet_of(right) or right.subnet_of(left):
                    raise ValueError(
                        f"retained {family} roots are nested: {left} and {right}"
                    )

        family_endpoints = [
            network
            for (endpoint_family, _), network in parsed_endpoints.items()
            if endpoint_family == family
        ]
        for index, left in enumerate(family_endpoints):
            for right in family_endpoints[index + 1 :]:
                if left.subnet_of(right) or right.subnet_of(left):
                    raise ValueError(
                        f"retained {family} endpoints are nested: {left} and {right}"
                    )

    duplicate_rows = len(candidates) - len(
        {
            (candidate.family, candidate.root_prefix, candidate.endpoint_prefix)
            for candidate in candidates
        }
    )
    multi_origin_endpoints = sum(
        len(candidate.endpoint_origins) > 1 for candidate in candidates
    )
    endpoint_prefix_origin_entries = {
        family: sum(
            len(candidate.endpoint_origins)
            for candidate in candidates
            if candidate.family == family
        )
        for family in EXPECTED_FAMILY_COUNTS
    }
    route_origin_tuples = [
        (candidate.family, candidate.endpoint_prefix, origin)
        for candidate in candidates
        for origin in candidate.endpoint_origins
    ]
    route_origin_counts = Counter(family for family, _, _ in route_origin_tuples)
    if dict(route_origin_counts) != EXPECTED_ROUTE_COUNTS:
        raise ValueError(
            f"route-origin counts changed: expected {EXPECTED_ROUTE_COUNTS}, "
            f"observed {dict(route_origin_counts)}"
        )
    eligible_route_origins = sum(
        is_eligible_delegated_origin(origin)
        for _, _, origin in route_origin_tuples
    )
    aggregate_origin_entries = sum(len(origins) for origins in root_origin_sets.values())
    metadata = {
        "sha256": observed_hash,
        "rows": len(candidates),
        "family_counts": dict(family_counts),
        "root_counts": root_counts,
        "duplicate_root_endpoint_rows": duplicate_rows,
        "multi_origin_endpoint_rows": multi_origin_endpoints,
        "endpoint_prefix_origin_entries": endpoint_prefix_origin_entries,
        "route_origin_counts": dict(route_origin_counts),
        "route_origin_count": len(route_origin_tuples),
        "route_origin_tuples_unique": len(route_origin_tuples)
        == len(set(route_origin_tuples)),
        "eligible_route_origin_count": eligible_route_origins,
        "ineligible_route_origin_count": len(route_origin_tuples)
        - eligible_route_origins,
        "aggregate_origin_entries": aggregate_origin_entries,
        "root_origin_sets_singleton": all(
            len(origins) == 1 for origins in root_origin_sets.values()
        ),
        "root_scope_max_length_range": {
            family: [
                min(
                    length
                    for (root_family, _), length in root_max_lengths.items()
                    if root_family == family
                ),
                max(
                    length
                    for (root_family, _), length in root_max_lengths.items()
                    if root_family == family
                ),
            ]
            for family in EXPECTED_FAMILY_COUNTS
        },
        "all_origin_sets_disjoint": True,
        "all_paths_registry_indirect": True,
        "all_prefixes_canonical": True,
        "all_endpoints_proper_subprefixes": True,
        "endpoint_prefixes_unique": True,
        "root_origin_sets_consistent": True,
        "retained_roots_non_nested": True,
        "retained_endpoints_non_nested": True,
        "scope_max_lengths_cover_retained_endpoints": True,
    }
    return candidates, metadata


def _stable_seed(family: str, rollout: int, namespace: str, master_seed: int) -> int:
    payload = f"{master_seed}|{family}|{rollout}|{namespace}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _rank_matrix(
    item_count: int,
    family: str,
    namespace: str,
    rollout_count: int,
    master_seed: int,
) -> np.ndarray:
    dtype = np.int16 if item_count < np.iinfo(np.int16).max else np.int32
    ranks = np.empty((rollout_count, item_count), dtype=dtype)
    positions = np.arange(item_count, dtype=dtype)
    for rollout in range(rollout_count):
        order = list(range(item_count))
        rng = random.Random(_stable_seed(family, rollout, namespace, master_seed))
        rng.shuffle(order)
        ranks[rollout, np.asarray(order, dtype=np.int64)] = positions
    return ranks


def _deterministic_root_ranks(
    roots: Sequence[str], fanout: dict[str, int], strategy: str
) -> np.ndarray:
    if strategy == "fanout-first":
        order = sorted(range(len(roots)), key=lambda i: (-fanout[roots[i]], roots[i]))
    elif strategy == "fanout-last":
        order = sorted(range(len(roots)), key=lambda i: (fanout[roots[i]], roots[i]))
    else:
        raise ValueError(f"unsupported deterministic strategy {strategy!r}")
    ranks = np.empty(len(roots), dtype=np.int16)
    ranks[np.asarray(order, dtype=np.int64)] = np.arange(len(roots), dtype=np.int16)
    return ranks


def _scored_root_rank_matrix(
    roots: Sequence[Any],
    scores: dict[Any, int],
    tie_ranks: np.ndarray,
    *,
    descending: bool,
) -> np.ndarray:
    """Rank roots by a fixed score and seeded random order within ties."""

    rollout_count, root_count = tie_ranks.shape
    if root_count != len(roots) or set(scores) != set(roots):
        raise ValueError("root-score coverage does not match the placement roots")
    dtype = np.int16 if root_count < np.iinfo(np.int16).max else np.int32
    ranks = np.empty((rollout_count, root_count), dtype=dtype)
    positions = np.arange(root_count, dtype=dtype)
    for rollout in range(rollout_count):
        if descending:
            order = sorted(
                range(root_count),
                key=lambda index: (
                    -scores[roots[index]],
                    int(tie_ranks[rollout, index]),
                ),
            )
        else:
            order = sorted(
                range(root_count),
                key=lambda index: (
                    scores[roots[index]],
                    int(tie_ranks[rollout, index]),
                ),
            )
        ranks[rollout, np.asarray(order, dtype=np.int64)] = positions
    return ranks


def _summarize(array: np.ndarray) -> dict[str, float]:
    values = np.asarray(array, dtype=np.float64)
    p025, p05, median, p95, p975 = np.percentile(
        values, [2.5, 5, 50, 95, 97.5], method="linear"
    )
    return {
        "mean": float(np.mean(values)),
        "median": float(median),
        "p025": float(p025),
        "p05": float(p05),
        "p95": float(p95),
        "p975": float(p975),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
    }


def _distribution(values: np.ndarray, denominator: int) -> dict[str, Any]:
    values = np.asarray(values, dtype=np.float64)
    percents = values * 100.0 / denominator
    return {"count": _summarize(values), "percent": _summarize(percents)}


def _selection_hash(*arrays: np.ndarray) -> str:
    digest = hashlib.sha256()
    for array in arrays:
        normalized = np.asarray(array, dtype="<i4")
        digest.update(normalized.shape[0].to_bytes(8, "little"))
        digest.update(normalized.shape[1].to_bytes(8, "little"))
        digest.update(normalized.tobytes(order="C"))
    return digest.hexdigest()


def compute_grid(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if rollout_count <= 0:
        raise ValueError("rollout_count must be positive")

    grid: list[dict[str, Any]] = []
    selection_metadata: dict[str, Any] = {}
    for family in ("IPv4", "IPv6"):
        family_candidates = [candidate for candidate in candidates if candidate.family == family]
        roots = sorted({candidate.root_prefix for candidate in family_candidates})
        root_to_index = {root: index for index, root in enumerate(roots)}
        candidate_root_index = np.asarray(
            [root_to_index[candidate.root_prefix] for candidate in family_candidates],
            dtype=np.int16,
        )
        fanout_counter = Counter(candidate.root_prefix for candidate in family_candidates)
        fanout = {root: fanout_counter[root] for root in roots}

        exact_ranks = _rank_matrix(
            len(family_candidates), family, "endpoint", rollout_count, master_seed
        )
        random_root_ranks = _rank_matrix(
            len(roots), family, "root", rollout_count, master_seed
        )
        first_ranks = _deterministic_root_ranks(roots, fanout, "fanout-first")
        last_ranks = _deterministic_root_ranks(roots, fanout, "fanout-last")
        selection_metadata[family] = {
            "candidate_count": len(family_candidates),
            "root_count": len(roots),
            "fanout_min": min(fanout.values()),
            "fanout_median": float(np.median(list(fanout.values()))),
            "fanout_max": max(fanout.values()),
            "largest_roots": [
                {"root_prefix": root, "candidate_rows": count}
                for root, count in sorted(
                    fanout.items(), key=lambda item: (-item[1], item[0])
                )[:5]
            ],
            "selection_sha256": _selection_hash(exact_ranks, random_root_ranks),
        }

        root_rank_by_strategy: dict[str, np.ndarray] = {
            "random": random_root_ranks,
            "fanout-first": np.broadcast_to(first_ranks, (rollout_count, len(roots))),
            "fanout-last": np.broadcast_to(last_ranks, (rollout_count, len(roots))),
        }
        n_candidates = len(family_candidates)
        n_roots = len(roots)

        for strategy in STRATEGIES:
            candidate_root_ranks = root_rank_by_strategy[strategy][:, candidate_root_index]
            for exact_target in TARGET_PERCENTS:
                exact_selected_count = math.floor(n_candidates * exact_target / 100)
                lacks_exact = exact_ranks >= exact_selected_count
                baseline_remaining = n_candidates - exact_selected_count
                for scope_target in TARGET_PERCENTS:
                    scope_selected_count = math.floor(n_roots * scope_target / 100)
                    root_is_marked = candidate_root_ranks < scope_selected_count
                    remaining = np.count_nonzero(
                        lacks_exact & ~root_is_marked, axis=1
                    )
                    avoided = baseline_remaining - remaining
                    remaining_stats = _distribution(remaining, n_candidates)
                    avoided_stats = _distribution(avoided, n_candidates)
                    efficiency_stats = (
                        _summarize(avoided / scope_selected_count)
                        if scope_selected_count > 0
                        else {statistic: None for statistic in _summarize(avoided).keys()}
                    )
                    row: dict[str, Any] = {
                        "family": family,
                        "root_order": strategy,
                        "exact_target_percent": exact_target,
                        "scope_target_percent": scope_target,
                        "candidate_count": n_candidates,
                        "root_count": n_roots,
                        "exact_selected_count": exact_selected_count,
                        "scope_selected_root_count": scope_selected_count,
                        "exact_achieved_percent": exact_selected_count
                        * 100.0
                        / n_candidates,
                        "scope_achieved_percent": scope_selected_count * 100.0 / n_roots,
                    }
                    for prefix, stats in (
                        ("remaining", remaining_stats),
                        ("avoided", avoided_stats),
                    ):
                        for unit in ("count", "percent"):
                            for statistic, value in stats[unit].items():
                                row[f"{prefix}_{unit}_{statistic}"] = value
                    for statistic, value in efficiency_stats.items():
                        row[f"avoided_per_scope_root_{statistic}"] = value
                    grid.append(row)

    validate_grid(grid)
    return grid, selection_metadata


def compute_pooled_deployment(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Replay ROA and OpenScope deployment over one pooled dual-stack corpus.

    Prefixes from different address families are never compared.  A root is
    keyed by ``(family, prefix)`` so an identical textual prefix cannot merge
    the IPv4 and IPv6 deployment units.  The pooled view is used only to make
    the main partial-deployment comparison; the family-specific grid remains
    available as an audit artifact.
    """

    if rollout_count <= 0:
        raise ValueError("rollout_count must be positive")

    pooled_candidates = list(candidates)
    roots = sorted(
        {(candidate.family, candidate.root_prefix) for candidate in pooled_candidates}
    )
    root_to_index = {root: index for index, root in enumerate(roots)}
    candidate_root_index = np.asarray(
        [
            root_to_index[(candidate.family, candidate.root_prefix)]
            for candidate in pooled_candidates
        ],
        dtype=np.int16,
    )
    fanout_counter = Counter(
        (candidate.family, candidate.root_prefix) for candidate in pooled_candidates
    )

    n_candidates = len(pooled_candidates)
    n_roots = len(roots)
    expected_candidates = sum(EXPECTED_FAMILY_COUNTS.values())
    expected_roots = sum(EXPECTED_ROOT_COUNTS.values())
    if n_candidates != expected_candidates or n_roots != expected_roots:
        raise ValueError(
            "pooled corpus changed: "
            f"expected {expected_candidates} candidates under {expected_roots} roots, "
            f"observed {n_candidates} under {n_roots}"
        )

    exact_ranks = _rank_matrix(
        n_candidates, "Combined", "endpoint", rollout_count, master_seed
    )
    root_ranks = _rank_matrix(
        n_roots, "Combined", "root", rollout_count, master_seed
    )
    candidate_root_ranks = root_ranks[:, candidate_root_index]
    rows: list[dict[str, Any]] = []

    for exact_target in TARGET_PERCENTS:
        exact_selected_count = math.floor(n_candidates * exact_target / 100)
        lacks_exact = exact_ranks >= exact_selected_count
        baseline_remaining = n_candidates - exact_selected_count
        for scope_target in POOLED_SCOPE_TARGETS:
            scope_selected_count = math.floor(n_roots * scope_target / 100)
            root_is_marked = candidate_root_ranks < scope_selected_count
            remaining = np.count_nonzero(lacks_exact & ~root_is_marked, axis=1)
            avoided = baseline_remaining - remaining
            remaining_stats = _distribution(remaining, n_candidates)
            avoided_stats = _distribution(avoided, n_candidates)
            efficiency_stats = (
                _summarize(avoided / scope_selected_count)
                if scope_selected_count > 0
                else {statistic: None for statistic in _summarize(avoided).keys()}
            )
            row: dict[str, Any] = {
                "family": "Combined",
                "root_order": "random",
                "exact_target_percent": exact_target,
                "scope_target_percent": scope_target,
                "candidate_count": n_candidates,
                "root_count": n_roots,
                "exact_selected_count": exact_selected_count,
                "scope_selected_root_count": scope_selected_count,
                "exact_achieved_percent": exact_selected_count * 100.0 / n_candidates,
                "scope_achieved_percent": scope_selected_count * 100.0 / n_roots,
            }
            for prefix, stats in (
                ("remaining", remaining_stats),
                ("avoided", avoided_stats),
            ):
                for unit in ("count", "percent"):
                    for statistic, value in stats[unit].items():
                        row[f"{prefix}_{unit}_{statistic}"] = value
            for statistic, value in efficiency_stats.items():
                row[f"avoided_per_scope_root_{statistic}"] = value
            rows.append(row)

    metadata = {
        "candidate_count": n_candidates,
        "root_count": n_roots,
        "family_counts": dict(Counter(candidate.family for candidate in candidates)),
        "root_counts": dict(EXPECTED_ROOT_COUNTS),
        "fanout_min": min(fanout_counter.values()),
        "fanout_median": float(np.median(list(fanout_counter.values()))),
        "fanout_max": max(fanout_counter.values()),
        "largest_roots": [
            {
                "family": family,
                "root_prefix": root_prefix,
                "candidate_rows": count,
            }
            for (family, root_prefix), count in sorted(
                fanout_counter.items(),
                key=lambda item: (-item[1], item[0][0], item[0][1]),
            )[:5]
        ],
        "selection_sha256": _selection_hash(exact_ranks, root_ranks),
    }
    validate_pooled_deployment(rows)
    return rows, metadata


def _pooled_rows_by_key(
    rows: Sequence[dict[str, Any]],
) -> dict[tuple[int, int], dict[str, Any]]:
    return {
        (
            int(row["exact_target_percent"]),
            int(row["scope_target_percent"]),
        ): row
        for row in rows
    }


def validate_pooled_deployment(rows: Sequence[dict[str, Any]]) -> None:
    expected_rows = len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS)
    keyed = _pooled_rows_by_key(rows)
    if len(rows) != expected_rows or len(keyed) != expected_rows:
        raise ValueError("pooled deployment grid is incomplete or nonunique")

    n_candidates = sum(EXPECTED_FAMILY_COUNTS.values())
    tolerance = 1e-9
    for exact_target in TARGET_PERCENTS:
        baseline = n_candidates - math.floor(n_candidates * exact_target / 100)
        previous_scope = float("inf")
        for scope_target in POOLED_SCOPE_TARGETS:
            row = keyed[(exact_target, scope_target)]
            remaining = float(row["remaining_count_median"])
            avoided = float(row["avoided_count_median"])
            if remaining > previous_scope + tolerance:
                raise ValueError("pooled conflicts increase with OpenScope deployment")
            if abs((remaining + avoided) - baseline) > tolerance:
                raise ValueError("pooled avoided and remaining counts do not close")
            previous_scope = remaining
        if keyed[(exact_target, 100)]["remaining_count_max"] != 0:
            raise ValueError("full pooled OpenScope leaves a potential conflict")

    for scope_target in POOLED_SCOPE_TARGETS:
        previous_exact = float("inf")
        for exact_target in TARGET_PERCENTS:
            remaining = float(
                keyed[(exact_target, scope_target)]["remaining_count_median"]
            )
            if remaining > previous_exact + tolerance:
                raise ValueError("pooled conflicts increase with ROA issuance")
            previous_exact = remaining
        if keyed[(100, scope_target)]["remaining_count_max"] != 0:
            raise ValueError("full pooled ROA issuance leaves a potential conflict")


REFERENCE_STATE_CODES = {
    ValidationState.EXPLICIT: 0,
    ValidationState.DELEGATED: 1,
    ValidationState.INVALID: 2,
    ValidationState.NOT_FOUND: 3,
}
STATE_FIELD_BY_CODE = {
    0: "explicit",
    1: "open_scope",
    2: "invalid",
    3: "not_found",
}


def _state_counts(states: Sequence[ValidationState]) -> dict[str, int]:
    counts = Counter(STATE_FIELD_BY_CODE[REFERENCE_STATE_CODES[state]] for state in states)
    return {state: counts.get(state, 0) for state in CONFLICT_STATES}


def build_reference_route_states(
    candidates: Sequence[Candidate],
) -> tuple[dict[str, np.ndarray], dict[str, Any]]:
    """Evaluate every route under the local states used by the rollout.

    Endpoint-prefix bundles are noncovering.  We therefore evaluate an unmarked
    root, a marked root, an exact downstream record, and an exact record that
    coexists with a base marker once with the reference engine.  Explicit origin
    matches take precedence over marker membership, and the verified local
    states are composed across the randomized deployment matrix.
    """

    roots = sorted({(candidate.family, candidate.root_prefix) for candidate in candidates})
    root_to_index = {root: index for index, root in enumerate(roots)}
    grouped: dict[tuple[str, str], list[Candidate]] = {
        root: [
            candidate
            for candidate in candidates
            if (candidate.family, candidate.root_prefix) == root
        ]
        for root in roots
    }

    unmarked_policies: dict[tuple[str, str], S2ROV] = {}
    marked_policies: dict[tuple[str, str], S2ROV] = {}
    aggregate_policies: dict[tuple[str, str], S2ROV] = {}
    root_route_states: list[ValidationState] = []
    for root, root_candidates in grouped.items():
        root_origins = root_candidates[0].root_origins
        if any(candidate.root_origins != root_origins for candidate in root_candidates):
            raise ValueError(f"root origin set changes within {root}")
        maximum_length = max(
            ipaddress.ip_network(candidate.endpoint_prefix).prefixlen
            for candidate in root_candidates
        )
        base_prefix = root[1]
        holder = root_origins[0]
        unmarked_base = Stripe(base_prefix, frozenset(root_origins), False)
        marked_base = Stripe(base_prefix, frozenset(root_origins), True)
        unmarked_policies[root] = S2ROV(
            base_prefix, maximum_length, holder, (unmarked_base,)
        )
        marked_policies[root] = S2ROV(
            base_prefix, maximum_length, holder, (marked_base,)
        )
        aggregate_policies[root] = S2ROV(
            base_prefix,
            ipaddress.ip_network(base_prefix).prefixlen,
            holder,
            (unmarked_base,),
        )
        for root_origin in root_origins:
            root_route_states.extend(
                (
                    unmarked_policies[root].validate_route(base_prefix, root_origin),
                    marked_policies[root].validate_route(base_prefix, root_origin),
                    aggregate_policies[root].validate_route(base_prefix, root_origin),
                )
            )

    route_candidate_index: list[int] = []
    route_root_index: list[int] = []
    route_origins: list[int] = []
    unmarked_states: list[ValidationState] = []
    marked_states: list[ValidationState] = []
    exact_states: list[ValidationState] = []
    exact_marked_states: list[ValidationState] = []
    aggregate_states: list[ValidationState] = []
    ineligible_routes: list[dict[str, Any]] = []

    for candidate_index, candidate in enumerate(candidates):
        root = (candidate.family, candidate.root_prefix)
        maximum_length = unmarked_policies[root].max_length
        unmarked_base = Stripe(
            candidate.root_prefix, frozenset(candidate.root_origins), False
        )
        marked_base = Stripe(
            candidate.root_prefix, frozenset(candidate.root_origins), True
        )
        exact_rule = Stripe(
            candidate.endpoint_prefix, frozenset(candidate.endpoint_origins), False
        )
        exact_policy = S2ROV(
            candidate.root_prefix,
            maximum_length,
            candidate.root_origins[0],
            (unmarked_base, exact_rule),
        )
        exact_marked_policy = S2ROV(
            candidate.root_prefix,
            maximum_length,
            candidate.root_origins[0],
            (marked_base, exact_rule),
        )
        for origin in candidate.endpoint_origins:
            unmarked_state = unmarked_policies[root].validate_route(
                candidate.endpoint_prefix, origin
            )
            marked_state = marked_policies[root].validate_route(
                candidate.endpoint_prefix, origin
            )
            exact_state = exact_policy.validate_route(candidate.endpoint_prefix, origin)
            exact_marked_state = exact_marked_policy.validate_route(
                candidate.endpoint_prefix, origin
            )
            aggregate_state = aggregate_policies[root].validate_route(
                candidate.endpoint_prefix, origin
            )
            route_candidate_index.append(candidate_index)
            route_root_index.append(root_to_index[root])
            route_origins.append(origin)
            unmarked_states.append(unmarked_state)
            marked_states.append(marked_state)
            exact_states.append(exact_state)
            exact_marked_states.append(exact_marked_state)
            aggregate_states.append(aggregate_state)
            if marked_state is ValidationState.INVALID:
                ineligible_routes.append(
                    {
                        "family": candidate.family,
                        "prefix": candidate.endpoint_prefix,
                        "origin": origin,
                    }
                )

    route_count = sum(EXPECTED_ROUTE_COUNTS.values())
    if len(route_origins) != route_count:
        raise ValueError(f"reference route table has {len(route_origins)} rows")
    if any(state is not ValidationState.EXPLICIT for state in root_route_states):
        raise ValueError("a retained root route is not Explicit")
    if any(state is not ValidationState.INVALID for state in aggregate_states):
        raise ValueError("aggregate-only policy does not make every endpoint Invalid")
    if any(state is not ValidationState.INVALID for state in unmarked_states):
        raise ValueError("unmarked root policy does not make every endpoint Invalid")
    if any(state is not ValidationState.EXPLICIT for state in exact_states):
        raise ValueError("a selected exact bundle is not Explicit")
    if any(state is not ValidationState.EXPLICIT for state in exact_marked_states):
        raise ValueError(
            "an exact downstream record does not remain Explicit with a base marker"
        )

    arrays = {
        "candidate_index": np.asarray(route_candidate_index, dtype=np.int16),
        "root_index": np.asarray(route_root_index, dtype=np.int16),
        "unmarked": np.asarray(
            [REFERENCE_STATE_CODES[state] for state in unmarked_states], dtype=np.int8
        ),
        "marked": np.asarray(
            [REFERENCE_STATE_CODES[state] for state in marked_states], dtype=np.int8
        ),
        "exact": np.asarray(
            [REFERENCE_STATE_CODES[state] for state in exact_states], dtype=np.int8
        ),
        "exact_marked": np.asarray(
            [REFERENCE_STATE_CODES[state] for state in exact_marked_states],
            dtype=np.int8,
        ),
    }
    state_digest = hashlib.sha256()
    for name in (
        "candidate_index",
        "root_index",
        "unmarked",
        "marked",
        "exact",
        "exact_marked",
    ):
        state_digest.update(name.encode("ascii"))
        state_digest.update(arrays[name].tobytes(order="C"))

    metadata = {
        "endpoint_prefix_count": len(candidates),
        "route_origin_count": route_count,
        "route_origin_counts": dict(EXPECTED_ROUTE_COUNTS),
        "root_count": len(roots),
        "root_route_checks": len(root_route_states),
        "reference_state_counts": {
            "aggregate_only": _state_counts(aggregate_states),
            "unmarked_root": _state_counts(unmarked_states),
            "marked_root": _state_counts(marked_states),
            "exact": _state_counts(exact_states),
            "exact_with_marked_root": _state_counts(exact_marked_states),
        },
        "ineligible_routes": ineligible_routes,
        "state_table_sha256": state_digest.hexdigest(),
        "reference_classifier": relative_to_repo(REFERENCE_SCRIPTS / "utils" / "s2rov.py"),
        "reference_classifier_sha256": sha256_file(
            REFERENCE_SCRIPTS / "utils" / "s2rov.py"
        ),
    }
    return arrays, metadata


def _conflict_rows_by_key(
    rows: Sequence[dict[str, Any]],
) -> dict[tuple[int, int], dict[str, Any]]:
    return {
        (
            int(row["downstream_roa_target_percent"]),
            int(row["scope_target_percent"]),
        ): row
        for row in rows
    }


def compute_route_state_replay(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Classify all observed route-origin pairs at every rollout snapshot."""

    if rollout_count <= 0:
        raise ValueError("rollout_count must be positive")
    reference, reference_metadata = build_reference_route_states(candidates)
    roots = sorted({(candidate.family, candidate.root_prefix) for candidate in candidates})
    n_candidates = len(candidates)
    n_routes = int(reference_metadata["route_origin_count"])
    n_roots = len(roots)
    exact_ranks = _rank_matrix(
        n_candidates, "Combined", "endpoint", rollout_count, master_seed
    )
    root_ranks = _rank_matrix(
        n_roots, "Combined", "root", rollout_count, master_seed
    )
    route_candidate_index = reference["candidate_index"]
    route_root_index = reference["root_index"]
    oracle_eligible = _oracle_route_eligibility(candidates)
    reference_eligible = (
        reference["marked"]
        == REFERENCE_STATE_CODES[ValidationState.DELEGATED]
    )
    if not np.array_equal(oracle_eligible, reference_eligible):
        raise ValueError("raw-origin eligibility disagrees with the reference classifier")
    oracle_ineligible = ~oracle_eligible
    rows: list[dict[str, Any]] = []
    previous_q_invalid: dict[int, np.ndarray] = {}

    for downstream_target in TARGET_PERCENTS:
        selected_prefix_count = math.floor(n_candidates * downstream_target / 100)
        exact_active = exact_ranks[:, route_candidate_index] < selected_prefix_count
        previous_scope_invalid = np.full(rollout_count, n_routes + 1, dtype=np.int32)
        for scope_target in POOLED_SCOPE_TARGETS:
            selected_root_count = math.floor(n_roots * scope_target / 100)
            root_marked = root_ranks[:, route_root_index] < selected_root_count
            states = np.where(
                exact_active,
                np.where(
                    root_marked, reference["exact_marked"], reference["exact"]
                ),
                np.where(root_marked, reference["marked"], reference["unmarked"]),
            )
            state_counts = {
                state: np.count_nonzero(states == code, axis=1)
                for code, state in STATE_FIELD_BY_CODE.items()
            }
            partition = sum(state_counts.values())
            if not np.all(partition == n_routes):
                raise ValueError("route states do not partition the replay corpus")

            oracle_invalid = np.count_nonzero(
                ~exact_active
                & (
                    ~root_marked
                    | oracle_ineligible[np.newaxis, :]
                ),
                axis=1,
            )
            if not np.array_equal(state_counts["invalid"], oracle_invalid):
                raise ValueError("reference-state replay disagrees with the independent oracle")
            if np.any(state_counts["invalid"] > previous_scope_invalid):
                raise ValueError("Invalid count rises with OpenScope deployment")
            previous_scope_invalid = state_counts["invalid"].copy()
            previous_for_scope = previous_q_invalid.get(scope_target)
            if previous_for_scope is not None and np.any(
                state_counts["invalid"] > previous_for_scope
            ):
                raise ValueError("Invalid count rises with downstream ROA deployment")
            previous_q_invalid[scope_target] = state_counts["invalid"].copy()

            row: dict[str, Any] = {
                "family": "Combined",
                "root_order": "random",
                "downstream_roa_target_percent": downstream_target,
                "scope_target_percent": scope_target,
                "endpoint_prefix_count": n_candidates,
                "route_origin_count": n_routes,
                "root_count": n_roots,
                "downstream_selected_prefix_count": selected_prefix_count,
                "scope_selected_root_count": selected_root_count,
                "downstream_achieved_percent": selected_prefix_count
                * 100.0
                / n_candidates,
                "scope_achieved_percent": selected_root_count * 100.0 / n_roots,
            }
            for state in CONFLICT_STATES:
                summary = _summarize(state_counts[state])
                for statistic in CONFLICT_STATISTICS:
                    row[f"{state}_count_{statistic}"] = summary[statistic]
            rows.append(row)

    validate_route_state_replay(rows)
    metadata = {
        **reference_metadata,
        "selection_sha256": _selection_hash(exact_ranks, root_ranks),
        "rollout_count": rollout_count,
        "master_seed": master_seed,
        "state_partition_verified": True,
        "independent_oracle_verified": True,
        "invalid_monotone_in_downstream_and_scope": True,
    }
    return rows, metadata


def validate_route_state_replay(rows: Sequence[dict[str, Any]]) -> None:
    expected_rows = len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS)
    keyed = _conflict_rows_by_key(rows)
    if len(rows) != expected_rows or len(keyed) != expected_rows:
        raise ValueError("route-state replay is incomplete or nonunique")

    n_routes = sum(EXPECTED_ROUTE_COUNTS.values())
    zero_unmarked = keyed[(0, 0)]
    if zero_unmarked["invalid_count_min"] != n_routes or zero_unmarked[
        "invalid_count_max"
    ] != n_routes:
        raise ValueError("aggregate-first snapshot does not make all endpoints Invalid")
    zero_full_scope = keyed[(0, 100)]
    if zero_full_scope["open_scope_count_min"] != n_routes - 1:
        raise ValueError("full OpenScope does not admit the 588 eligible routes")
    if zero_full_scope["invalid_count_min"] != 1 or zero_full_scope[
        "invalid_count_max"
    ] != 1:
        raise ValueError("full OpenScope does not retain the ineligible route")

    tolerance = 1e-9
    for downstream_target in TARGET_PERCENTS:
        previous_scope = float("inf")
        for scope_target in POOLED_SCOPE_TARGETS:
            row = keyed[(downstream_target, scope_target)]
            invalid = float(row["invalid_count_median"])
            if invalid > previous_scope + tolerance:
                raise ValueError("median Invalid count rises with OpenScope")
            previous_scope = invalid
            if row["not_found_count_max"] != 0:
                raise ValueError("a route becomes NotFound while its root is present")
            mean_partition = sum(
                float(row[f"{state}_count_mean"]) for state in CONFLICT_STATES
            )
            if abs(mean_partition - n_routes) > tolerance:
                raise ValueError("mean route-state counts do not close")
        if keyed[(downstream_target, 100)]["invalid_count_max"] > 1:
            raise ValueError("full OpenScope leaves more than the ineligible route")

    for scope_target in POOLED_SCOPE_TARGETS:
        previous_downstream = float("inf")
        for downstream_target in TARGET_PERCENTS:
            invalid = float(keyed[(downstream_target, scope_target)]["invalid_count_median"])
            if invalid > previous_downstream + tolerance:
                raise ValueError("median Invalid count rises with downstream ROAs")
            previous_downstream = invalid
        full_exact = keyed[(100, scope_target)]
        if full_exact["invalid_count_max"] != 0:
            raise ValueError("full downstream ROA coverage leaves an Invalid route")
        if full_exact["explicit_count_min"] != n_routes:
            raise ValueError("full downstream ROA coverage is not fully Explicit")


def compute_deployment_conflict_curves(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the randomized deployment experiment used by the two main panels.

    Each rollout fixes three independent, nested random orders over the actual
    corpus: downstream endpoint-prefix bundles, root ROAs, and roots selected
    for OpenScope.  At one issuance target, the corresponding prefix and root
    counts are taken from the front of those orders.  The potential view holds
    every root ROA active.  The observed view instead activates only the root
    ROAs selected at that issuance target.  The reference classifier supplies
    the state of every observed route under each local policy state, and the
    experiment counts the resulting Invalid states for all 1,000 deployments.
    """

    if rollout_count <= 0:
        raise ValueError("rollout_count must be positive")

    reference, reference_metadata = build_reference_route_states(candidates)
    n_candidates = len(candidates)
    n_routes = int(reference_metadata["route_origin_count"])
    n_roots = int(reference_metadata["root_count"])
    expected_candidates = sum(EXPECTED_FAMILY_COUNTS.values())
    expected_routes = sum(EXPECTED_ROUTE_COUNTS.values())
    expected_roots = sum(EXPECTED_ROOT_COUNTS.values())
    if (n_candidates, n_routes, n_roots) != (
        expected_candidates,
        expected_routes,
        expected_roots,
    ):
        raise ValueError("deployment replay corpus changed")
    if n_routes != CONFLICT_RATE_DENOMINATOR:
        raise ValueError("conflict-rate denominator changed")

    endpoint_ranks = _rank_matrix(
        n_candidates,
        "Combined",
        "figure3-downstream-roa",
        rollout_count,
        master_seed,
    )
    root_roa_ranks = _rank_matrix(
        n_roots,
        "Combined",
        "figure3-root-roa",
        rollout_count,
        master_seed,
    )
    scope_ranks = _rank_matrix(
        n_roots,
        "Combined",
        "figure3-openscope",
        rollout_count,
        master_seed,
    )
    route_candidate_index = reference["candidate_index"]
    route_root_index = reference["root_index"]
    oracle_eligible = _oracle_route_eligibility(candidates)
    reference_eligible = (
        reference["marked"]
        == REFERENCE_STATE_CODES[ValidationState.DELEGATED]
    )
    if not np.array_equal(oracle_eligible, reference_eligible):
        raise ValueError("raw-origin eligibility disagrees with the reference classifier")
    ineligible = ~oracle_eligible
    not_found_code = REFERENCE_STATE_CODES[ValidationState.NOT_FOUND]
    invalid_code = REFERENCE_STATE_CODES[ValidationState.INVALID]

    rows: list[dict[str, Any]] = []
    for issuance_percent in TARGET_PERCENTS:
        downstream_selected = math.floor(n_candidates * issuance_percent / 100)
        root_roa_selected = math.floor(n_roots * issuance_percent / 100)
        exact_active = (
            endpoint_ranks[:, route_candidate_index] < downstream_selected
        )
        root_roa_active = root_roa_ranks[:, route_root_index] < root_roa_selected

        for scope_target in POOLED_SCOPE_TARGETS:
            scope_selected = math.floor(n_roots * scope_target / 100)
            root_marked = scope_ranks[:, route_root_index] < scope_selected
            active_root_state = np.where(
                root_marked,
                reference["marked"],
                reference["unmarked"],
            )
            exact_state = np.where(
                root_marked,
                reference["exact_marked"],
                reference["exact"],
            )
            potential_states = np.where(
                exact_active,
                exact_state,
                active_root_state,
            )
            observed_states = np.where(
                exact_active,
                exact_state,
                np.where(root_roa_active, active_root_state, not_found_code),
            )
            potential_conflicts = np.count_nonzero(
                potential_states == invalid_code, axis=1
            )
            observed_conflicts = np.count_nonzero(
                observed_states == invalid_code, axis=1
            )

            potential_oracle = np.count_nonzero(
                ~exact_active & (~root_marked | ineligible[np.newaxis, :]),
                axis=1,
            )
            observed_oracle = np.count_nonzero(
                root_roa_active
                & ~exact_active
                & (~root_marked | ineligible[np.newaxis, :]),
                axis=1,
            )
            if not np.array_equal(potential_conflicts, potential_oracle):
                raise ValueError("potential replay disagrees with the oracle")
            if not np.array_equal(observed_conflicts, observed_oracle):
                raise ValueError("observed replay disagrees with the oracle")

            row: dict[str, Any] = {
                "roa_issuance_percent": issuance_percent,
                "rollout_count": rollout_count,
                "endpoint_prefix_count": n_candidates,
                "route_origin_count": n_routes,
                "root_count": n_roots,
                "downstream_selected_prefix_count": downstream_selected,
                "root_roa_selected_count": root_roa_selected,
                "scope_target_percent": scope_target,
                "scope_selected_root_count": scope_selected,
                "downstream_achieved_percent": 100.0
                * downstream_selected
                / n_candidates,
                "root_roa_achieved_percent": 100.0 * root_roa_selected / n_roots,
                "scope_achieved_percent": 100.0 * scope_selected / n_roots,
                "conflict_rate_denominator": CONFLICT_RATE_DENOMINATOR,
            }
            for outcome, values in (
                ("potential_conflicts", potential_conflicts),
                ("observed_conflicts", observed_conflicts),
            ):
                summary = _summarize(values)
                percent_summary = _summarize(
                    np.asarray(values, dtype=np.float64)
                    * 100.0
                    / CONFLICT_RATE_DENOMINATOR
                )
                for statistic in CONFLICT_STATISTICS:
                    row[f"{outcome}_{statistic}"] = summary[statistic]
                    row[f"{outcome}_percent_{statistic}"] = percent_summary[
                        statistic
                    ]
            rows.append(row)

    metadata = {
        **reference_metadata,
        "rollout_count": rollout_count,
        "master_seed": master_seed,
        "selection_sha256": _selection_hash(
            endpoint_ranks, root_roa_ranks, scope_ranks
        ),
        "placement_units": {
            "downstream_roa": n_candidates,
            "root_roa": n_roots,
            "openscope": n_roots,
        },
        "placements_independent": True,
        "placements_nested_within_each_rollout": True,
        "conflict_rate_denominator": CONFLICT_RATE_DENOMINATOR,
        "reference_state_replay_verified": True,
        "independent_oracle_verified": True,
    }
    validate_deployment_conflict_curves(rows)
    return rows, metadata


def _deployment_curve_rows_by_key(
    rows: Sequence[dict[str, Any]],
) -> dict[tuple[int, int], dict[str, Any]]:
    return {
        (
            int(row["roa_issuance_percent"]),
            int(row["scope_target_percent"]),
        ): row
        for row in rows
    }


def validate_deployment_conflict_curves(rows: Sequence[dict[str, Any]]) -> None:
    """Validate the empirical deployment summaries used by Figure 2."""

    expected_rows = len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS)
    keyed = _deployment_curve_rows_by_key(rows)
    if len(rows) != expected_rows or len(keyed) != expected_rows:
        raise ValueError("deployment curve grid is incomplete or nonunique")

    tolerance = 1e-9
    for scope_target in POOLED_SCOPE_TARGETS:
        potential = np.asarray(
            [
                keyed[(issuance, scope_target)]["potential_conflicts_mean"]
                for issuance in TARGET_PERCENTS
            ],
            dtype=np.float64,
        )
        observed = np.asarray(
            [
                keyed[(issuance, scope_target)]["observed_conflicts_mean"]
                for issuance in TARGET_PERCENTS
            ],
            dtype=np.float64,
        )
        if np.any(np.diff(potential) > tolerance):
            raise ValueError("potential conflicts rise with downstream ROAs")
        if abs(potential[-1]) > tolerance or abs(observed[-1]) > tolerance:
            raise ValueError("potential conflicts remain at full issuance")
        if abs(observed[0]) > tolerance or abs(observed[-1]) > tolerance:
            raise ValueError("observed conflicts do not vanish at both endpoints")
        if np.any(observed - potential > tolerance):
            raise ValueError("observed conflicts exceed potential conflicts")
        peak = int(np.argmax(observed))
        if peak not in (
            TARGET_PERCENTS.index(40),
            TARGET_PERCENTS.index(50),
            TARGET_PERCENTS.index(60),
        ):
            raise ValueError("an observed-conflict series lacks an interior peak")

        for issuance_percent in TARGET_PERCENTS:
            row = keyed[(issuance_percent, scope_target)]
            if int(row["conflict_rate_denominator"]) != CONFLICT_RATE_DENOMINATOR:
                raise ValueError("deployment conflict-rate denominator changed")
            for outcome in ("potential_conflicts", "observed_conflicts"):
                minimum = float(row[f"{outcome}_min"])
                p05 = float(row[f"{outcome}_p05"])
                median = float(row[f"{outcome}_median"])
                mean = float(row[f"{outcome}_mean"])
                p95 = float(row[f"{outcome}_p95"])
                maximum = float(row[f"{outcome}_max"])
                if not (minimum <= p05 <= median <= p95 <= maximum):
                    raise ValueError(f"{outcome} summary statistics are unordered")
                if not minimum - tolerance <= mean <= maximum + tolerance:
                    raise ValueError(f"{outcome} mean lies outside its range")
                for statistic in CONFLICT_STATISTICS:
                    expected_percent = (
                        100.0
                        * float(row[f"{outcome}_{statistic}"])
                        / CONFLICT_RATE_DENOMINATOR
                    )
                    if not math.isclose(
                        float(row[f"{outcome}_percent_{statistic}"]),
                        expected_percent,
                        rel_tol=0.0,
                        abs_tol=tolerance,
                    ):
                        raise ValueError(
                            f"{outcome} conflict rate uses the wrong denominator"
                        )

    if abs(keyed[(0, 0)]["potential_conflicts_mean"] - 589.0) > tolerance:
        raise ValueError("no-OpenScope potential baseline changed")
    if abs(keyed[(0, 100)]["potential_conflicts_mean"] - 1.0) > tolerance:
        raise ValueError("full OpenScope does not retain the ineligible route")

    for issuance_percent in TARGET_PERCENTS:
        previous_potential = float("inf")
        previous_observed = float("inf")
        for scope_target in POOLED_SCOPE_TARGETS:
            row = keyed[(issuance_percent, scope_target)]
            potential = float(row["potential_conflicts_mean"])
            observed = float(row["observed_conflicts_mean"])
            if potential > previous_potential + tolerance:
                raise ValueError("OpenScope raises potential conflicts")
            if observed > previous_observed + tolerance:
                raise ValueError("OpenScope raises observed conflicts")
            previous_potential = potential
            previous_observed = observed


def _placement_rows_by_key(
    rows: Sequence[dict[str, Any]],
) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (row["strategy"], int(row["scope_target_percent"])): row
        for row in rows
    }


def compute_openscope_placement(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
    placement_scores: dict[int, dict[str, int]] | None = None,
    placement_score_metadata: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compare root placement orders at fixed downstream ROA issuance.

    The experiment uses the same pooled route-state table and downstream ROA
    samples as the potential-conflict panel.  It compares route-count, ASRank,
    AS-degree, and random root orders.  Seeded score ties preserve nested root
    budgets without introducing a prefix-lexicographic placement preference.
    """

    if rollout_count <= 0:
        raise ValueError("rollout_count must be positive")
    if placement_scores is None:
        if placement_score_metadata is not None:
            raise ValueError("placement-score metadata was supplied without scores")
        placement_scores, placement_score_metadata = load_placement_scores()
    elif placement_score_metadata is None:
        raise ValueError("placement scores require their source metadata")

    reference, reference_metadata = build_reference_route_states(candidates)
    roots = sorted({(candidate.family, candidate.root_prefix) for candidate in candidates})
    n_candidates = len(candidates)
    n_routes = int(reference_metadata["route_origin_count"])
    n_roots = len(roots)
    if (n_candidates, n_routes, n_roots) != (587, 589, 97):
        raise ValueError("OpenScope placement corpus changed")
    if n_routes != CONFLICT_RATE_DENOMINATOR:
        raise ValueError("conflict-rate denominator changed")

    root_origins: dict[tuple[str, str], int] = {}
    for candidate in candidates:
        if len(candidate.root_origins) != 1:
            raise ValueError("placement requires one observed aggregate origin per root")
        root = (candidate.family, candidate.root_prefix)
        previous = root_origins.setdefault(root, candidate.root_origins[0])
        if previous != candidate.root_origins[0]:
            raise ValueError("observed aggregate origin changes within a root")
    required_asns = set(root_origins.values())
    if set(placement_scores) != required_asns:
        missing = sorted(required_asns - set(placement_scores))
        extra = sorted(set(placement_scores) - required_asns)
        raise ValueError(
            f"placement-score ASN coverage changed; missing={missing}, extra={extra}"
        )

    endpoint_ranks = _rank_matrix(
        n_candidates,
        "Combined",
        "figure3-downstream-roa",
        rollout_count,
        master_seed,
    )
    random_root_ranks = _rank_matrix(
        n_roots,
        "Combined",
        "figure3-openscope",
        rollout_count,
        master_seed,
    )
    score_tie_ranks = _rank_matrix(
        n_roots,
        "Combined",
        "figure3-score-ties",
        rollout_count,
        master_seed,
    )
    route_candidate_index = reference["candidate_index"]
    route_root_index = reference["root_index"]
    eligible = _oracle_route_eligibility(candidates)
    reference_eligible = (
        reference["marked"]
        == REFERENCE_STATE_CODES[ValidationState.DELEGATED]
    )
    if not np.array_equal(eligible, reference_eligible):
        raise ValueError("raw-origin eligibility disagrees with the reference classifier")
    root_route_loads = np.bincount(
        route_root_index,
        weights=eligible.astype(np.int16),
        minlength=n_roots,
    ).astype(np.int16)
    load_by_root = {
        root: int(root_route_loads[index]) for index, root in enumerate(roots)
    }
    most_ranks = _deterministic_root_ranks(
        roots, load_by_root, "fanout-first"
    )
    asrank_score_by_root = {
        root: placement_scores[root_origins[root]]["customer_cone_asns"]
        for root in roots
    }
    degree_score_by_root = {
        root: placement_scores[root_origins[root]]["total_degree"]
        for root in roots
    }
    asrank_ranks = _scored_root_rank_matrix(
        roots,
        asrank_score_by_root,
        score_tie_ranks,
        descending=True,
    )
    degree_ranks = _scored_root_rank_matrix(
        roots,
        degree_score_by_root,
        score_tie_ranks,
        descending=True,
    )
    root_ranks_by_strategy = {
        "most-routes-first": np.broadcast_to(
            most_ranks, (rollout_count, n_roots)
        ),
        "asrank-first": asrank_ranks,
        "degree-first": degree_ranks,
        "random": random_root_ranks,
    }

    downstream_selected = math.floor(
        n_candidates * PLACEMENT_ROA_TARGET_PERCENT / 100
    )
    exact_active = (
        endpoint_ranks[:, route_candidate_index] < downstream_selected
    )
    invalid_code = REFERENCE_STATE_CODES[ValidationState.INVALID]
    ineligible = ~eligible
    rows: list[dict[str, Any]] = []

    for strategy in PLACEMENT_STRATEGIES:
        candidate_root_ranks = root_ranks_by_strategy[strategy][
            :, route_root_index
        ]
        for scope_target in TARGET_PERCENTS:
            scope_selected = math.floor(n_roots * scope_target / 100)
            root_marked = candidate_root_ranks < scope_selected
            states = np.where(
                exact_active,
                np.where(
                    root_marked, reference["exact_marked"], reference["exact"]
                ),
                np.where(root_marked, reference["marked"], reference["unmarked"]),
            )
            potential_conflicts = np.count_nonzero(
                states == invalid_code, axis=1
            )
            oracle = np.count_nonzero(
                ~exact_active
                & (~root_marked | ineligible[np.newaxis, :]),
                axis=1,
            )
            if not np.array_equal(potential_conflicts, oracle):
                raise ValueError("OpenScope placement disagrees with the oracle")

            row: dict[str, Any] = {
                "strategy": strategy,
                "roa_issuance_percent": PLACEMENT_ROA_TARGET_PERCENT,
                "scope_target_percent": scope_target,
                "rollout_count": rollout_count,
                "endpoint_prefix_count": n_candidates,
                "route_origin_count": n_routes,
                "root_count": n_roots,
                "downstream_selected_prefix_count": downstream_selected,
                "scope_selected_root_count": scope_selected,
                "scope_achieved_percent": 100.0 * scope_selected / n_roots,
                "conflict_rate_denominator": CONFLICT_RATE_DENOMINATOR,
            }
            summary = _summarize(potential_conflicts)
            percent_summary = _summarize(
                np.asarray(potential_conflicts, dtype=np.float64)
                * 100.0
                / CONFLICT_RATE_DENOMINATOR
            )
            for statistic in CONFLICT_STATISTICS:
                row[f"potential_conflicts_{statistic}"] = summary[statistic]
                row[f"potential_conflicts_percent_{statistic}"] = (
                    percent_summary[statistic]
                )
            rows.append(row)

    metadata = {
        **reference_metadata,
        "rollout_count": rollout_count,
        "master_seed": master_seed,
        "roa_issuance_percent": PLACEMENT_ROA_TARGET_PERCENT,
        "downstream_selected_prefix_count": downstream_selected,
        "strategies": list(PLACEMENT_STRATEGIES),
        "root_scores": {
            "most-routes-first": (
                "eligible observed route-origin pairs below the root"
            ),
            "asrank-first": (
                "aggregate-origin ASN customer-cone order from CAIDA ASRank"
            ),
            "degree-first": (
                "aggregate-origin ASN total degree in the same CAIDA graph"
            ),
            "random": "uniform seeded root permutation",
        },
        "score_tie_break": (
            "independent fixed-seed random order within equal score groups; "
            "nested within each rollout"
        ),
        "placement_score_input": placement_score_metadata,
        "placement_score_coverage": {
            "roots": len(root_origins),
            "unique_aggregate_origin_asns": len(required_asns),
            "covered_asns": len(placement_scores),
        },
        "root_route_load_min": int(np.min(root_route_loads)),
        "root_route_load_median": float(np.median(root_route_loads)),
        "root_route_load_max": int(np.max(root_route_loads)),
        "root_route_load_sum": int(np.sum(root_route_loads)),
        "largest_roots": [
            {
                "family": root[0],
                "root_prefix": root[1],
                "eligible_observed_routes": load,
            }
            for root, load in sorted(
                load_by_root.items(), key=lambda item: (-item[1], item[0])
            )[:5]
        ],
        "selection_sha256": _selection_hash(
            endpoint_ranks,
            random_root_ranks,
            root_ranks_by_strategy["most-routes-first"],
            root_ranks_by_strategy["asrank-first"],
            root_ranks_by_strategy["degree-first"],
        ),
        "reference_state_replay_verified": True,
        "independent_oracle_verified": True,
        "orders_nested_within_strategy": True,
        "conflict_rate_denominator": CONFLICT_RATE_DENOMINATOR,
    }
    validate_openscope_placement(rows)
    return rows, metadata


def validate_openscope_placement(rows: Sequence[dict[str, Any]]) -> None:
    expected_rows = len(PLACEMENT_STRATEGIES) * len(TARGET_PERCENTS)
    keyed = _placement_rows_by_key(rows)
    if len(rows) != expected_rows or len(keyed) != expected_rows:
        raise ValueError("OpenScope placement grid is incomplete or nonunique")

    tolerance = 1e-9
    for strategy in PLACEMENT_STRATEGIES:
        previous = float("inf")
        for scope_target in TARGET_PERCENTS:
            row = keyed[(strategy, scope_target)]
            if int(row["roa_issuance_percent"]) != PLACEMENT_ROA_TARGET_PERCENT:
                raise ValueError("OpenScope placement ROA target changed")
            expected_selected = math.floor(97 * scope_target / 100)
            if int(row["scope_selected_root_count"]) != expected_selected:
                raise ValueError("OpenScope placement root count is incorrect")
            if int(row["conflict_rate_denominator"]) != CONFLICT_RATE_DENOMINATOR:
                raise ValueError("placement conflict-rate denominator changed")
            conflicts = float(row["potential_conflicts_mean"])
            if conflicts > previous + tolerance:
                raise ValueError("placement conflicts increase with root budget")
            previous = conflicts
            minimum = float(row["potential_conflicts_min"])
            p05 = float(row["potential_conflicts_p05"])
            median = float(row["potential_conflicts_median"])
            p95 = float(row["potential_conflicts_p95"])
            maximum = float(row["potential_conflicts_max"])
            if not minimum <= p05 <= median <= p95 <= maximum:
                raise ValueError("placement summary statistics are unordered")
            if not minimum - tolerance <= conflicts <= maximum + tolerance:
                raise ValueError("placement mean lies outside its range")
            for statistic in CONFLICT_STATISTICS:
                expected_percent = (
                    100.0
                    * float(row[f"potential_conflicts_{statistic}"])
                    / CONFLICT_RATE_DENOMINATOR
                )
                if not math.isclose(
                    float(row[f"potential_conflicts_percent_{statistic}"]),
                    expected_percent,
                    rel_tol=0.0,
                    abs_tol=tolerance,
                ):
                    raise ValueError(
                        "placement conflict rate uses the wrong denominator"
                    )

    for scope_target in TARGET_PERCENTS:
        most = float(
            keyed[("most-routes-first", scope_target)][
                "potential_conflicts_mean"
            ]
        )
        for strategy in ("asrank-first", "degree-first", "random"):
            comparator = float(
                keyed[(strategy, scope_target)]["potential_conflicts_mean"]
            )
            if most > comparator + tolerance:
                raise ValueError("most-routes-first is not the lower envelope")

    for scope_target in (0, 100):
        endpoint_values = {
            round(
                float(
                    keyed[(strategy, scope_target)][
                        "potential_conflicts_mean"
                    ]
                ),
                12,
            )
            for strategy in PLACEMENT_STRATEGIES
        }
        if len(endpoint_values) != 1:
            raise ValueError("placement strategies disagree at an endpoint")


def compute_decision_budget(
    candidates: Sequence[Candidate],
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> list[dict[str, Any]]:
    """Compare equal counts of endpoint-path and root-scope decisions.

    One endpoint-path decision covers one candidate row.  One root-scope decision
    covers every candidate row grouped under that root.  Random root ordering
    varies across rollouts; fanout-first and fanout-last are deterministic.
    """

    budget_rows: list[dict[str, Any]] = []
    for family in ("IPv4", "IPv6"):
        family_candidates = [candidate for candidate in candidates if candidate.family == family]
        roots = sorted({candidate.root_prefix for candidate in family_candidates})
        root_to_index = {root: index for index, root in enumerate(roots)}
        candidate_root_index = np.asarray(
            [root_to_index[candidate.root_prefix] for candidate in family_candidates],
            dtype=np.int16,
        )
        fanout_counter = Counter(candidate.root_prefix for candidate in family_candidates)
        fanout = {root: fanout_counter[root] for root in roots}
        random_root_ranks = _rank_matrix(
            len(roots), family, "root", rollout_count, master_seed
        )
        first_ranks = _deterministic_root_ranks(roots, fanout, "fanout-first")
        last_ranks = _deterministic_root_ranks(roots, fanout, "fanout-last")
        ranks_by_strategy: dict[str, np.ndarray] = {
            "random": random_root_ranks,
            "fanout-first": np.broadcast_to(first_ranks, (rollout_count, len(roots))),
            "fanout-last": np.broadcast_to(last_ranks, (rollout_count, len(roots))),
        }
        n_candidates = len(family_candidates)
        n_roots = len(roots)
        for strategy in STRATEGIES:
            candidate_ranks = ranks_by_strategy[strategy][:, candidate_root_index]
            for budget in range(n_roots + 1):
                scope_avoided = np.count_nonzero(candidate_ranks < budget, axis=1)
                exact_avoided = min(budget, n_candidates)
                scope_distribution = _distribution(scope_avoided, n_candidates)
                gain_distribution = _summarize(scope_avoided - exact_avoided)
                efficiency_distribution = (
                    _summarize(scope_avoided / budget)
                    if budget > 0
                    else {statistic: None for statistic in _summarize(scope_avoided).keys()}
                )
                row: dict[str, Any] = {
                    "family": family,
                    "root_order": strategy,
                    "configuration_decisions": budget,
                    "candidate_count": n_candidates,
                    "root_count": n_roots,
                    "exact_paths_covered_count": exact_avoided,
                    "exact_paths_covered_percent": exact_avoided
                    * 100.0
                    / n_candidates,
                }
                for unit in ("count", "percent"):
                    for statistic, value in scope_distribution[unit].items():
                        row[f"scope_paths_covered_{unit}_{statistic}"] = value
                for statistic, value in efficiency_distribution.items():
                    row[f"scope_paths_per_decision_{statistic}"] = value
                for statistic, value in gain_distribution.items():
                    row[f"scope_minus_exact_paths_{statistic}"] = value
                budget_rows.append(row)
    validate_decision_budget(budget_rows)
    return budget_rows


def validate_decision_budget(rows: Sequence[dict[str, Any]]) -> None:
    keyed = {
        (
            row["family"],
            row["root_order"],
            int(row["configuration_decisions"]),
        ): row
        for row in rows
    }
    expected = sum(
        len(STRATEGIES) * (EXPECTED_ROOT_COUNTS[family] + 1)
        for family in EXPECTED_ROOT_COUNTS
    )
    if len(rows) != expected or len(keyed) != expected:
        raise ValueError("decision-budget grid is incomplete or nonunique")
    for family in ("IPv4", "IPv6"):
        n_candidates = EXPECTED_FAMILY_COUNTS[family]
        n_roots = EXPECTED_ROOT_COUNTS[family]
        for strategy in STRATEGIES:
            if keyed[(family, strategy, 0)]["scope_paths_covered_count_max"] != 0:
                raise ValueError("zero OpenScope decisions cover candidate paths")
            if keyed[(family, strategy, n_roots)][
                "scope_paths_covered_count_min"
            ] != n_candidates:
                raise ValueError("all root decisions do not cover all candidate paths")
            previous = -1.0
            for budget in range(n_roots + 1):
                value = float(
                    keyed[(family, strategy, budget)][
                        "scope_paths_covered_count_median"
                    ]
                )
                if value < previous:
                    raise ValueError("scope coverage decreases with decision count")
                previous = value


def _rows_by_key(grid: Sequence[dict[str, Any]]) -> dict[tuple[Any, ...], dict[str, Any]]:
    return {
        (
            row["family"],
            row["root_order"],
            int(row["exact_target_percent"]),
            int(row["scope_target_percent"]),
        ): row
        for row in grid
    }


def validate_grid(grid: Sequence[dict[str, Any]]) -> None:
    expected_rows = 2 * len(STRATEGIES) * len(TARGET_PERCENTS) ** 2
    if len(grid) != expected_rows:
        raise ValueError(f"grid has {len(grid)} rows; expected {expected_rows}")
    keyed = _rows_by_key(grid)
    if len(keyed) != expected_rows:
        raise ValueError("grid keys are not unique")

    tolerance = 1e-9
    for family in ("IPv4", "IPv6"):
        n_candidates = EXPECTED_FAMILY_COUNTS[family]
        for strategy in STRATEGIES:
            for exact_target in TARGET_PERCENTS:
                baseline = keyed[(family, strategy, exact_target, 0)]
                expected_baseline = n_candidates - math.floor(
                    n_candidates * exact_target / 100
                )
                if abs(baseline["remaining_count_mean"] - expected_baseline) > tolerance:
                    raise ValueError("scope-zero baseline does not match exact selection")
                previous_scope = float("inf")
                for scope_target in TARGET_PERCENTS:
                    row = keyed[(family, strategy, exact_target, scope_target)]
                    remaining = float(row["remaining_count_median"])
                    avoided = float(row["avoided_count_median"])
                    if remaining > previous_scope + tolerance:
                        raise ValueError("remaining conflicts increase with scope deployment")
                    previous_scope = remaining
                    if abs((remaining + avoided) - expected_baseline) > tolerance:
                        raise ValueError("avoided and remaining counts do not close")
                if keyed[(family, strategy, exact_target, 100)][
                    "remaining_count_max"
                ] != 0:
                    raise ValueError("full scope does not remove all potential conflicts")

            for scope_target in TARGET_PERCENTS:
                previous_exact = float("inf")
                for exact_target in TARGET_PERCENTS:
                    remaining = float(
                        keyed[(family, strategy, exact_target, scope_target)][
                            "remaining_count_median"
                        ]
                    )
                    if remaining > previous_exact + tolerance:
                        raise ValueError("remaining conflicts increase with exact coverage")
                    previous_exact = remaining
                if keyed[(family, strategy, 100, scope_target)][
                    "remaining_count_max"
                ] != 0:
                    raise ValueError("full exact coverage leaves a potential conflict")


def _format_grid_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (np.integer, int)):
        return str(int(value))
    if isinstance(value, (np.floating, float)):
        return f"{float(value):.6f}"
    return str(value)


def rows_csv_text(rows: Sequence[dict[str, Any]], fields: Sequence[str]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _format_grid_value(row[field]) for field in fields})
    return buffer.getvalue()


def grid_csv_text(grid: Sequence[dict[str, Any]]) -> str:
    return rows_csv_text(grid, GRID_FIELDS)


def configure_style() -> None:
    configure_body_font()
    mpl.rcParams.update(
        {
            "svg.fonttype": "none",
            "svg.hashsalt": "partial-policy-replay-v1",
            "pdf.fonttype": 42,
            "font.size": ACTIVE_BASE_FONTSIZE,
            "axes.labelsize": ACTIVE_AXIS_LABELSIZE,
            "xtick.labelsize": ACTIVE_TICK_LABELSIZE,
            "ytick.labelsize": ACTIVE_TICK_LABELSIZE,
            "legend.fontsize": ACTIVE_LEGEND_FONTSIZE,
            "axes.linewidth": 0.75,
            "axes.spines.top": True,
            "axes.spines.right": True,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.top": False,
            "ytick.right": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )


def _plot_matrix(grid: Sequence[dict[str, Any]], family: str) -> np.ndarray:
    keyed = _rows_by_key(grid)
    return np.asarray(
        [
            [
                keyed[(family, "random", exact_target, scope_target)][
                    "remaining_percent_median"
                ]
                for exact_target in TARGET_PERCENTS
            ]
            for scope_target in TARGET_PERCENTS
        ],
        dtype=np.float64,
    )


def draw_family_figure(
    grid: Sequence[dict[str, Any]], family: str, output_base: Path
) -> list[Path]:
    configure_style()
    matrix = _plot_matrix(grid, family)
    fig, ax = plt.subplots(figsize=(3.50, 3.08))
    fig.subplots_adjust(left=0.155, right=0.855, bottom=0.145, top=0.985)
    image = ax.imshow(
        matrix,
        origin="lower",
        interpolation="nearest",
        aspect="equal",
        cmap="OrRd",
        vmin=0.0,
        vmax=100.0,
    )
    tick_positions = np.arange(len(TARGET_PERCENTS))
    ax.set_xticks(tick_positions)
    ax.set_xticklabels([str(value) for value in TARGET_PERCENTS])
    ax.set_yticks(tick_positions)
    ax.set_yticklabels([str(value) for value in TARGET_PERCENTS])
    ax.set_xlabel(FIGURE_TEXT[0])
    ax.set_ylabel(FIGURE_TEXT[1])
    ax.tick_params(
        axis="both",
        which="both",
        length=0,
        width=0.6,
        direction="in",
        top=False,
        right=False,
        pad=1.5,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)

    norm = mpl.colors.Normalize(vmin=0.0, vmax=100.0)
    color_map = mpl.colormaps["OrRd"]
    for row_index in range(matrix.shape[0]):
        for column_index in range(matrix.shape[1]):
            value = matrix[row_index, column_index]
            red, green, blue, _ = color_map(norm(value))
            luminance = 0.299 * red + 0.587 * green + 0.114 * blue
            ax.text(
                column_index,
                row_index,
                f"{value:.1f}",
                ha="center",
                va="center",
                fontsize=5.0,
                color="white" if luminance < 0.52 else "#272727",
                clip_on=False,
            )

    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.035)
    colorbar.set_label(FIGURE_TEXT[2], fontsize=6.7)
    colorbar.set_ticks([0, 25, 50, 75, 100])
    colorbar.set_ticklabels([f"{value:.1f}" for value in [0, 25, 50, 75, 100]])
    colorbar.ax.tick_params(
        which="both",
        direction="in",
        labelsize=5.5,
        length=2.0,
        width=0.6,
        pad=1.5,
    )
    colorbar.outline.set_linewidth(0.55)

    creator = "Partial policy deployment replay"
    outputs = [
        output_base.with_suffix(".svg"),
        output_base.with_suffix(".pdf"),
        output_base.with_suffix(".tiff"),
    ]
    fig.savefig(
        outputs[0],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        facecolor="white",
    )
    fig.savefig(
        outputs[1],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        facecolor="white",
    )
    fig.savefig(
        outputs[2],
        format="tiff",
        dpi=600,
        facecolor="white",
    )
    plt.close(fig)
    return outputs


def draw_strategy_figure(
    grid: Sequence[dict[str, Any]], family: str, output_base: Path
) -> list[Path]:
    """Draw the q=50% placement-sensitivity view without point markers."""

    configure_style()
    keyed = _rows_by_key(grid)
    x = np.asarray(TARGET_PERCENTS, dtype=np.float64)

    def values(strategy: str, field: str) -> np.ndarray:
        return np.asarray(
            [
                keyed[(family, strategy, 50, scope_target)][field]
                for scope_target in TARGET_PERCENTS
            ],
            dtype=np.float64,
        )

    random_median = values("random", "remaining_percent_median")
    random_low = values("random", "remaining_percent_p025")
    random_high = values("random", "remaining_percent_p975")
    fanout_first = values("fanout-first", "remaining_percent_median")
    fanout_last = values("fanout-last", "remaining_percent_median")

    fig, ax = plt.subplots(figsize=(3.50, 1.92))
    fig.subplots_adjust(left=0.16, right=0.975, bottom=0.245, top=0.965)
    ax.fill_between(
        x,
        random_low,
        random_high,
        color="#C9D8EA",
        alpha=0.78,
        linewidth=0,
        label=FIGURE_TEXT[4],
        zorder=1,
    )
    ax.plot(
        x,
        random_median,
        color="#0F4D92",
        linewidth=1.55,
        linestyle="-",
        label=FIGURE_TEXT[3],
        zorder=3,
    )
    ax.plot(
        x,
        fanout_first,
        color="#2C7A78",
        linewidth=1.35,
        linestyle=(0, (4, 2)),
        label=FIGURE_TEXT[5],
        zorder=3,
    )
    ax.plot(
        x,
        fanout_last,
        color="#9A6500",
        linewidth=1.35,
        linestyle=(0, (1.4, 1.5)),
        label=FIGURE_TEXT[6],
        zorder=3,
    )
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 55)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_yticks([0, 10, 20, 30, 40, 50])
    ax.set_xlabel(FIGURE_TEXT[1])
    ax.set_ylabel(FIGURE_TEXT[2])
    ax.grid(axis="y", color="#D8D8D8", linewidth=0.45, linestyle=":")
    ax.set_axisbelow(True)
    ax.tick_params(
        axis="both",
        which="both",
        length=2.5,
        width=0.65,
        direction="in",
        top=False,
        right=False,
        pad=1.8,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)
    handles, labels = ax.get_legend_handles_labels()
    order = [1, 0, 2, 3]
    ax.legend(
        [handles[index] for index in order],
        [labels[index] for index in order],
        loc="upper right",
        ncol=2,
        frameon=False,
        fontsize=5.3,
        handlelength=2.4,
        columnspacing=0.9,
        borderaxespad=0.15,
    )

    creator = "Partial policy deployment order sensitivity"
    outputs = [
        output_base.with_suffix(".svg"),
        output_base.with_suffix(".pdf"),
        output_base.with_suffix(".tiff"),
    ]
    fig.savefig(
        outputs[0],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        facecolor="white",
    )
    fig.savefig(
        outputs[1],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        facecolor="white",
    )
    fig.savefig(
        outputs[2],
        format="tiff",
        dpi=600,
        facecolor="white",
    )
    plt.close(fig)
    return outputs


def _set_integer_major_ticks(
    ax: Axes,
    *,
    x_ticks: Sequence[int],
    y_ticks: Sequence[int],
) -> None:
    """Use fixed major ticks rendered as bare integers on both axes."""

    ax.xaxis.set_major_locator(FixedLocator(x_ticks))
    ax.xaxis.set_major_formatter(StrMethodFormatter("{x:.0f}"))
    ax.yaxis.set_major_locator(FixedLocator(y_ticks))
    ax.yaxis.set_major_formatter(StrMethodFormatter("{x:.0f}"))


def _deployment_conflict_series() -> tuple[tuple[Any, ...], ...]:
    """Return the shared line encoding for both Figure 2 panels and legend."""

    return (
        (0, FIGURE_TEXT[17], "#333333", "-", "o"),
        (20, FIGURE_TEXT[18], "#4477AA", (0, (5, 2)), "s"),
        (40, FIGURE_TEXT[19], "#228833", (0, (3, 1.6)), "^"),
        (60, FIGURE_TEXT[20], "#EE7733", (0, (5, 1.5, 1.2, 1.5)), "D"),
        (80, FIGURE_TEXT[21], "#AA3377", (0, (1.2, 1.4)), "v"),
        (100, FIGURE_TEXT[22], "#33AADD", (0, (7, 2)), "X"),
    )


def draw_deployment_conflict_legend(output_base: Path) -> list[Path]:
    """Export the one shared Figure 2 legend on its own fixed canvas."""

    configure_style()
    handles = [
        Line2D(
            [],
            [],
            color=color,
            linewidth=1.25,
            linestyle=linestyle,
            marker=marker,
            markersize=2.5,
            markerfacecolor="white",
            markeredgecolor=color,
            markeredgewidth=0.75,
        )
        for _, _, color, linestyle, marker in _deployment_conflict_series()
    ]
    labels = [label for _, label, _, _, _ in _deployment_conflict_series()]
    legend_order = [0, 1, 2, 3, 4, 5]

    fig = plt.figure(figsize=DEPLOYMENT_LEGEND_FIGSIZE)
    legend = fig.legend(
        [handles[index] for index in legend_order],
        [labels[index] for index in legend_order],
        loc="center right",
        bbox_to_anchor=(ACTIVE_PANEL_MARGINS["right"], 0.5),
        bbox_transform=fig.transFigure,
        ncol=6,
        frameon=False,
        fontsize=ACTIVE_LEGEND_FONTSIZE,
        title=FIGURE_TEXT[23],
        title_fontsize=7.2,
        handlelength=2.1,
        columnspacing=1.2,
        handletextpad=0.35,
        labelspacing=0.15,
        borderpad=0,
        borderaxespad=0,
    )
    legend._legend_box.align = "center"

    creator = "OpenScope deployment legend"
    outputs = [
        output_base.with_suffix(".svg"),
        output_base.with_suffix(".pdf"),
        output_base.with_suffix(".png"),
        output_base.with_suffix(".tiff"),
    ]
    fig.savefig(
        outputs[0],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        facecolor="white",
    )
    fig.savefig(
        outputs[1],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        facecolor="white",
    )
    fig.savefig(outputs[2], format="png", dpi=300, facecolor="white")
    fig.savefig(outputs[3], format="tiff", dpi=600, facecolor="white")
    plt.close(fig)
    return outputs


def draw_deployment_conflict_panel(
    curve_rows: Sequence[dict[str, Any]],
    outcome: str,
    output_base: Path,
) -> list[Path]:
    """Draw one Figure 2 panel from randomized deployment means."""

    if outcome not in DEPLOYMENT_FIGURE_BASENAMES:
        raise ValueError(f"unsupported deployment outcome: {outcome}")
    configure_style()
    keyed = _deployment_curve_rows_by_key(curve_rows)
    series = _deployment_conflict_series()

    x = np.asarray(TARGET_PERCENTS, dtype=np.float64)
    fig, ax = plt.subplots(figsize=ACTIVE_PANEL_FIGSIZE)
    fig.subplots_adjust(**ACTIVE_PANEL_MARGINS)
    for order, (scope_target, label, color, linestyle, marker) in enumerate(series):
        y = np.asarray(
            [
                keyed[(issuance_percent, scope_target)][
                    f"{outcome}_percent_mean"
                ]
                for issuance_percent in TARGET_PERCENTS
            ],
            dtype=np.float64,
        )
        ax.plot(
            x,
            y,
            color=color,
            linewidth=1.25,
            linestyle=linestyle,
            marker=marker,
            markersize=2.5,
            markerfacecolor="white",
            markeredgecolor=color,
            markeredgewidth=0.75,
            label=label,
            zorder=4 + order,
            clip_on=False,
        )
    ax.set_xlim(0, 100)
    x_ticks = [0, 20, 40, 60, 80, 100]
    if outcome == "potential_conflicts":
        y_ticks = [0, 25, 50, 75, 100]
        ax.set_ylim(0, 101)
        ax.set_ylabel(FIGURE_TEXT[15])
        creator = "Potential conflicts during partial ROA issuance"
    else:
        y_ticks = [0, 5, 10, 15, 20, 25]
        ax.set_ylim(0, 25.5)
        ax.set_ylabel(FIGURE_TEXT[16])
        creator = "Observed conflicts during joint ROA issuance"
    _set_integer_major_ticks(ax, x_ticks=x_ticks, y_ticks=y_ticks)
    ax.set_xlabel(FIGURE_TEXT[14])
    ax.grid(axis="y", color="#D8D8D8", linewidth=0.45, linestyle=":")
    ax.set_axisbelow(True)
    ax.tick_params(
        axis="both",
        which="both",
        length=2.5,
        width=0.7,
        direction="in",
        top=False,
        right=False,
        pad=1.8,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)
    ax.spines["bottom"].set_zorder(0)

    outputs = [
        output_base.with_suffix(".svg"),
        output_base.with_suffix(".pdf"),
        output_base.with_suffix(".png"),
        output_base.with_suffix(".tiff"),
    ]
    fig.savefig(
        outputs[0],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        facecolor="white",
    )
    fig.savefig(
        outputs[1],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        facecolor="white",
    )
    fig.savefig(
        outputs[2],
        format="png",
        dpi=300,
        facecolor="white",
    )
    fig.savefig(
        outputs[3],
        format="tiff",
        dpi=600,
        facecolor="white",
    )
    plt.close(fig)
    return outputs


def draw_openscope_placement(
    placement_rows: Sequence[dict[str, Any]], output_base: Path
) -> list[Path]:
    """Draw the pooled fixed-issuance root-placement comparison."""

    configure_style()
    keyed = _placement_rows_by_key(placement_rows)
    series = (
        (
            "most-routes-first",
            "Route count",
            "#228833",
            (0, (4, 2)),
            "s",
        ),
        (
            "asrank-first",
            "ASRank",
            "#CC6677",
            (0, (5, 1.5, 1.2, 1.5)),
            "^",
        ),
        (
            "degree-first",
            "AS degree",
            "#AA4499",
            (0, (1.2, 1.5)),
            "D",
        ),
        ("random", "Random", "#4477AA", "-", "o"),
    )
    x = np.asarray(TARGET_PERCENTS, dtype=np.float64)
    fig, ax = plt.subplots(figsize=ACTIVE_PANEL_FIGSIZE)
    fig.subplots_adjust(**ACTIVE_PANEL_MARGINS)
    for order, (strategy, label, color, linestyle, marker) in enumerate(series):
        y = np.asarray(
            [
                keyed[(strategy, scope_target)][
                    "potential_conflicts_percent_mean"
                ]
                for scope_target in TARGET_PERCENTS
            ],
            dtype=np.float64,
        )
        ax.plot(
            x,
            y,
            color=color,
            linewidth=1.35,
            linestyle=linestyle,
            marker=marker,
            markersize=2.7,
            markerfacecolor="white",
            markeredgecolor=color,
            markeredgewidth=0.75,
            label=label,
            zorder=4 + order,
            clip_on=False,
        )

    ax.set_xlim(0, 100)
    ax.set_ylim(0, 51)
    _set_integer_major_ticks(
        ax,
        x_ticks=[0, 20, 40, 60, 80, 100],
        y_ticks=[0, 10, 20, 30, 40, 50],
    )
    ax.set_xlabel(FIGURE_TEXT[24])
    ax.set_ylabel(FIGURE_TEXT[15])
    ax.grid(axis="y", color="#D8D8D8", linewidth=0.45, linestyle=":")
    ax.set_axisbelow(True)
    ax.tick_params(
        axis="both",
        which="both",
        length=2.5,
        width=0.7,
        direction="in",
        top=False,
        right=False,
        pad=1.8,
    )
    for spine in ax.spines.values():
        spine.set_visible(True)
    ax.spines["bottom"].set_zorder(0)
    ax.legend(
        loc="upper right",
        ncol=2,
        frameon=False,
        fontsize=ACTIVE_LEGEND_FONTSIZE,
        handlelength=2.2,
        columnspacing=0.8,
        handletextpad=0.45,
        borderaxespad=0.25,
    )

    creator = "S²-ROV aggregate-prefix prioritization"
    outputs = [
        output_base.with_suffix(".svg"),
        output_base.with_suffix(".pdf"),
        output_base.with_suffix(".png"),
        output_base.with_suffix(".tiff"),
    ]
    fig.savefig(
        outputs[0],
        format="svg",
        metadata={"Date": None, "Creator": creator},
        facecolor="white",
    )
    fig.savefig(
        outputs[1],
        format="pdf",
        metadata={"Creator": creator, "CreationDate": None, "ModDate": None},
        facecolor="white",
    )
    fig.savefig(outputs[2], format="png", dpi=300, facecolor="white")
    fig.savefig(outputs[3], format="tiff", dpi=600, facecolor="white")
    plt.close(fig)
    return outputs


def _rounded_metrics(row: dict[str, Any]) -> dict[str, Any]:
    metrics = {
        "exact_selected": int(row["exact_selected_count"]),
        "scope_roots_selected": int(row["scope_selected_root_count"]),
        "remaining_count_median": round(float(row["remaining_count_median"]), 1),
        "remaining_percent_median": round(float(row["remaining_percent_median"]), 1),
        "avoided_count_median": round(float(row["avoided_count_median"]), 1),
        "avoided_percent_median": round(float(row["avoided_percent_median"]), 1),
        "remaining_count_p025": round(float(row["remaining_count_p025"]), 1),
        "remaining_count_p05": round(float(row["remaining_count_p05"]), 1),
        "remaining_count_p95": round(float(row["remaining_count_p95"]), 1),
        "remaining_count_p975": round(float(row["remaining_count_p975"]), 1),
        "remaining_percent_p05": round(float(row["remaining_percent_p05"]), 1),
        "remaining_percent_p95": round(float(row["remaining_percent_p95"]), 1),
    }
    efficiency = row["avoided_per_scope_root_median"]
    metrics["avoided_per_scope_root_median"] = (
        None if efficiency is None else round(float(efficiency), 1)
    )
    return metrics


def _rounded_conflict_metrics(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "downstream_prefixes_selected": int(
            row["downstream_selected_prefix_count"]
        ),
        "scope_roots_selected": int(row["scope_selected_root_count"]),
        **{
            f"{state}_count_{statistic}": round(
                float(row[f"{state}_count_{statistic}"]), 1
            )
            for state in CONFLICT_STATES
            for statistic in ("median", "p05", "p95")
        },
    }


def summarize_decision_findings(
    rows: Sequence[dict[str, Any]], input_metadata: dict[str, Any]
) -> dict[str, Any]:
    keyed = {
        (
            row["family"],
            row["root_order"],
            int(row["configuration_decisions"]),
        ): row
        for row in rows
    }
    anchor_decisions = {"IPv4": 41, "IPv6": 7}
    full_coverage: dict[str, Any] = {}
    anchors: dict[str, Any] = {}
    for family in ("IPv4", "IPv6"):
        full_coverage[family] = {
            "endpoint_path_decisions": EXPECTED_FAMILY_COUNTS[family],
            "exact_prefix_origin_entries": input_metadata[
                "endpoint_prefix_origin_entries"
            ][family],
            "root_scope_decisions": EXPECTED_ROOT_COUNTS[family],
        }
        budget = anchor_decisions[family]
        random_row = keyed[(family, "random", budget)]
        first_row = keyed[(family, "fanout-first", budget)]
        last_row = keyed[(family, "fanout-last", budget)]
        anchors[family] = {
            "configuration_decisions": budget,
            "exact_paths_covered_percent": round(
                float(random_row["exact_paths_covered_percent"]), 1
            ),
            "random_scope_paths_covered_percent_median": round(
                float(random_row["scope_paths_covered_percent_median"]), 1
            ),
            "random_scope_paths_covered_percent_p05": round(
                float(random_row["scope_paths_covered_percent_p05"]), 1
            ),
            "random_scope_paths_covered_percent_p95": round(
                float(random_row["scope_paths_covered_percent_p95"]), 1
            ),
            "fanout_first_paths_covered_percent_median": round(
                float(first_row["scope_paths_covered_percent_median"]), 1
            ),
            "fanout_last_paths_covered_percent_median": round(
                float(last_row["scope_paths_covered_percent_median"]), 1
            ),
        }
    return {"full_coverage": full_coverage, "audit_anchors": anchors}


def summarize_placement_findings(
    rows: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    keyed = _placement_rows_by_key(rows)
    anchors: dict[str, Any] = {}
    for scope_target in (0, 20, 40, 50, 60, 80, 100):
        anchors[f"s{scope_target}"] = {
            "scope_selected_roots": int(
                keyed[("random", scope_target)]["scope_selected_root_count"]
            ),
            **{
                strategy.replace("-", "_"): round(
                    float(
                        keyed[(strategy, scope_target)][
                            "potential_conflicts_mean"
                        ]
                    ),
                    1,
                )
                for strategy in PLACEMENT_STRATEGIES
            },
            "conflicting_routes_percent": {
                strategy.replace("-", "_"): round(
                    float(
                        keyed[(strategy, scope_target)][
                            "potential_conflicts_percent_mean"
                        ]
                    ),
                    1,
                )
                for strategy in PLACEMENT_STRATEGIES
            },
        }
    random_s20 = float(
        keyed[("random", 20)]["potential_conflicts_mean"]
    )
    most_s20 = float(
        keyed[("most-routes-first", 20)]["potential_conflicts_mean"]
    )
    return {
        "roa_issuance_percent": PLACEMENT_ROA_TARGET_PERCENT,
        "anchors": anchors,
        "s20_most_routes_first_reduction_vs_random_percent": round(
            100.0 * (random_s20 - most_s20) / random_s20,
            1,
        ),
    }


def _display_conflict_rate_percent(value: float) -> str:
    if 0.0 < value < 0.05:
        return "<0.1%"
    return f"{value:.1f}%"


def summarize_findings(
    grid: Sequence[dict[str, Any]],
    pooled_rows: Sequence[dict[str, Any]],
    conflict_rows: Sequence[dict[str, Any]],
    curve_rows: Sequence[dict[str, Any]],
    placement_rows: Sequence[dict[str, Any]],
    budget_rows: Sequence[dict[str, Any]],
    input_metadata: dict[str, Any],
) -> dict[str, Any]:
    keyed = _rows_by_key(grid)
    key_cell: dict[str, Any] = {}
    order_findings: dict[str, Any] = {}
    for family in ("IPv4", "IPv6"):
        key_cell[family] = {
            strategy: _rounded_metrics(keyed[(family, strategy, 50, 10)])
            for strategy in STRATEGIES
        }
        gaps: list[tuple[float, int, int, dict[str, Any], dict[str, Any]]] = []
        for exact_target in TARGET_PERCENTS:
            for scope_target in TARGET_PERCENTS:
                first = keyed[(family, "fanout-first", exact_target, scope_target)]
                last = keyed[(family, "fanout-last", exact_target, scope_target)]
                gap = float(first["avoided_count_median"]) - float(
                    last["avoided_count_median"]
                )
                gaps.append((gap, exact_target, scope_target, first, last))
        gap, exact_target, scope_target, first, last = max(
            gaps, key=lambda item: (item[0], -item[1], -item[2])
        )
        order_findings[family] = {
            "maximum_fanout_first_minus_last_avoided_count_median": round(gap, 1),
            "at_exact_target_percent": exact_target,
            "at_scope_target_percent": scope_target,
            "fanout_first": _rounded_metrics(first),
            "fanout_last": _rounded_metrics(last),
        }
    pooled_keyed = _pooled_rows_by_key(pooled_rows)
    pooled_q50 = {
        f"s{scope_target}": _rounded_metrics(pooled_keyed[(50, scope_target)])
        for scope_target in POOLED_SCOPE_TARGETS
    }
    conflict_keyed = _conflict_rows_by_key(conflict_rows)
    conflict_q50 = {
        f"s{scope_target}": _rounded_conflict_metrics(
            conflict_keyed[(50, scope_target)]
        )
        for scope_target in POOLED_SCOPE_TARGETS
    }
    curve_keyed = _deployment_curve_rows_by_key(curve_rows)
    curve_q50: dict[str, Any] = {}
    for scope_target in POOLED_SCOPE_TARGETS:
        entry: dict[str, Any] = {
            "scope_selected_roots": int(
                curve_keyed[(50, scope_target)]["scope_selected_root_count"]
            ),
            **{
                f"{outcome}_{statistic}": round(
                    float(
                        curve_keyed[(50, scope_target)][
                            f"{outcome}_{statistic}"
                        ]
                    ),
                    1,
                )
                for outcome in ("potential_conflicts", "observed_conflicts")
                for statistic in ("mean", "p05", "p95")
            },
        }
        for outcome in ("potential_conflicts", "observed_conflicts"):
            for statistic in ("mean", "p05", "p95"):
                field = f"{outcome}_percent_{statistic}"
                value = float(curve_keyed[(50, scope_target)][field])
                entry[field] = value
                entry[f"{field}_display"] = _display_conflict_rate_percent(value)
        curve_q50[f"s{scope_target}"] = entry
    return {
        "figure_2_q50_by_scope": curve_q50,
        "openscope_placement": summarize_placement_findings(placement_rows),
        "route_state_q50_by_scope": conflict_q50,
        "pooled_q50_by_scope": pooled_q50,
        "family_q50_s10_secondary": key_cell,
        "deployment_order": order_findings,
        "configuration_decisions": summarize_decision_findings(
            budget_rows, input_metadata
        ),
    }


def build_manifest(
    input_path: Path,
    input_metadata: dict[str, Any],
    grid: Sequence[dict[str, Any]],
    pooled_rows: Sequence[dict[str, Any]],
    conflict_rows: Sequence[dict[str, Any]],
    curve_rows: Sequence[dict[str, Any]],
    placement_rows: Sequence[dict[str, Any]],
    budget_rows: Sequence[dict[str, Any]],
    selection_metadata: dict[str, Any],
    pooled_selection_metadata: dict[str, Any],
    conflict_selection_metadata: dict[str, Any],
    deployment_selection_metadata: dict[str, Any],
    placement_selection_metadata: dict[str, Any],
    grid_path: Path,
    pooled_path: Path,
    conflict_path: Path,
    curve_path: Path,
    placement_path: Path,
    budget_path: Path,
    figure_paths: Sequence[Path],
    rollout_count: int,
    master_seed: int,
) -> dict[str, Any]:
    output_paths = [
        grid_path,
        pooled_path,
        conflict_path,
        curve_path,
        placement_path,
        budget_path,
        *figure_paths,
    ]
    return {
        "schema": "partial-policy-replay-v8",
        "status": "VERIFIED",
        "figure_contract": {
            "core_conclusion": (
                "OpenScope lowers both potential conflicts "
                "and mid-rollout conflicts realized when upstream ROAs are "
                "active before matching downstream ROAs, while selecting roots "
                "with more eligible observed routes accelerates the reduction."
            ),
            "archetype": (
                "Figure 2 uses one standalone shared legend above two vertically "
                "stacked panels; Figure 3 is one single-panel placement comparison"
            ),
            "layout": {
                "figure_2": {
                    "legend_basename": DEPLOYMENT_LEGEND_BASENAME,
                    "legend_canvas_inches": list(DEPLOYMENT_LEGEND_FIGSIZE),
                    "legend_right_fraction": ACTIVE_PANEL_MARGINS["right"],
                    "panel_canvas_inches": list(DEPLOYMENT_PANEL_FIGSIZE),
                    "panel_axes_fraction": {
                        "left": DEPLOYMENT_PANEL_ADJUST["left"],
                        "bottom": DEPLOYMENT_PANEL_ADJUST["bottom"],
                        "width": DEPLOYMENT_PANEL_ADJUST["right"]
                        - DEPLOYMENT_PANEL_ADJUST["left"],
                        "height": DEPLOYMENT_PANEL_ADJUST["top"]
                        - DEPLOYMENT_PANEL_ADJUST["bottom"],
                    },
                    "panel_legends": 0,
                    "y_label": "Conflicting routes (%)",
                    "potential_y_ticks": [0, 25, 50, 75, 100],
                    "observed_y_ticks": [0, 5, 10, 15, 20, 25],
                },
                "figure_3": {
                    "panel_basename": PLACEMENT_FIGURE_BASENAME,
                    "panel_canvas_inches": list(DEPLOYMENT_PANEL_FIGSIZE),
                    "displayed_strategies": list(PLACEMENT_STRATEGIES),
                    "y_label": "Conflicting routes (%)",
                    "y_ticks": [0, 10, 20, 30, 40, 50],
                },
            },
            "shared_panel_style": {
                "canvas_inches": list(ACTIVE_PANEL_FIGSIZE),
                "axes_fraction": {
                    "left": ACTIVE_PANEL_MARGINS["left"],
                    "bottom": ACTIVE_PANEL_MARGINS["bottom"],
                    "width": ACTIVE_PANEL_MARGINS["right"]
                    - ACTIVE_PANEL_MARGINS["left"],
                    "height": ACTIVE_PANEL_MARGINS["top"]
                    - ACTIVE_PANEL_MARGINS["bottom"],
                },
                "axis_label_pt": ACTIVE_AXIS_LABELSIZE,
                "tick_label_pt": ACTIVE_TICK_LABELSIZE,
                "legend_pt": ACTIVE_LEGEND_FONTSIZE,
            },
            "panel_map": {
                "heatmap_IPv4": "random-order median over IPv4 candidate paths",
                "heatmap_IPv6": "random-order median over IPv6 candidate paths",
                "strategy_IPv4": "q=50% placement sensitivity for IPv4",
                "strategy_IPv6": "q=50% placement sensitivity for IPv6",
                "potential_conflicts": (
                    "all root ROAs active; downstream ROA issuance varies"
                ),
                "observed_conflicts": (
                    "independent root and downstream issuance share one rate"
                ),
                "openscope_placement": (
                    "fixed 50% downstream ROA issuance; Route count, "
                    "ASRank, AS degree, and Random root placement"
                ),
            },
            "hero_evidence": (
                "randomized replay means for Figure 2 conflicts at six S²-ROV "
                "policy levels and Figure 3 prioritization means at fixed 50% issuance"
            ),
            "robustness": (
                "full q by s grid, family sensitivity, and four root-placement "
                "orders at fixed downstream issuance"
            ),
            "reviewer_risk": (
                "Observed denotes conflicts realized on the RRC00-derived routes "
                "inside the constructed joint rollout, not a historical Internet "
                "time series or an adoption estimate."
            ),
        },
        "input": {
            "path": relative_to_repo(input_path),
            **input_metadata,
        },
        "placement_score_input": placement_selection_metadata[
            "placement_score_input"
        ],
        "design": {
            "deployment_unit": (
                "one retained endpoint-prefix bundle containing its complete "
                "observed origin set"
            ),
            "outcome_unit": "one observed endpoint (prefix, origin) route",
            "endpoint_routes_announced_from_start": True,
            "potential_root_policy": "present for every retained root",
            "observed_root_policy": (
                "independently active with the same marginal issuance rate as "
                "downstream exact ROAs"
            ),
            "multi_origin_rule": (
                "exact selection covers the complete observed endpoint-origin set"
            ),
            "scope_length_rule": (
                "each selected root uses the longest retained endpoint length below "
                "that root"
            ),
            "exact_target_percent": list(TARGET_PERCENTS),
            "scope_target_percent": list(TARGET_PERCENTS),
            "primary_scope_target_percent": list(POOLED_SCOPE_TARGETS),
            "scope_selection_count_rule": "floor(97 * target / 100)",
            "secondary_selection_count_rule": "floor(population * target / 100)",
            "rollout_orders": rollout_count,
            "master_seed": master_seed,
            "nested_endpoint_orders": True,
            "nested_root_orders": True,
            "root_orders": list(STRATEGIES),
            "secondary_route_state_statistic": "random-order median",
            "secondary_route_state_interval": (
                "5th to 95th rollout-order percentiles"
            ),
            "secondary_grid_interval": (
                "2.5th to 97.5th rollout-order percentiles"
            ),
            "figure_2_statistic": "mean over randomized deployment replays",
            "figure_conflict_rate_denominator": CONFLICT_RATE_DENOMINATOR,
            "figure_conflict_rate_definition": (
                "100 * mean number of conflicting routes / 589"
            ),
            "figure_conflict_rate_scope": (
                "the same fixed denominator is used for both Figure 2 panels "
                "and Figure 3"
            ),
            "figure_2_display": (
                "arithmetic-mean curves only; no interval or range glyphs"
            ),
            "placement_roa_issuance_percent": PLACEMENT_ROA_TARGET_PERCENT,
            "placement_scope_target_percent": list(TARGET_PERCENTS),
            "placement_root_scores": placement_selection_metadata["root_scores"],
            "placement_display_strategies": list(PLACEMENT_STRATEGIES),
            "placement_score_tie_break": placement_selection_metadata[
                "score_tie_break"
            ],
            "placement_statistic": "mean over 1,000 paired downstream-ROA replays",
            "potential_definition": (
                "Invalid routes when every root ROA is active and the sampled "
                "downstream ROAs and S²-ROV policies are installed"
            ),
            "observed_definition": (
                "Invalid routes when sampled root ROAs, downstream ROAs, and "
                "S²-ROV policies are installed independently"
            ),
            "remaining_definition": (
                "candidate lacks exact coverage and its root lacks OpenScope"
            ),
            "invalid_definition": (
                "reference classifier returns Invalid for an announced endpoint "
                "route in the constructed deployment snapshot"
            ),
            "avoided_definition": "C(q,0) minus C(q,s)",
            "deployment_efficiency_definition": (
                "avoided candidate rows per deployed OpenScope root"
            ),
            "configuration_decision_definition": (
                "one endpoint decision atomically covers one candidate path and its "
                "complete observed endpoint-origin set; one root-scope decision "
                "covers every candidate path grouped below the selected root"
            ),
            "primary_count_denominator": "all 589 observed endpoint route-origin pairs",
            "deployment_denominator": "all 587 endpoint-prefix bundles",
            "pooled_root_identity": "(IP version, canonical root prefix)",
        },
        "selection": {
            "family_specific_secondary": selection_metadata,
            "pooled_structural_secondary": pooled_selection_metadata,
            "route_state_secondary": conflict_selection_metadata,
            "deployment_primary": deployment_selection_metadata,
            "openscope_placement": placement_selection_metadata,
        },
        "findings": summarize_findings(
            grid,
            pooled_rows,
            conflict_rows,
            curve_rows,
            placement_rows,
            budget_rows,
            input_metadata,
        ),
        "gates": {
            "input_hash_pinned": input_metadata["sha256"] == EXPECTED_INPUT_SHA256,
            "paper_candidate_counts_match": input_metadata["family_counts"]
            == EXPECTED_FAMILY_COUNTS,
            "paper_root_counts_match": input_metadata["root_counts"]
            == EXPECTED_ROOT_COUNTS,
            "origin_sets_disjoint": input_metadata["all_origin_sets_disjoint"],
            "prefixes_canonical": input_metadata["all_prefixes_canonical"],
            "endpoints_are_proper_subprefixes": input_metadata[
                "all_endpoints_proper_subprefixes"
            ],
            "endpoint_prefixes_unique": input_metadata["endpoint_prefixes_unique"],
            "route_origin_tuples_unique": input_metadata[
                "route_origin_tuples_unique"
            ],
            "retained_endpoints_non_nested": input_metadata[
                "retained_endpoints_non_nested"
            ],
            "root_origin_sets_consistent": input_metadata[
                "root_origin_sets_consistent"
            ],
            "retained_roots_non_nested": input_metadata[
                "retained_roots_non_nested"
            ],
            "scope_max_lengths_cover_retained_endpoints": input_metadata[
                "scope_max_lengths_cover_retained_endpoints"
            ],
            "complete_factorial_grid": len(grid)
            == 2 * len(STRATEGIES) * len(TARGET_PERCENTS) ** 2,
            "complete_pooled_primary_grid": len(pooled_rows)
            == len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS),
            "complete_route_state_grid": len(conflict_rows)
            == len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS),
            "complete_deployment_curve_grid": len(curve_rows)
            == len(TARGET_PERCENTS) * len(POOLED_SCOPE_TARGETS),
            "complete_openscope_placement_grid": len(placement_rows)
            == len(PLACEMENT_STRATEGIES) * len(TARGET_PERCENTS),
            "fixed_conflict_rate_denominator_verified": all(
                int(row["conflict_rate_denominator"])
                == CONFLICT_RATE_DENOMINATOR
                for row in (*curve_rows, *placement_rows)
            ),
            "deployment_replay_count": deployment_selection_metadata["rollout_count"],
            "deployment_placements_independent": deployment_selection_metadata[
                "placements_independent"
            ],
            "deployment_reference_states_verified": deployment_selection_metadata[
                "reference_state_replay_verified"
            ],
            "deployment_oracle_verified": deployment_selection_metadata[
                "independent_oracle_verified"
            ],
            "placement_reference_states_verified": placement_selection_metadata[
                "reference_state_replay_verified"
            ],
            "placement_oracle_verified": placement_selection_metadata[
                "independent_oracle_verified"
            ],
            "placement_score_input_hash_pinned": (
                placement_selection_metadata["placement_score_input"]["sha256"]
                == EXPECTED_PLACEMENT_SCORES_SHA256
            ),
            "placement_score_asn_coverage_complete": (
                placement_selection_metadata["placement_score_coverage"]
                == {
                    "roots": 97,
                    "unique_aggregate_origin_asns": 37,
                    "covered_asns": 37,
                }
            ),
            "observed_series_zero_at_endpoints": True,
            "complete_decision_budget_grid": len(budget_rows)
            == sum(
                len(STRATEGIES) * (EXPECTED_ROOT_COUNTS[family] + 1)
                for family in EXPECTED_ROOT_COUNTS
            ),
            "scope_zero_baseline_verified": True,
            "remaining_monotone_in_exact_and_scope": True,
            "structural_full_exact_remaining_zero": True,
            "structural_full_scope_remaining_zero": True,
            "avoided_identity_verified": True,
            "reference_classifier_state_table_verified": True,
            "route_state_partition_verified": conflict_selection_metadata[
                "state_partition_verified"
            ],
            "route_state_oracle_verified": conflict_selection_metadata[
                "independent_oracle_verified"
            ],
            "aggregate_first_all_endpoint_routes_invalid": (
                conflict_selection_metadata["reference_state_counts"][
                    "aggregate_only"
                ]["invalid"]
                == sum(EXPECTED_ROUTE_COUNTS.values())
            ),
            "full_scope_retains_one_ineligible_route": (
                conflict_selection_metadata["reference_state_counts"]["marked_root"][
                    "invalid"
                ]
                == 1
            ),
            "full_downstream_coverage_invalid_zero": True,
            "figure_text_excludes_forbidden_tokens": all(
                token not in " ".join(FIGURE_TEXT).lower() for token in ("pp", "csv")
            ),
        },
        "runtime": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "matplotlib": mpl.__version__,
        },
        "outputs": {
            relative_to_repo(path): {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in output_paths
        },
        "runner": {
            "path": relative_to_repo(Path(__file__)),
            "sha256": sha256_file(Path(__file__)),
        },
    }


def write_outputs(
    input_path: Path = DEFAULT_INPUT,
    placement_score_path: Path = DEFAULT_PLACEMENT_SCORES,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    figure_dir: Path = DEFAULT_FIGURE_DIR,
    rollout_count: int = ROLLOUTS,
    master_seed: int = MASTER_SEED,
) -> tuple[Path, Path, Path, Path, Path, Path, Path, list[Path]]:
    candidates, input_metadata = load_candidates(input_path)
    placement_scores, placement_score_metadata = load_placement_scores(
        placement_score_path
    )
    grid, selection_metadata = compute_grid(
        candidates, rollout_count=rollout_count, master_seed=master_seed
    )
    pooled_rows, pooled_selection_metadata = compute_pooled_deployment(
        candidates, rollout_count=rollout_count, master_seed=master_seed
    )
    conflict_rows, conflict_selection_metadata = compute_route_state_replay(
        candidates, rollout_count=rollout_count, master_seed=master_seed
    )
    curve_rows, deployment_selection_metadata = compute_deployment_conflict_curves(
        candidates,
        rollout_count=rollout_count,
        master_seed=master_seed,
    )
    placement_rows, placement_selection_metadata = compute_openscope_placement(
        candidates,
        rollout_count=rollout_count,
        master_seed=master_seed,
        placement_scores=placement_scores,
        placement_score_metadata=placement_score_metadata,
    )
    budget_rows = compute_decision_budget(
        candidates, rollout_count=rollout_count, master_seed=master_seed
    )
    source_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)

    grid_path = source_dir / GRID_FILENAME
    grid_path.write_text(grid_csv_text(grid), encoding="utf-8")
    pooled_path = source_dir / POOLED_FILENAME
    pooled_path.write_text(
        rows_csv_text(pooled_rows, GRID_FIELDS), encoding="utf-8"
    )
    conflict_path = source_dir / CONFLICT_FILENAME
    conflict_path.write_text(
        rows_csv_text(conflict_rows, CONFLICT_FIELDS), encoding="utf-8"
    )
    curve_path = source_dir / DEPLOYMENT_CURVE_FILENAME
    curve_path.write_text(
        rows_csv_text(curve_rows, DEPLOYMENT_CURVE_FIELDS), encoding="utf-8"
    )
    placement_path = source_dir / PLACEMENT_FILENAME
    placement_path.write_text(
        rows_csv_text(placement_rows, PLACEMENT_FIELDS), encoding="utf-8"
    )
    budget_path = source_dir / BUDGET_FILENAME
    budget_path.write_text(
        rows_csv_text(budget_rows, BUDGET_FIELDS), encoding="utf-8"
    )
    figure_paths: list[Path] = []
    for family in ("IPv4", "IPv6"):
        output_base = figure_dir / FIGURE_BASENAMES[family]
        figure_paths.extend(draw_family_figure(grid, family, output_base))
        strategy_output_base = figure_dir / STRATEGY_FIGURE_BASENAMES[family]
        figure_paths.extend(
            draw_strategy_figure(grid, family, strategy_output_base)
        )
    for outcome, basename in DEPLOYMENT_FIGURE_BASENAMES.items():
        figure_paths.extend(
            draw_deployment_conflict_panel(
                curve_rows,
                outcome,
                figure_dir / basename,
            )
        )
    figure_paths.extend(
        draw_deployment_conflict_legend(
            figure_dir / DEPLOYMENT_LEGEND_BASENAME,
        )
    )
    figure_paths.extend(
        draw_openscope_placement(
            placement_rows,
            figure_dir / PLACEMENT_FIGURE_BASENAME,
        )
    )

    manifest = build_manifest(
        input_path=input_path,
        input_metadata=input_metadata,
        grid=grid,
        pooled_rows=pooled_rows,
        conflict_rows=conflict_rows,
        curve_rows=curve_rows,
        placement_rows=placement_rows,
        budget_rows=budget_rows,
        selection_metadata=selection_metadata,
        pooled_selection_metadata=pooled_selection_metadata,
        conflict_selection_metadata=conflict_selection_metadata,
        deployment_selection_metadata=deployment_selection_metadata,
        placement_selection_metadata=placement_selection_metadata,
        grid_path=grid_path,
        pooled_path=pooled_path,
        conflict_path=conflict_path,
        curve_path=curve_path,
        placement_path=placement_path,
        budget_path=budget_path,
        figure_paths=figure_paths,
        rollout_count=rollout_count,
        master_seed=master_seed,
    )
    manifest_path = figure_dir / MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return (
        grid_path,
        pooled_path,
        conflict_path,
        curve_path,
        placement_path,
        budget_path,
        manifest_path,
        figure_paths,
    )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument(
        "--placement-scores",
        type=Path,
        default=DEFAULT_PLACEMENT_SCORES,
    )
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--figure-dir", type=Path, default=DEFAULT_FIGURE_DIR)
    parser.add_argument("--rollouts", type=int, default=ROLLOUTS)
    parser.add_argument("--seed", type=int, default=MASTER_SEED)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    (
        grid_path,
        pooled_path,
        conflict_path,
        curve_path,
        placement_path,
        budget_path,
        manifest_path,
        figure_paths,
    ) = write_outputs(
        input_path=args.input,
        placement_score_path=args.placement_scores,
        source_dir=args.source_dir,
        figure_dir=args.figure_dir,
        rollout_count=args.rollouts,
        master_seed=args.seed,
    )
    print(f"grid: {grid_path}")
    print(f"pooled deployment: {pooled_path}")
    print(f"route-state replay: {conflict_path}")
    print(f"deployment curves: {curve_path}")
    print(f"OpenScope placement: {placement_path}")
    print(f"decision budget: {budget_path}")
    print(f"manifest: {manifest_path}")
    for path in figure_paths:
        print(f"figure: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
