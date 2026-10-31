#!/usr/bin/env python3
"""Measure strict parent--leaf origin divergence in the RIPE allocation tree.

The previous implementation used every BGP route contained anywhere below a
root as the root's origin set and searched only a fixed +/-300-row window.
Both choices can change the result.  This version deliberately asks a narrower
and reproducible question:

* the RIPE root and leaf ranges must each be one canonical IPv4 CIDR;
* both CIDRs must appear exactly in the selected RouteViews RIB; and
* their complete visible origin sets must be disjoint.

The resulting rows are *counterfactual candidates*.  They do not establish
contractual delegation, current ROA state, or route legitimacy.
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress as ip
import json
import math
import statistics
from collections import Counter
from pathlib import Path


PHASE_DIR = Path(__file__).resolve().parents[1]
TABLE_DIR = PHASE_DIR / "outputs" / "tables"
PAIR_CSV = TABLE_DIR / "allocation_tree_pairs.csv"
BGP_CSV = TABLE_DIR / "bgp_origins.csv"
CANDIDATE_CSV = TABLE_DIR / "allocation_tree_origin_divergence.csv"
SUMMARY_JSON = TABLE_DIR / "allocation_tree_origin_divergence_summary.json"

IPV4_MIN = 0
IPV4_MAX = (1 << 32) - 1


def range_to_single_cidr(start: int, end: int) -> str | None:
    """Return the canonical CIDR for an exact power-of-two range, else None."""
    if not (IPV4_MIN <= start <= end <= IPV4_MAX):
        return None
    prefix_length = 32 - (start ^ end).bit_length()
    size = 1 << (32 - prefix_length)
    if start % size or end - start + 1 != size:
        return None
    return f"{ip.IPv4Address(start)}/{prefix_length}"


def load_exact_origins(path: Path) -> dict[str, set[int]]:
    """Load every visible origin for each exact IPv4 prefix in the RIB."""
    origins: dict[str, set[int]] = {}
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                prefix = str(ip.IPv4Network(row["prefix"], strict=False))
                asn = int(row["origin_as"])
            except (KeyError, ValueError):
                continue
            origins.setdefault(prefix, set()).add(asn)
    return origins


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def analyze() -> dict[str, object]:
    origins = load_exact_origins(BGP_CSV)
    counts: Counter[str] = Counter()
    root_origins: set[int] = set()
    leaf_origins: set[int] = set()
    candidate_roots: set[str] = set()
    candidate_leaves: set[str] = set()
    root_statuses: Counter[str] = Counter()
    leaf_statuses: Counter[str] = Counter()
    candidate_leaves_per_root: Counter[str] = Counter()

    fieldnames = [
        "root_prefix",
        "root_status",
        "root_origins",
        "leaf_prefix",
        "leaf_status",
        "leaf_origins",
        "classification",
    ]

    with PAIR_CSV.open(newline="") as source, CANDIDATE_CSV.open(
        "w", newline=""
    ) as destination:
        reader = csv.DictReader(source)
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            counts["matched_pairs_raw"] += 1
            root_start = int(row["root_start"])
            root_end = int(row["root_end"])
            leaf_start = int(row["leaf_start"])
            leaf_end = int(row["leaf_end"])

            if root_start == IPV4_MIN and root_end == IPV4_MAX:
                counts["excluded_zero_root"] += 1
                continue
            counts["matched_pairs_without_zero_root"] += 1

            root_prefix = range_to_single_cidr(root_start, root_end)
            leaf_prefix = range_to_single_cidr(leaf_start, leaf_end)
            if root_prefix is None or leaf_prefix is None:
                counts["excluded_non_cidr_pair"] += 1
                continue
            counts["exact_cidr_pairs"] += 1

            root_set = origins.get(root_prefix, set())
            leaf_set = origins.get(leaf_prefix, set())
            if not root_set:
                counts["no_exact_root_route"] += 1
            if not leaf_set:
                counts["no_exact_leaf_route"] += 1
            if not root_set or not leaf_set:
                continue
            counts["exact_routes_at_both_endpoints"] += 1

            if root_set.isdisjoint(leaf_set):
                classification = "disjoint_origin_sets"
                counts["disjoint_origin_candidates"] += 1
                root_origins.update(root_set)
                leaf_origins.update(leaf_set)
                candidate_roots.add(root_prefix)
                candidate_leaves.add(leaf_prefix)
                candidate_leaves_per_root[root_prefix] += 1
                root_statuses[row["root_status"]] += 1
                leaf_statuses[row["leaf_status"]] += 1
                writer.writerow(
                    {
                        "root_prefix": root_prefix,
                        "root_status": row["root_status"],
                        "root_origins": ";".join(map(str, sorted(root_set))),
                        "leaf_prefix": leaf_prefix,
                        "leaf_status": row["leaf_status"],
                        "leaf_origins": ";".join(map(str, sorted(leaf_set))),
                        "classification": classification,
                    }
                )
            else:
                counts["overlapping_origin_sets"] += 1

    root_fanouts = sorted(candidate_leaves_per_root.values())
    if root_fanouts:
        fanout_summary: dict[str, int | float] = {
            "mean": statistics.fmean(root_fanouts),
            "median": statistics.median(root_fanouts),
            "p90_nearest_rank": root_fanouts[
                math.ceil(0.90 * len(root_fanouts)) - 1
            ],
            "p95_nearest_rank": root_fanouts[
                math.ceil(0.95 * len(root_fanouts)) - 1
            ],
            "maximum": max(root_fanouts),
            "single_leaf_roots": sum(value == 1 for value in root_fanouts),
        }
    else:
        fanout_summary = {
            "mean": 0.0,
            "median": 0.0,
            "p90_nearest_rank": 0,
            "p95_nearest_rank": 0,
            "maximum": 0,
            "single_leaf_roots": 0,
        }
    summary: dict[str, object] = {
        "method": {
            "root_and_leaf": "exact canonical IPv4 CIDRs",
            "bgp_match": "exact prefix match in RouteViews RIB",
            "candidate_rule": "non-empty, disjoint complete origin sets",
            "interpretation": (
                "counterfactual candidate only; no inference of delegation, "
                "authorization, current ROA state, or legitimacy"
            ),
        },
        "counts": dict(counts),
        "candidate_root_prefixes": len(candidate_roots),
        "candidate_leaf_prefixes": len(candidate_leaves),
        "candidate_root_origin_asns": len(root_origins),
        "candidate_leaf_origin_asns": len(leaf_origins),
        "candidate_root_statuses": dict(root_statuses),
        "candidate_leaf_statuses": dict(leaf_statuses),
        "candidate_leaves_per_root": fanout_summary,
        "inputs": {
            "allocation_pairs": {
                "path": str(PAIR_CSV),
                "sha256": sha256(PAIR_CSV),
            },
            "bgp_origins": {
                "path": str(BGP_CSV),
                "sha256": sha256(BGP_CSV),
            },
        },
        "output": {
            "path": str(CANDIDATE_CSV),
            "sha256": sha256(CANDIDATE_CSV),
        },
    }
    SUMMARY_JSON.write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> None:
    summary = analyze()
    counts = summary["counts"]
    print(json.dumps(summary, indent=2))
    print(
        "\nStrict origin-divergence candidates: "
        f"{counts['disjoint_origin_candidates']:,}"
    )


if __name__ == "__main__":
    main()
