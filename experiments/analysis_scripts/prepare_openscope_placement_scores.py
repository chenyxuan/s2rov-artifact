#!/usr/bin/env python3
"""Derive the hash-bound ASRank and degree input for Figure 3.

Run this script with the routing-model BGPy environment and the pinned, decompressed
CAIDA serial-2 relationship snapshot.  The active replay consumes only the
small derived JSON, so manuscript builds remain offline and deterministic.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from bgpy.as_graphs import CAIDAASGraphConstructor
from frozendict import frozendict


REPO = Path(__file__).resolve().parents[2]
MANUSCRIPT = Path(__file__).resolve().parents[2]
DEFAULT_CANDIDATES = (
    REPO
    / "experiments" / "candidates"
    / "allocation_tree"
    / "visibility_experiment"
    / "results"
    / "visibility_candidates.csv"
)
DEFAULT_OUTPUT = (
    MANUSCRIPT
    / "figure-data"
    / "source_data"
    / "openscope_placement_as_scores.json"
)
EXPECTED_CANDIDATE_SHA256 = (
    "0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918"
)
EXPECTED_GRAPH_SHA256 = (
    "aabd0b2154d9dec5b4c0b63d1d9f88cbfbf381bbc4d2246fe0471dd4aacf2181"
)
SOURCE_URL = (
    "https://publicdata.caida.org/datasets/as-relationships/serial-2/"
    "20260701.as-rel2.txt.bz2"
)
BGPY_COMMIT = "c3b1be48148e8c246a60b9dec6513b688a4736a5"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_root_asns(path: Path) -> set[int]:
    if sha256_file(path) != EXPECTED_CANDIDATE_SHA256:
        raise ValueError("candidate input does not match the Figure 3 freeze")
    root_origins: dict[tuple[str, str], int] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"family", "root_prefix", "root_origins"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError("candidate input is missing root-origin fields")
        for row in reader:
            origins = tuple(
                int(token) for token in row["root_origins"].split(";") if token
            )
            if len(origins) != 1:
                raise ValueError("Figure 3 requires one observed origin per root")
            key = (row["family"], row["root_prefix"])
            previous = root_origins.setdefault(key, origins[0])
            if previous != origins[0]:
                raise ValueError("observed root origin changes within one root")
    if len(root_origins) != 97 or len(set(root_origins.values())) != 37:
        raise ValueError("Figure 3 root or aggregate-origin population changed")
    return set(root_origins.values())


def derive_scores(graph_path: Path, target_asns: set[int]) -> list[dict[str, int]]:
    if sha256_file(graph_path) != EXPECTED_GRAPH_SHA256:
        raise ValueError("CAIDA relationship graph does not match the pinned snapshot")
    constructor = CAIDAASGraphConstructor(
        as_graph_kwargs=frozendict(store_customer_cone_size=True)
    )
    graph_info = constructor._get_as_graph_info(graph_path)
    graph = constructor._get_as_graph(graph_info)
    missing = sorted(target_asns - set(graph.as_dict))
    if missing:
        raise ValueError(f"CAIDA graph is missing aggregate origins {missing}")

    scores: list[dict[str, int]] = []
    for asn in sorted(target_asns):
        as_object = graph.as_dict[asn]
        if as_object.customer_cone_size is None:
            raise ValueError(f"BGPy did not compute the customer cone for AS{asn}")
        scores.append(
            {
                "asn": asn,
                "customer_cone_asns": int(as_object.customer_cone_size),
                "total_degree": len(as_object.neighbors),
            }
        )
    return scores


def build_document(graph_path: Path, candidate_path: Path) -> dict[str, Any]:
    target_asns = load_root_asns(candidate_path)
    return {
        "schema": "openscope-placement-as-scores-v1",
        "source": {
            "dataset": "CAIDA AS Relationships serial-2",
            "snapshot": "2026-07-01",
            "url": SOURCE_URL,
            "uncompressed_sha256": sha256_file(graph_path),
        },
        "derivation": {
            "asrank_order": "descending customer-cone AS count",
            "degree": "number of unique AS neighbors",
            "implementation": f"BGPy {importlib.metadata.version('bgpy-pkg')}",
            "implementation_commit": BGPY_COMMIT,
        },
        "scores": derive_scores(graph_path, target_asns),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = build_document(args.graph, args.candidates)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"scores: {args.output}")
    print(f"sha256: {sha256_file(args.output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
