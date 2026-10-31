#!/usr/bin/env python3
"""Construct a reference-policy corpus from strict allocation candidates.

The generated policies are synthetic constructions over observed endpoint
prefix/origin sets.  They are useful for structural and serialization tests;
they do not assert that the candidate rows are authorized delegations or real
S2-ROVs.
"""
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))

from utils.s2rov import S2ROV, Stripe  # noqa: E402


CANDIDATES = (
    ROOT
    / "experiments" / "candidates"
    / "allocation_tree"
    / "outputs"
    / "tables"
    / "allocation_tree_origin_divergence.csv"
)
OUTPUT = HERE_DIR / "outputs" / "tables" / "candidate_policy_corpus.csv"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)


def parse_as_set(value: str) -> set[int]:
    return {int(part) for part in value.split(";") if part}


def load_groups() -> dict[str, dict[str, object]]:
    groups: dict[str, dict[str, object]] = {}
    with CANDIDATES.open(newline="") as handle:
        for row in csv.DictReader(handle):
            root = row["root_prefix"]
            group = groups.setdefault(
                root,
                {
                    "root_origins": parse_as_set(row["root_origins"]),
                    "leaves": defaultdict(set),
                },
            )
            if group["root_origins"] != parse_as_set(row["root_origins"]):
                raise ValueError(f"inconsistent root origin set for {root}")
            group["leaves"][row["leaf_prefix"]].update(
                parse_as_set(row["leaf_origins"])
            )
    return groups


def main() -> None:
    rows: list[dict[str, object]] = []
    for root, group in sorted(load_groups().items()):
        root_origins = group["root_origins"]
        leaves = group["leaves"]
        holder = min(root_origins)
        max_length = max(int(prefix.split("/")[1]) for prefix in leaves)
        stripes = [Stripe(root, root_origins, is_open=True)]
        stripes.extend(
            Stripe(prefix, origins, is_open=False)
            for prefix, origins in sorted(leaves.items())
        )
        policy = S2ROV(root, max_length, holder, stripes)
        payload = policy.serialize()
        decoded = S2ROV.deserialize(payload)
        assert decoded.serialize() == payload
        rows.append(
            {
                "root_prefix": root,
                "root_origin_count": len(root_origins),
                "candidate_leaf_count": len(leaves),
                "stripes": len(stripes),
                "reference_payload_bytes": len(payload),
                "conservative_projected_vrps": len(policy.flatten_to_vrps()),
                "roundtrip_ok": True,
                "interpretation": "synthetic policy over counterfactual candidates",
            }
        )

    with OUTPUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Policies: {len(rows):,}")
    print(f"Candidate leaves: {sum(int(r['candidate_leaf_count']) for r in rows):,}")
    print(f"Round trips passed: {sum(r['roundtrip_ok'] is True for r in rows):,}")
    print(f"Output -> {OUTPUT}")


if __name__ == "__main__":
    main()
