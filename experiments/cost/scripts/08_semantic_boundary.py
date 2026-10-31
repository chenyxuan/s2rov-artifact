#!/usr/bin/env python3
"""Semantic boundary checks for open and closed S2-ROV policies.

The source corpus has cause/relationship labels, not attack ground truth.
It checks the reference implementation's intended boundary:

* a relationship-labeled route under a constructed open parent is Delegated
  when its ASN is eligible;
* an arbitrary public ASN is also Delegated under open policy; and
* that same ASN is Invalid under closed policy.

These are Python reference checks, not prototype-system experiments.
"""
from __future__ import annotations

import csv
import ipaddress as ip
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
HERE_DIR = Path(__file__).resolve().parents[1]
S2ROV_CODEC_SCRIPTS = ROOT / "implementation" / "s2rov_codec" / "scripts"
sys.path.insert(0, str(S2ROV_CODEC_SCRIPTS))

from utils.s2rov import S2ROV, Stripe, ValidationState


TABLE_DIR = HERE_DIR / "outputs" / "tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)
CANDIDATES_TABLE_DIR = (
    ROOT / "experiments" / "candidates" / "ndss26_analysis" / "outputs" / "tables"
)
CANDIDATES_PARQUET = CANDIDATES_TABLE_DIR / "data_processed.parquet"
CANDIDATES_CSV = CANDIDATES_TABLE_DIR / "data_processed.csv.gz"
RELATIONSHIP_COLUMNS = [
    "customer",
    "org_transit",
    "direct_leasing",
    "hidden_transit",
    "broker_leasing",
]
PUBLIC_CONTROL_ASN = 15169


def load_candidates_dataframe() -> pd.DataFrame:
    if CANDIDATES_CSV.exists():
        return pd.read_csv(CANDIDATES_CSV)
    if CANDIDATES_PARQUET.exists():
        try:
            return pd.read_parquet(CANDIDATES_PARQUET)
        except ImportError as exc:
            raise RuntimeError(
                "Only a Parquet cache is available; rerun the candidate-selection loader "
                "to create data_processed.csv.gz"
            ) from exc
    raise FileNotFoundError(f"no processed candidate-selection table under {CANDIDATES_TABLE_DIR}")


def constructed_policy(route_prefix: str, holder_asn: int, open_base: bool) -> S2ROV:
    route = ip.IPv4Network(route_prefix, strict=False)
    if route.prefixlen == 0:
        raise ValueError("cannot construct a proper parent for /0")
    parent = route.supernet()
    return S2ROV(
        str(parent),
        route.prefixlen,
        holder_asn,
        [Stripe(str(parent), {holder_asn}, is_open=open_base)],
    )


def main() -> None:
    frame = load_candidates_dataframe()
    label_mask = frame[RELATIONSHIP_COLUMNS].gt(0).any(axis=1)
    differing = (
        label_mask
        & (frame["bgp_origin"] != frame["roa_origin"])
        & frame["prefix"].str.contains("/")
    )
    constructible = (
        frame["roa_origin"].between(1, 0xFFFFFFFF)
        & frame["bgp_origin"].between(1, 0xFFFFFFFF)
    )
    candidates = frame[differing & constructible]
    excluded_non_asn_holder_or_origin = int((differing & ~constructible).sum())
    sample = candidates.sample(n=min(10_000, len(candidates)), random_state=42)

    delegated = 0
    ineligible = 0
    open_control_delegated = 0
    closed_control_invalid = 0
    tested = 0
    for row in sample.itertuples(index=False):
        route_prefix = str(row.prefix)
        holder = int(row.roa_origin)
        observed = int(row.bgp_origin)
        if ip.IPv4Network(route_prefix, strict=False).prefixlen == 0:
            continue
        tested += 1

        open_policy = constructed_policy(route_prefix, holder, True)
        observed_state = open_policy.validate_route(route_prefix, observed)
        delegated += observed_state == ValidationState.DELEGATED
        ineligible += observed_state == ValidationState.INVALID

        control = PUBLIC_CONTROL_ASN
        if control == holder:
            control = 13335
        open_control_delegated += (
            open_policy.validate_route(route_prefix, control)
            == ValidationState.DELEGATED
        )
        closed_policy = constructed_policy(route_prefix, holder, False)
        closed_control_invalid += (
            closed_policy.validate_route(route_prefix, control)
            == ValidationState.INVALID
        )

    rows = [
        {
            "metric": "excluded_non_asn_holder_or_origin_rows",
            "value": excluded_non_asn_holder_or_origin,
        },
        {"metric": "relationship_labeled_rows_tested", "value": tested},
        {
            "metric": "observed_origin_delegated_pct",
            "value": f"{100 * delegated / tested:.2f}",
        },
        {
            "metric": "observed_origin_ineligible_pct",
            "value": f"{100 * ineligible / tested:.2f}",
        },
        {
            "metric": "arbitrary_public_origin_delegated_open_pct",
            "value": f"{100 * open_control_delegated / tested:.2f}",
        },
        {
            "metric": "arbitrary_public_origin_invalid_closed_pct",
            "value": f"{100 * closed_control_invalid / tested:.2f}",
        },
    ]
    output = TABLE_DIR / "semantic_boundary_summary.csv"
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(f"{row['metric']}: {row['value']}")
    assert open_control_delegated == tested
    assert closed_control_invalid == tested
    print(f"Output -> {output}")


if __name__ == "__main__":
    main()
