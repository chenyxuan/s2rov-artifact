#!/usr/bin/env python3
"""Reference-format size diagnostics on synthetic policy shapes.

This script intentionally does not compare the custom Stripe payload with
ROA/CMS objects, RTR PDUs, h-ROA, or router memory: those are different
representations.  It also reports no Python timing as a system-performance
result.  Prototype control-plane performance is measured under implementation.prototype.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path


HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))

from utils.s2rov import S2ROV, Stripe  # noqa: E402


TABLE_DIR = HERE_DIR / "outputs" / "tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def make_policy(
    name: str,
    base_prefix: str,
    max_length: int,
    holder_asn: int,
    customers: list[tuple[str, int]],
    mark_base: bool,
) -> dict[str, object]:
    stripes = [Stripe(base_prefix, {holder_asn}, is_open=mark_base)]
    stripes.extend(
        Stripe(prefix, {asn}, is_open=False) for prefix, asn in customers
    )
    policy = S2ROV(base_prefix, max_length, holder_asn, stripes)
    payload = policy.serialize()
    decoded = S2ROV.deserialize(payload)
    assert decoded.serialize() == payload

    return {
        "scenario": name,
        # Retained for compatibility with earlier diagnostic CSV readers.
        "open_base": mark_base,
        "explicit_customer_prefixes": len(customers),
        "stripes": len(stripes),
        "reference_payload_bytes": len(payload),
        "conservative_projected_vrps": len(policy.flatten_to_vrps()),
        "roundtrip_ok": True,
    }


def customers(count: int) -> list[tuple[str, int]]:
    return [
        (f"10.0.{index}.0/24", 100000 + index)
        for index in range(count)
    ]


def main() -> None:
    rows = [
        make_policy(
            "enterprise_unmarked",
            "203.0.113.0/24",
            24,
            64500,
            [],
            False,
        ),
        make_policy(
            "isp_marker_no_explicit_children",
            "10.0.0.0/16",
            24,
            64501,
            [],
            True,
        ),
        make_policy(
            "isp_marker_10_explicit",
            "10.0.0.0/16",
            24,
            64501,
            customers(10),
            True,
        ),
        make_policy(
            "isp_marker_100_explicit",
            "10.0.0.0/16",
            24,
            64501,
            customers(100),
            True,
        ),
        make_policy(
            "isp_marker_255_explicit",
            "10.0.0.0/16",
            24,
            64501,
            customers(255),
            True,
        ),
    ]

    output = TABLE_DIR / "reference_format_sizes.csv"
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(
            f"{row['scenario']:26s} "
            f"{row['stripes']:4d} stripes  "
            f"{row['reference_payload_bytes']:5d} bytes  "
            f"{row['conservative_projected_vrps']:4d} projected VRPs"
        )
    print(f"\nReference diagnostics -> {output}")


if __name__ == "__main__":
    main()
