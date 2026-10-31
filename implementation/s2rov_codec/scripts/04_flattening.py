#!/usr/bin/env python3
"""Task 4: VRP Flattening & Standard ROA Derivation — validation tests.

Usage: python scripts/04_flattening.py
"""
import sys
from pathlib import Path
import csv

HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))
from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402
from utils.flatten import (  # noqa: E402
    derive_standard_roa,
    flatten_to_vrps,
    flattening_validation,
)

TABLE_DIR = HERE_DIR / "outputs/tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def main():
    results = []

    # Test 1: Enterprise PI
    pi = S2ROV("203.0.113.0/24", 24, 64500, [
        Stripe("203.0.113.0/24", {64500}, is_open=False),
    ])
    std_roa = derive_standard_roa(pi)
    vrps = flatten_to_vrps(pi)
    results.append({
        "test": "enterprise_pi",
        "std_prefix": std_roa[0],
        "std_asn": std_roa[1],
        "std_maxlen": std_roa[2],
        "flattened_vrp_count": len(vrps),
        "expected_vrps": 1,
    })
    print(f"  enterprise_pi:       std=({std_roa[0]}, AS{std_roa[1]}, ℓ={std_roa[2]})  "
          f"vrps={len(vrps)}")

    # Test 2: ISP /16 with an OpenScope marker
    isp_marked = S2ROV("10.0.0.0/16", 24, 64501, [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
    ])
    std_roa2 = derive_standard_roa(isp_marked)
    vrps2 = flatten_to_vrps(isp_marked)
    results.append({
        "test": "isp_openscope_marker",
        "std_prefix": std_roa2[0],
        "std_asn": std_roa2[1],
        "std_maxlen": std_roa2[2],
        "flattened_vrp_count": len(vrps2),
        "expected_vrps": 1,
    })
    print(f"  isp_openscope_marker: std=({std_roa2[0]}, AS{std_roa2[1]}, ℓ={std_roa2[2]})  "
          f"vrps={len(vrps2)}")

    # Test 3: ISP with explicit customers
    isp_cust = S2ROV("10.0.0.0/16", 24, 64501, [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
        Stripe("10.0.1.0/24", {64502}, is_open=False),
        Stripe("10.0.2.0/24", {64503}, is_open=False),
    ])
    std_roa3 = derive_standard_roa(isp_cust)
    vrps3 = flatten_to_vrps(isp_cust)
    results.append({
        "test": "isp_explicit_customers",
        "std_prefix": std_roa3[0],
        "std_asn": std_roa3[1],
        "std_maxlen": std_roa3[2],
        "flattened_vrp_count": len(vrps3),
        "expected_vrps": 3,  # base + 2 customers
    })
    print(f"  isp_explicit_cust:   std=({std_roa3[0]}, AS{std_roa3[1]}, ℓ={std_roa3[2]})  "
          f"vrps={len(vrps3)}")

    # Projection must never turn a non-explicit DA outcome into legacy Valid.
    for policy in (pi, isp_marked, isp_cust):
        assert flattening_validation(policy)
    assert std_roa2[2] == 24
    # The base record explicitly names the holder, so it remains Explicit at
    # descendants even though the same prefix carries an OpenScope marker.
    assert isp_marked.validate_route("10.0.1.0/24", 64501) == ValidationState.EXPLICIT
    assert ("10.0.0.0/16", 64501, 24) in vrps2

    print("\n  ✅ Every projected VRP maps to an Explicit DA outcome")

    # Write CSV
    keys = ["test", "std_prefix", "std_asn", "std_maxlen", "flattened_vrp_count", "expected_vrps"]
    with open(TABLE_DIR / "flattening_validation.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)

    print(f"\n✅ Flattening validation → {TABLE_DIR / 'flattening_validation.csv'}")


if __name__ == "__main__":
    main()
