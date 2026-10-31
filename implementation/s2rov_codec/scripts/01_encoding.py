#!/usr/bin/env python3
"""Task 1: S2-ROV Wire Format — serialization/deserialization round-trip tests.

Usage: python scripts/01_encoding.py
"""
import sys
from pathlib import Path
import csv

HERE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE_DIR / "scripts"))
from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402

TABLE_DIR = HERE_DIR / "outputs/tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def test_roundtrip(s2rov: S2ROV, name: str) -> dict:
    """Test serialization round-trip and return stats."""
    serialized = s2rov.serialize()
    deserialized = S2ROV.deserialize(serialized)

    # Verify round-trip fidelity
    assert s2rov.base_prefix == deserialized.base_prefix, f"{name}: base prefix mismatch"
    assert s2rov.max_length == deserialized.max_length, f"{name}: maxLength mismatch"
    assert s2rov.holder_asn == deserialized.holder_asn, f"{name}: holder ASN mismatch"
    assert len(s2rov.stripes) == len(deserialized.stripes), f"{name}: stripe count mismatch"

    for i, (s1, s2) in enumerate(zip(s2rov.stripes, deserialized.stripes)):
        assert s1.prefix == s2.prefix, f"{name}: stripe[{i}] prefix mismatch"
        assert s1.as_set == s2.as_set, f"{name}: stripe[{i}] AS set mismatch"
        assert s1.is_open == s2.is_open, f"{name}: stripe[{i}] marker mismatch"

    return {
        "test": name,
        "num_stripes": len(s2rov.stripes),
        "wire_bytes": len(serialized),
        "header_bytes": 14,
        "stripe_bytes": len(serialized) - 14,
        "roundtrip_ok": True,
    }


def main():
    results = []

    # Test 1: Enterprise PI (single unmarked record)
    pi = S2ROV("203.0.113.0/24", 24, 64500, [
        Stripe("203.0.113.0/24", {64500}, is_open=False),
    ])
    results.append(test_roundtrip(pi, "enterprise_pi"))

    # Test 2: ISP /16 with an OpenScope marker
    isp_marked = S2ROV("10.0.0.0/16", 24, 64501, [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
    ])
    results.append(test_roundtrip(isp_marked, "isp_openscope_marker"))

    # Test 3: ISP with explicit customers
    isp_customers = S2ROV("10.0.0.0/16", 24, 64501, [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
        Stripe("10.0.1.0/24", {64502}, is_open=False),
        Stripe("10.0.2.0/24", {64503}, is_open=False),
        Stripe("10.0.3.0/24", {64504}, is_open=False),
    ])
    results.append(test_roundtrip(isp_customers, "isp_explicit_customers"))

    # Test 4: ISP with multiple customer ASes (List encoding)
    isp_list = S2ROV("10.0.0.0/16", 24, 64501, [
        Stripe("10.0.0.0/16", {64501}, is_open=True),
        Stripe("10.0.0.0/24", {64510, 64511, 64512, 64513, 64514}, is_open=False),
    ])
    results.append(test_roundtrip(isp_list, "isp_list_as_set"))

    # Test 5: an empty unmarked child does not shadow the covering marker.
    empty_child = S2ROV("192.0.2.0/24", 25, 64500, [
        Stripe("192.0.2.0/24", {64500}, is_open=True),
        Stripe("192.0.2.128/25", set(), is_open=False),
    ])
    assert (
        empty_child.validate_route("192.0.2.128/25", 15169)
        == ValidationState.OPEN_SCOPE
    )
    results.append(test_roundtrip(empty_child, "unmarked_empty_child"))

    malformed_rejected = 0
    for constructor in (
        lambda: S2ROV("10.0.0.0/16", 24, 64501, []),
        lambda: S2ROV("10.0.0.0/16", 24, 64501, [
            Stripe("10.0.0.0/16", {64501}, True),
            Stripe("10.0.0.0/16", {64502}, False),
        ]),
        lambda: S2ROV("10.0.0.0/16", 24, 64501, [
            Stripe("10.0.0.0/16", {64501}, True),
            Stripe("10.1.0.0/24", {64502}, False),
        ]),
    ):
        try:
            constructor()
        except ValueError:
            malformed_rejected += 1
    assert malformed_rejected == 3

    # Write results
    keys = ["test", "num_stripes", "wire_bytes", "header_bytes", "stripe_bytes", "roundtrip_ok"]
    with open(TABLE_DIR / "encoding_sizes.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)

    print(f"✅ All {len(results)} round-trip tests passed")
    print(f"✅ Malformed policies rejected: {malformed_rejected}/3")
    for r in results:
        print(f"  {r['test']:30s}: {r['num_stripes']:2d} stripes → {r['wire_bytes']:3d} bytes")
    print(f"\nResults → {TABLE_DIR / 'encoding_sizes.csv'}")


if __name__ == "__main__":
    main()
