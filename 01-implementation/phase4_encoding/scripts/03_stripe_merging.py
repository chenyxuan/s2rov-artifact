#!/usr/bin/env python3
"""Task 3: Prefix preservation under the historical merge API.

Usage: python scripts/03_stripe_merging.py
"""
import sys
from pathlib import Path
import csv

PHASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_DIR / "scripts"))
from utils.daroa import Stripe  # noqa: E402
from utils.merge import merge_ratio, merge_stripes  # noqa: E402

TABLE_DIR = PHASE_DIR / "outputs/tables"
FIG_DIR = PHASE_DIR / "outputs/figures"
TABLE_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)


def generate_contiguous_block(base: str, count: int, as_set: set, has_marker: bool) -> list:
    """Generate `count` adjacent /24 prefixes starting from `base`."""
    import ipaddress as ip
    net = ip.IPv4Network(base, strict=False)
    base_int = int(net.network_address)
    stripes = []
    for i in range(count):
        addr = ip.IPv4Address(base_int + i * 256)
        prefix = f"{addr}/24"
        stripes.append(Stripe(prefix, as_set, has_marker))
    return stripes


def main():
    results = []

    # Non-base explicit records are exact, including contiguous records with
    # the same origin, so their prefixes must be preserved.
    unmarked_block = generate_contiguous_block("10.0.0.0/24", 8, {64501}, False)
    merged = merge_stripes(unmarked_block)
    ratio = merge_ratio(unmarked_block, merged)
    results.append({
        "test": "8x_contiguous_unmarked",
        "raw_stripes": len(unmarked_block),
        "merged_stripes": len(merged),
        "ratio": f"{ratio:.1f}:1",
        "merged_prefixes": [s.prefix for s in merged],
    })
    print(f"  8 contiguous unmarked: {len(unmarked_block)} → {len(merged)} ({ratio:.1f}:1)")
    print(f"    Preserved: {[s.prefix for s in merged]}")

    # Test 2: OpenScope markers retain their exact prefixes.
    marker_block = generate_contiguous_block("10.0.0.0/24", 8, set(), True)
    merged2 = merge_stripes(marker_block)
    ratio2 = merge_ratio(marker_block, merged2)
    results.append({
        "test": "8x_contiguous_markers",
        "raw_stripes": len(marker_block),
        "merged_stripes": len(merged2),
        "ratio": f"{ratio2:.1f}:1",
        "merged_prefixes": [s.prefix for s in merged2],
    })
    print(f"  8 contiguous markers:  {len(marker_block)} → {len(merged2)} ({ratio2:.1f}:1)")
    print(f"    Preserved: {[s.prefix for s in merged2]}")

    # Test 3: 32 contiguous /24s (full /19)
    block_32 = generate_contiguous_block("10.0.0.0/24", 32, {64501}, False)
    merged3 = merge_stripes(block_32)
    ratio3 = merge_ratio(block_32, merged3)
    results.append({
        "test": "32x_contiguous_unmarked",
        "raw_stripes": len(block_32),
        "merged_stripes": len(merged3),
        "ratio": f"{ratio3:.1f}:1",
        "merged_prefixes": [s.prefix for s in merged3],
    })
    print(f"  32 contiguous unmarked: {len(block_32)} → {len(merged3)} ({ratio3:.1f}:1)")
    print(f"    Preserved: {[s.prefix for s in merged3]}")

    # Test 4: 256 contiguous /24s (full /16)
    block_256 = generate_contiguous_block("10.0.0.0/24", 256, {64501}, False)
    merged4 = merge_stripes(block_256)
    ratio4 = merge_ratio(block_256, merged4)
    results.append({
        "test": "256x_contiguous_unmarked",
        "raw_stripes": len(block_256),
        "merged_stripes": len(merged4),
        "ratio": f"{ratio4:.1f}:1",
        "merged_prefixes": [s.prefix for s in merged4],
    })
    print(f"  256 contiguous unmarked: {len(block_256)} → {len(merged4)} ({ratio4:.1f}:1)")
    print(f"    Preserved: {[s.prefix for s in merged4]}")

    # Test 5: Adjacent but semantically different regions remain separate.
    unmarked = generate_contiguous_block("10.0.0.0/24", 4, {64501}, False)
    markers = generate_contiguous_block("10.0.4.0/24", 4, {64501}, True)
    mixed = unmarked + markers
    merged5 = merge_stripes(mixed)
    ratio5 = merge_ratio(mixed, merged5)
    results.append({
        "test": "adjacent_unmarked_and_markers",
        "raw_stripes": len(mixed),
        "merged_stripes": len(merged5),
        "ratio": f"{ratio5:.1f}:1",
        "merged_prefixes": [s.prefix for s in merged5],
    })
    print(f"  4x unmarked + 4 markers: {len(mixed)} → {len(merged5)} ({ratio5:.1f}:1)")
    print(f"    Preserved: {[s.prefix for s in merged5]}")

    # Write CSV
    keys = ["test", "raw_stripes", "merged_stripes", "ratio", "merged_prefixes"]
    with open(TABLE_DIR / "merge_ratios.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)

    print(f"\n✅ Merge ratio results → {TABLE_DIR / 'merge_ratios.csv'}")


if __name__ == "__main__":
    main()
