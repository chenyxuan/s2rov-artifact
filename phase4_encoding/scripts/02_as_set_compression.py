#!/usr/bin/env python3
"""Task 2: Explicit-AS-set encoding size checks.

Tests two encoding modes: Empty (0B) and List (1+4kB).  These are
reference-format payload sizes, not compressed RPKI object sizes.
Usage: python scripts/02_as_set_compression.py
"""
import sys
from pathlib import Path
import csv

PHASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_DIR / "scripts"))
from utils.as_set import AsSetType, decode, encode, encode_size  # noqa: E402

TABLE_DIR = PHASE_DIR / "outputs/tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def generate_test_sets() -> list:
    """Generate representative AS set test cases."""
    return [
        ("empty_explicit_set", set()),
        ("single_as", {15169}),
        ("single_large_as", {13335}),
        ("two_ases", {15169, 13335}),
        ("three_ases_sparse", {15169, 13335, 16509}),
        ("ten_ases", {15169, 13335, 16509, 8075, 37963, 45102, 4826, 6939, 174, 6453}),
        ("fifty_ases", set(range(64500, 64550))),
        ("max_list_255", set(range(64500, 64755))),
    ]


def main():
    results = []
    test_cases = generate_test_sets()

    for name, as_set in test_cases:
        typ = AsSetType.select(as_set)
        size_bytes, enc_name = encode_size(as_set)
        encoded_type, payload = encode(as_set)
        assert encoded_type == typ
        assert decode(encoded_type, payload) == as_set

        results.append({
            "test_name": name,
            "set_size": len(as_set),
            "encoding": enc_name,
            "byte_size": size_bytes,
            "raw_4byte_asn": len(as_set) * 4,
            "compression_ratio": f"{len(as_set) * 4 / max(size_bytes, 1):.1f}x",
        })

        print(f"  {name:25s}: |A|={len(as_set):3d}  {enc_name:8s} → {size_bytes:3d}B  "
              f"(raw: {len(as_set)*4:3d}B)")

    keys = ["test_name", "set_size", "encoding", "byte_size", "raw_4byte_asn", "compression_ratio"]
    with open(TABLE_DIR / "as_set_stats.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)

    print(f"\n✅ AS set compression results → {TABLE_DIR / 'as_set_stats.csv'}")


if __name__ == "__main__":
    main()
