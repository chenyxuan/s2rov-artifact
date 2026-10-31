#!/usr/bin/env python3
"""Evaluate the S2-ROV reference encoder and provenance-aware validator.

The experiment checks policy outcomes across a serialization round trip and
measures indexed validation cost as the number of explicit Stripes grows. The
timing is a Python reference-implementation microbenchmark, not a router
data-plane throughput claim.
"""
from __future__ import annotations

import csv
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
S2ROV_CODEC_SCRIPTS = ROOT / "implementation" / "s2rov_codec" / "scripts"
sys.path.insert(0, str(S2ROV_CODEC_SCRIPTS))

from utils.s2rov import S2ROV, Stripe, ValidationState


HERE_DIR = Path(__file__).resolve().parents[1]
TABLE_DIR = HERE_DIR / "outputs" / "tables"
TABLE_DIR.mkdir(parents=True, exist_ok=True)


def build_policy(num_customers: int) -> S2ROV:
    stripes = [
        Stripe("10.0.0.0/8", {64501}, is_open=True),
    ]
    for i in range(num_customers):
        second = i // 256
        third = i % 256
        stripes.append(
            Stripe(
                f"10.{second}.{third}.0/24",
                {100000 + i},
                is_open=False,
            )
        )
    return S2ROV("10.0.0.0/8", 24, 64501, stripes)


def policy_cases() -> list[dict[str, str]]:
    policy = S2ROV(
        "10.0.0.0/16",
        24,
        64501,
        [
            Stripe("10.0.0.0/16", {64501}, is_open=True),
            Stripe("10.0.1.0/24", {64502}, is_open=False),
        ],
    )
    decoded = S2ROV.deserialize(policy.serialize())
    cases = [
        ("holder aggregate", "10.0.0.0/16", 64501, ValidationState.EXPLICIT),
        ("wrong aggregate origin", "10.0.0.0/16", 64502, ValidationState.INVALID),
        ("listed customer", "10.0.1.0/24", 64502, ValidationState.EXPLICIT),
        (
            "eligible unlisted origin beside exact ROA",
            "10.0.1.0/24",
            15169,
            ValidationState.DELEGATED,
        ),
        ("open delegated range", "10.0.2.0/24", 18403, ValidationState.DELEGATED),
        ("public origin in open range", "10.0.2.0/24", 15169, ValidationState.DELEGATED),
        ("private origin in open range", "10.0.2.0/24", 64513, ValidationState.INVALID),
        ("outside object", "192.0.2.0/24", 64501, ValidationState.NOT_FOUND),
    ]

    rows = []
    for name, prefix, asn, expected in cases:
        before = policy.validate_route(prefix, asn)
        after = decoded.validate_route(prefix, asn)
        assert before == expected, (name, before, expected)
        assert after == expected, (name, after, expected)
        rows.append(
            {
                "case": name,
                "prefix": prefix,
                "origin_asn": str(asn),
                "expected": expected.value,
                "before_roundtrip": before.value,
                "after_roundtrip": after.value,
                "pass": "True",
            }
        )
    return rows


def benchmark() -> list[dict[str, str]]:
    rows = []
    query_count = 20000
    repetitions = 5

    for customers in (1, 16, 256, 4096):
        policy = build_policy(customers)
        decoded = S2ROV.deserialize(policy.serialize())
        queries = []
        for i in range(query_count):
            customer = i % customers
            second = customer // 256
            third = customer % 256
            if i % 2:
                queries.append((f"10.{second}.{third}.0/24", 100000 + customer))
            else:
                unknown = (customer + customers + 8192) % 65536
                queries.append(
                    (f"10.{unknown // 256}.{unknown % 256}.0/24", 15169)
                )

        timings = []
        checksum = 0
        for _ in range(repetitions):
            start = time.perf_counter_ns()
            for prefix, asn in queries:
                state = decoded.validate_route(prefix, asn)
                checksum += state in (
                    ValidationState.EXPLICIT,
                    ValidationState.DELEGATED,
                )
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed / query_count)

        rows.append(
            {
                "explicit_customers": str(customers),
                "stripes": str(len(decoded.stripes)),
                "wire_bytes": str(len(policy.serialize())),
                "queries_per_repetition": str(query_count),
                "repetitions": str(repetitions),
                "median_ns_per_query": f"{statistics.median(timings):.0f}",
                "min_ns_per_query": f"{min(timings):.0f}",
                "max_ns_per_query": f"{max(timings):.0f}",
                "checksum": str(checksum),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    cases = policy_cases()
    perf = benchmark()
    write_csv(TABLE_DIR / "s2rov_policy_cases.csv", cases)
    write_csv(TABLE_DIR / "s2rov_reference_benchmark.csv", perf)

    print(f"Policy cases passed: {len(cases)}/{len(cases)}")
    for row in perf:
        print(
            f"{row['explicit_customers']:>4} customers, "
            f"{row['stripes']:>4} stripes, "
            f"{row['wire_bytes']:>6} bytes, "
            f"{row['median_ns_per_query']:>6} ns/query"
        )


if __name__ == "__main__":
    main()
