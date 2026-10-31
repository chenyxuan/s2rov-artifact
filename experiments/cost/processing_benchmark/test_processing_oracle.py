#!/usr/bin/env python3
"""Focused tests for the independent IPv4 marker-semantics oracle."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARK_DIR))

import run_processing_benchmark as benchmark  # noqa: E402
from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402


class IPv4OracleTests(unittest.TestCase):
    def test_explicit_matches_precede_covering_marker(self) -> None:
        stripes = [
            {"prefix": "0.0.0.0/0", "origins": [174], "is_open": True},
            {
                "prefix": "192.0.2.0/24",
                "origins": [15169],
                "is_open": False,
            },
        ]
        policy = S2ROV(
            "0.0.0.0/0",
            32,
            174,
            tuple(
                Stripe(
                    item["prefix"],
                    frozenset(item["origins"]),
                    bool(item["is_open"]),
                )
                for item in stripes
            ),
        )
        cases = [
            ("0.0.0.0/0", 174, ValidationState.EXPLICIT.value),
            ("0.0.0.0/0", 15169, ValidationState.INVALID.value),
            ("192.0.2.0/24", 15169, ValidationState.EXPLICIT.value),
            ("192.0.2.0/24", 174, ValidationState.EXPLICIT.value),
            ("192.0.2.0/24", 16509, ValidationState.DELEGATED.value),
            ("192.0.2.128/25", 15169, ValidationState.DELEGATED.value),
            ("192.0.2.128/25", 16509, ValidationState.DELEGATED.value),
            ("192.0.2.0/24", 64513, ValidationState.INVALID.value),
        ]
        for prefix, origin, expected in cases:
            with self.subTest(prefix=prefix, origin=origin):
                oracle = benchmark.independent_oracle(
                    stripes,
                    prefix,
                    origin,
                    base_prefix="0.0.0.0/0",
                    max_length=32,
                )
                self.assertEqual(oracle, expected)
                self.assertEqual(policy.validate_route(prefix, origin).value, oracle)

    def test_nonbase_origin_does_not_propagate_without_marker(self) -> None:
        stripes = [
            {"prefix": "0.0.0.0/0", "origins": [174], "is_open": False},
            {
                "prefix": "192.0.2.0/24",
                "origins": [15169],
                "is_open": False,
            },
        ]
        policy = S2ROV(
            "0.0.0.0/0",
            32,
            174,
            tuple(
                Stripe(
                    item["prefix"],
                    frozenset(item["origins"]),
                    bool(item["is_open"]),
                )
                for item in stripes
            ),
        )
        cases = [
            ("192.0.2.0/24", 15169, ValidationState.EXPLICIT.value),
            ("192.0.2.128/25", 15169, ValidationState.INVALID.value),
            ("192.0.2.128/25", 174, ValidationState.EXPLICIT.value),
        ]
        for prefix, origin, expected in cases:
            with self.subTest(prefix=prefix, origin=origin):
                oracle = benchmark.independent_oracle(
                    stripes,
                    prefix,
                    origin,
                    base_prefix="0.0.0.0/0",
                    max_length=32,
                )
                self.assertEqual(oracle, expected)
                self.assertEqual(policy.validate_route(prefix, origin).value, oracle)


if __name__ == "__main__":
    unittest.main()
