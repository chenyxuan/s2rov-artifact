#!/usr/bin/env python3
"""Unit tests for the independent IPv6 processing benchmark driver."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARK_DIR))

import run_ipv6_processing_benchmark as benchmark  # noqa: E402
from utils.s2rov import S2ROV, Stripe, ValidationState  # noqa: E402


class IPv6WorkloadTests(unittest.TestCase):
    def write_fixture(self, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["prefix", "origin_as"])
            writer.writerow(["0.0.0.0/0", "1299"])
            writer.writerow(["::/0", "24482"])
            writer.writerow(["2001:db8::/32", "15169"])
            writer.writerow(["2001:db8::/32", "{AMBIGUOUS}"])
            writer.writerow(["192.0.2.0/24", "64496"])
            writer.writerow(["2001:db8:1::/48", "16509"])

    def test_mixed_source_filter_and_ipv6_policy_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            source = tmp / "mixed.csv"
            workload = tmp / "ipv6.csv"
            run_dir = tmp / "run"
            run_dir.mkdir()
            self.write_fixture(source)

            manifest = benchmark.prepare_ipv6_workload(
                source,
                workload,
                limit=None,
                max_policy_size=3,
                seed=7,
            )
            self.assertEqual(manifest["source_rows_scanned"], 6)
            self.assertEqual(manifest["source_ipv4_rows_skipped"], 2)
            self.assertEqual(manifest["source_ipv6_rows"], 4)
            self.assertEqual(
                manifest["source_ipv6_ambiguous_markers_excluded"], 1
            )
            self.assertEqual(manifest["ipv6_rows"], 3)
            self.assertEqual(manifest["holder_asn"], 24482)
            self.assertEqual(
                [item["prefix"] for item in manifest["selected_children"]],
                ["2001:db8::/32", "2001:db8:1::/48"],
            )

            policies = benchmark.create_ipv6_policies(run_dir, manifest, [1, 3])
            self.assertEqual(sorted(policies), [1, 3])
            for size in (1, 3):
                payload = Path(policies[size]["serialized_path"]).read_bytes()
                policy = S2ROV.deserialize(payload)
                self.assertEqual(policy.ip_version, 6)
                self.assertEqual(policy.base_prefix, "::/0")
                self.assertEqual(policy.max_length, 128)
                self.assertEqual(len(policy.stripes), size)
                self.assertEqual(policy.serialize(), payload)

            rows = list(benchmark.iter_workload(workload))
            policy, checks = benchmark.load_ipv6_policy_and_check(
                Path(policies[3]["serialized_path"]),
                Path(policies[3]["oracle_spots_path"]),
            )
            preloaded = benchmark.process_preloaded(policy, rows, 2)
            streamed = benchmark.process_streaming(policy, workload, 2)
            self.assertEqual(preloaded[1], streamed[1])
            self.assertEqual(preloaded[2], streamed[2])
            self.assertTrue(checks["roundtrip_identical"])
            self.assertTrue(checks["oracle_spot_checks_pass"])

    def test_independent_ipv6_oracle_semantics(self) -> None:
        stripes = [
            {"prefix": "::/0", "origins": [24482], "is_open": True},
            {
                "prefix": "2001:db8:1::/48",
                "origins": [16509],
                "is_open": False,
            },
        ]
        policy = S2ROV(
            "::/0",
            128,
            24482,
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
            ("::/0", 24482, ValidationState.EXPLICIT.value),
            ("::/0", 15169, ValidationState.INVALID.value),
            ("2001:db8:2::/48", 15169, ValidationState.DELEGATED.value),
            ("2001:db8:2::/48", 64513, ValidationState.INVALID.value),
            ("2001:db8:1::/48", 16509, ValidationState.EXPLICIT.value),
            ("2001:db8:1::/48", 24482, ValidationState.EXPLICIT.value),
            ("2001:db8:1::/48", 15169, ValidationState.DELEGATED.value),
            ("2001:db8:1:1::/64", 16509, ValidationState.DELEGATED.value),
            ("2001:db8:1:1::/64", 15169, ValidationState.DELEGATED.value),
        ]
        for prefix, origin, expected in cases:
            with self.subTest(prefix=prefix, origin=origin):
                oracle = benchmark.independent_ipv6_oracle(
                    stripes,
                    prefix,
                    origin,
                    base_prefix="::/0",
                    max_length=128,
                )
                self.assertEqual(oracle, expected)
                self.assertEqual(policy.validate_route(prefix, origin).value, oracle)

    def test_nonbase_ipv6_origin_does_not_propagate_without_marker(self) -> None:
        stripes = [
            {"prefix": "::/0", "origins": [24482], "is_open": False},
            {
                "prefix": "2001:db8:1::/48",
                "origins": [16509],
                "is_open": False,
            },
        ]
        policy = S2ROV(
            "::/0",
            128,
            24482,
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
            ("2001:db8:1::/48", 16509, ValidationState.EXPLICIT.value),
            ("2001:db8:1:1::/64", 16509, ValidationState.INVALID.value),
            ("2001:db8:1:1::/64", 24482, ValidationState.EXPLICIT.value),
        ]
        for prefix, origin, expected in cases:
            with self.subTest(prefix=prefix, origin=origin):
                oracle = benchmark.independent_ipv6_oracle(
                    stripes,
                    prefix,
                    origin,
                    base_prefix="::/0",
                    max_length=128,
                )
                self.assertEqual(oracle, expected)
                self.assertEqual(policy.validate_route(prefix, origin).value, oracle)

    def test_formal_count_projection(self) -> None:
        manifest = {
            "source_rows_scanned": benchmark.EXPECTED_SOURCE_ROWS,
            "source_ipv4_rows_skipped": benchmark.EXPECTED_SOURCE_IPV4_ROWS,
            "source_ipv6_rows": benchmark.EXPECTED_SOURCE_IPV6_ROWS,
            "source_ipv6_ambiguous_markers_excluded": (
                benchmark.EXPECTED_AMBIGUOUS_IPV6_ROWS
            ),
            "ipv6_rows": benchmark.EXPECTED_VALID_IPV6_ROWS,
            "ignored": json.dumps({"not": "part of the gate"}),
        }
        self.assertEqual(
            benchmark.formal_input_counts(manifest),
            {
                "source_rows_scanned": 1_393_270,
                "source_ipv4_rows_skipped": 1_135_687,
                "source_ipv6_rows": 257_583,
                "source_ipv6_ambiguous_markers_excluded": 33,
                "ipv6_rows": 257_550,
            },
        )


if __name__ == "__main__":
    unittest.main()
